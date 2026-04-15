'use server';

import { revalidatePath } from 'next/cache';

import {
  backendFetch,
  clearAccessTokenCookie,
  clearRefreshTokenCookie,
  clearTrustedDeviceCookie,
  requireJson,
  setAccessTokenCookie,
  setRefreshTokenCookie,
  setTrustedDeviceCookie,
} from '@/lib/api';
import { SubjectKey, subjectThemes } from '@/lib/subjects';

export type ActionState = {
  ok: boolean;
  error?: string;
  message?: string;
  requiresMfa?: boolean;
  nextPath?: string;
  demoCode?: string;
  pendingOtp?: boolean;
};

type AuthResponse = {
  access_token: string;
  refresh_token: string;
  access_expires_at: string;
  refresh_expires_at: string;
  dashboard_path: string;
  requires_mfa: boolean;
  trusted_device_token?: string | null;
  clear_trusted_device?: boolean;
};

type MfaResponse = {
  trusted_device_token?: string | null;
};

type ErrorPayload = {
  error?: string;
  demo_code?: string;
  auto_registered?: boolean;
  expires_in_seconds?: number;
  retry_after_seconds?: number;
};

export type ActionResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string };

/**
 * 处理密码登录，并在成功后把后端返回的 session token 写入 Next 侧 Cookie。
 */
export async function passwordLoginAction(_prev: ActionState, formData: FormData): Promise<ActionState> {
  const email = String(formData.get('email') || '');
  const password = String(formData.get('password') || '');
  const role = String(formData.get('role') || '');
  const deviceName = String(formData.get('device_name') || 'Browser Session');
  const rememberDevice = formData.get('remember_device') === 'on';

  const response = await backendFetch('/api/auth/password/login', {
    method: 'POST',
    body: JSON.stringify({
      email,
      password,
      role,
      device_name: deviceName,
      remember_device: rememberDevice,
    }),
  });

  if (!response.ok) {
    return actionError(response, 'Login failed');
  }

  const payload = (await response.json()) as AuthResponse;
  await applyAuthCookies(payload);
  return {
    ok: true,
    requiresMfa: payload.requires_mfa,
    nextPath: payload.dashboard_path,
  };
}

/**
 * 请求登录 OTP；开发环境下会把 demo code 一并返回，便于联调和手工测试。
 */
export async function requestOtpAction(_prev: ActionState, formData: FormData): Promise<ActionState> {
  const response = await backendFetch('/api/auth/otp/request', {
    method: 'POST',
    body: JSON.stringify({
      email: formData.get('email'),
      role: formData.get('role'),
    }),
  });

  const payload = (await response.json()) as ErrorPayload;
  if (!response.ok) {
    return { ok: false, error: payload.error || 'OTP request failed' };
  }

  return {
    ok: true,
    demoCode: payload.demo_code,
    message: payload.auto_registered
      ? '账号不存在，系统已自动创建并发送 OTP，请完成验证后继续登录。'
      : `OTP 已发送，请在 ${payload.expires_in_seconds || 600} 秒内完成验证。`,
    pendingOtp: true,
  };
}

/**
 * 校验登录 OTP，并在通过后建立正式会话或进入 MFA 阶段。
 */
export async function verifyOtpAction(_prev: ActionState, formData: FormData): Promise<ActionState> {
  const response = await backendFetch('/api/auth/otp/verify', {
    method: 'POST',
    body: JSON.stringify({
      email: formData.get('email'),
      code: formData.get('code'),
      role: formData.get('role'),
      device_name: formData.get('device_name') || 'Browser Session',
      remember_device: formData.get('remember_device') === 'on',
    }),
  });

  if (!response.ok) {
    return actionError(response, 'OTP verification failed');
  }

  const payload = (await response.json()) as AuthResponse;
  await applyAuthCookies(payload);
  return {
    ok: true,
    requiresMfa: payload.requires_mfa,
    nextPath: payload.dashboard_path,
  };
}

/**
 * 为已完成一阶段登录的会话发送 MFA OTP。
 */
export async function requestMfaOtpAction(_prev: ActionState, _formData: FormData): Promise<ActionState> {
  const response = await backendFetch('/api/auth/mfa/otp/request', {
    method: 'POST',
  });

  const payload = (await response.json()) as ErrorPayload;
  if (!response.ok) {
    return { ok: false, error: payload.error || 'MFA OTP 请求失败' };
  }

  return {
    ok: true,
    demoCode: payload.demo_code,
    message: `MFA OTP 已发送，请在 ${payload.expires_in_seconds || 600} 秒内完成验证。`,
    pendingOtp: true,
  };
}

/**
 * 校验 MFA OTP，并在通过后把 trusted device token 回写到浏览器 Cookie。
 */
export async function verifyMfaOtpAction(_prev: ActionState, formData: FormData): Promise<ActionState> {
  const response = await backendFetch('/api/auth/mfa/otp/verify', {
    method: 'POST',
    body: JSON.stringify({ code: formData.get('code') }),
  });

  if (!response.ok) {
    return actionError(response, 'MFA verification failed');
  }

  const payload = (await response.json()) as MfaResponse;
  await applyTrustedDeviceCookie(payload.trusted_device_token, false);
  const subject = String(formData.get('subject')) as SubjectKey;
  return { ok: true, nextPath: `/dashboard/${subject}` };
}

/**
 * 获取 Passkey 登录 challenge；只有已注册 Passkey 的账号才能继续完成浏览器断言。
 */
export async function beginPasskeyLoginAction(
  email: string,
  subject: SubjectKey,
): Promise<ActionResult<{ challenge_id: string; public_key: unknown }>> {
  try {
    const response = await backendFetch('/api/auth/passkey/challenge', {
      method: 'POST',
      body: JSON.stringify({ email, role: subjectThemes[subject].role }),
    });
    if (!response.ok) {
      const payload = (await response.json().catch(() => ({ error: 'Passkey 登录失败' }))) as ErrorPayload;
      return { ok: false, error: normalizePasskeyError(payload.error, 'login') };
    }

    return {
      ok: true,
      data: (await response.json()) as { challenge_id: string; public_key: unknown },
    };
  } catch {
    return { ok: false, error: 'Passkey 登录请求失败，请稍后重试。' };
  }
}

/**
 * 把浏览器返回的 Passkey assertion 提交给后端，换取登录后的访问/刷新令牌。
 */
export async function finishPasskeyLoginAction(input: {
  challengeId: string;
  email: string;
  subject: SubjectKey;
  response: unknown;
  rememberDevice: boolean;
  deviceName: string;
}): Promise<ActionState> {
  const response = await backendFetch('/api/auth/passkey/verify', {
    method: 'POST',
    body: JSON.stringify({
      challenge_id: input.challengeId,
      email: input.email,
      role: subjectThemes[input.subject].role,
      response: input.response,
      remember_device: input.rememberDevice,
      device_name: input.deviceName,
    }),
  });

  if (!response.ok) {
    return actionError(response, 'Passkey login failed');
  }

  const payload = (await response.json()) as AuthResponse;
  await applyAuthCookies(payload);
  return {
    ok: true,
    requiresMfa: payload.requires_mfa,
    nextPath: payload.dashboard_path,
  };
}

/**
 * 为当前完整 MFA 会话申请 Passkey 注册 challenge。
 */
export async function beginPasskeyRegisterAction(
  _email: string,
): Promise<ActionResult<{ challenge_id: string; public_key: unknown }>> {
  try {
    const response = await backendFetch('/api/auth/passkey/register/challenge', {
      method: 'POST',
      body: JSON.stringify({}),
    });
    if (!response.ok) {
      const payload = (await response.json().catch(() => ({ error: 'Passkey 注册挑战获取失败' }))) as ErrorPayload;
      return { ok: false, error: normalizePasskeyError(payload.error, 'register') };
    }

    return {
      ok: true,
      data: (await response.json()) as { challenge_id: string; public_key: unknown },
    };
  } catch {
    return { ok: false, error: 'Passkey 注册请求失败，请稍后重试。' };
  }
}

/**
 * 提交浏览器生成的注册响应，要求后端完成 attestation 校验并持久化新凭据。
 */
export async function finishPasskeyRegisterAction(
  input: { challengeId: string; response: unknown },
): Promise<ActionResult<{ external_id: string; label: string }>> {
  let payload: { external_id: string; label: string };
  try {
    const response = await backendFetch('/api/auth/passkey/register/verify', {
      method: 'POST',
      body: JSON.stringify({
        challenge_id: input.challengeId,
        response: input.response,
      }),
    });
    if (!response.ok) {
      const errorPayload = (await response.json().catch(() => ({ error: 'Passkey 注册失败' }))) as ErrorPayload;
      return { ok: false, error: normalizePasskeyError(errorPayload.error, 'register') };
    }
    payload = (await response.json()) as { external_id: string; label: string };
  } catch {
    return { ok: false, error: 'Passkey 注册失败，请稍后重试。' };
  }

  revalidatePath('/dashboard/member');
  revalidatePath('/dashboard/community');
  revalidatePath('/dashboard/platform');
  return { ok: true, data: payload };
}

/**
 * 统一把 Passkey 相关服务端报错转成更适合前端展示的提示文案。
 */
function normalizePasskeyError(raw: string | undefined, flow: 'login' | 'register'): string {
  if (!raw) {
    return flow === 'login' ? 'Passkey 验证失败' : 'Passkey 注册失败';
  }
  // Map generic server 401 to a user-friendly hint without leaking account existence.
  if (raw === 'Authentication required') {
    return flow === 'login'
      ? '未找到可用的 Passkey。请先通过密码或 OTP 登录，再到设置页注册 Passkey。'
      : '需要完整的 MFA 认证，请先完成登录后再注册 Passkey。';
  }
  return raw;
}

/**
 * 远程撤销指定 session，并让三个主体仪表盘都重新拉取服务端状态。
 */
export async function revokeSessionAction(sessionId: string) {
  await requireJson(await backendFetch(`/api/sessions/${sessionId}`, { method: 'POST' }));
  revalidatePath('/dashboard/member');
  revalidatePath('/dashboard/community');
  revalidatePath('/dashboard/platform');
}

/**
 * 远程撤销除当前会话外的全部设备。
 */
export async function revokeOtherSessionsAction() {
  await requireJson(await backendFetch('/api/sessions/revoke-others', { method: 'POST' }));
  revalidatePath('/dashboard/member');
  revalidatePath('/dashboard/community');
  revalidatePath('/dashboard/platform');
}

/**
 * 调用后端注销，并清理 Web 层维护的所有认证 Cookie。
 */
export async function logoutAction() {
  const response = await backendFetch('/api/auth/logout', { method: 'POST' });
  await clearAccessTokenCookie();
  await clearRefreshTokenCookie();
  await clearTrustedDeviceCookie();
  await requireJson(response);
}

/**
 * 以统一格式解析 action 错误，避免每个调用点重复处理 response body。
 */
async function actionError(response: Response, fallback: string): Promise<ActionState> {
  const payload = (await response.json().catch(() => ({ error: fallback }))) as ErrorPayload;
  return { ok: false, error: payload.error || fallback };
}

/**
 * 把后端颁发的访问令牌、刷新令牌与 trusted device token 同步写入浏览器 Cookie。
 */
async function applyAuthCookies(payload: AuthResponse) {
  await setAccessTokenCookie(payload.access_token, payload.access_expires_at);
  await setRefreshTokenCookie(payload.refresh_token, payload.refresh_expires_at);
  await applyTrustedDeviceCookie(payload.trusted_device_token, payload.clear_trusted_device === true);
}

/**
 * 写入或清理 trusted device cookie，用于后续跳过重复 MFA 校验。
 */
async function applyTrustedDeviceCookie(token: string | null | undefined, clearCookie: boolean) {
  if (token) {
    await setTrustedDeviceCookie(token);
    return;
  }

  if (clearCookie) {
    await clearTrustedDeviceCookie();
  }
}
