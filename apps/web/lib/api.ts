import { cookies, headers as nextHeaders } from 'next/headers';

const ACCESS_COOKIE = process.env.SESSION_COOKIE_NAME || 'session_token';
const REFRESH_COOKIE = process.env.REFRESH_COOKIE_NAME || 'refresh_token';
const TRUSTED_DEVICE_COOKIE = process.env.TRUSTED_DEVICE_COOKIE_NAME || 'trusted_device_token';
const REFRESH_PATH = '/api/auth/refresh';
const FORWARDED_HEADER_NAMES = ['user-agent'] as const;
const OPTIONAL_IP_HEADERS = ['x-forwarded-for', 'x-real-ip'] as const;
const ACCESS_TOKEN_TTL_MINUTES = parseEnvNumber('ACCESS_TOKEN_TTL_MINUTES', 15);
const SESSION_TTL_HOURS = parseEnvNumber('SESSION_TTL_HOURS', 24 * 7);
const FORWARD_IP_HEADERS = parseEnvBoolean('FORWARD_IP_HEADERS', false);
const SESSION_TTL_SECONDS = SESSION_TTL_HOURS * 60 * 60;
const TRUSTED_DEVICE_TTL_SECONDS = parseEnvNumber('TRUSTED_DEVICE_TTL_SECONDS', SESSION_TTL_SECONDS);
const DEFAULT_ACCESS_COOKIE_MAX_AGE_SECONDS = ACCESS_TOKEN_TTL_MINUTES * 60;
const DEFAULT_REFRESH_COOKIE_MAX_AGE_SECONDS = SESSION_TTL_SECONDS;

export type ApiError = {
  error: string;
  request_id?: string;
};

type RefreshResponse = {
  access_token: string;
  refresh_token: string;
  access_expires_at: string;
  refresh_expires_at: string;
};

type SessionTokens = {
  accessToken?: string;
  refreshToken?: string;
  trustedDeviceToken?: string;
};

type BuildHeadersInput = {
  initHeaders?: HeadersInit;
  accessToken?: string;
  refreshToken?: string;
  trustedDeviceToken?: string;
  includeRefreshHeader?: boolean;
};

export function apiBaseUrl() {
  // SSR 与 Docker 场景优先走内部地址；浏览器场景再退回公开地址。
  return process.env.INTERNAL_API_BASE_URL || process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8080';
}

/**
 * 统一代理 Web 层到后端 API 的请求，并在受保护接口 401 时自动尝试 refresh。
 */
export async function backendFetch(path: string, init?: RequestInit) {
  // 先从 Next.js 的服务端 Cookie Store 中读取当前会话相关令牌。
  const tokens = await readSessionTokens();
  const response = await backendFetchOnce(path, init, tokens);

  // 只有命中了“受保护接口 + 401 + 持有 refresh token”这三个条件才尝试刷新。
  if (!shouldAttemptRefresh(path, response.status, tokens.refreshToken)) {
    return response;
  }

  // refresh 成功后必须先落盘新的 access/refresh token；否则旋转后的 refresh token 会丢失。
  const refreshedSession = await refreshSessionTokens(tokens.refreshToken!);
  if (!refreshedSession) {
    return response;
  }

  // 某些 Server Component 渲染阶段不能写 Cookie；这时不能继续重试，否则会制造“本次成功、下次失效”的幽灵会话。
  if (!(await tryPersistRefreshedSessionCookies(refreshedSession))) {
    return response;
  }
  return backendFetchOnce(path, init, {
    ...tokens,
    accessToken: refreshedSession.access_token,
    refreshToken: refreshedSession.refresh_token,
  });
}

/** 解析成功响应中的 JSON 载荷。 */
export async function parseJson<T>(response: Response): Promise<T> {
  return (await response.json()) as T;
}

/**
 * 对响应做“必须成功”的断言；若失败则抛出规范化后的 Error 供上层处理。
 */
export async function requireJson<T>(response: Response): Promise<T> {
  // 前端调用层统一把后端错误规范化成可抛出的 message。
  if (!response.ok) {
    const body = (await response.json()) as ApiError;
    throw new Error(body.error || 'Request failed');
  }

  return parseJson<T>(response);
}

/** 写入 access token Cookie，并尽量与后端返回的绝对过期时间保持一致。 */
export async function setAccessTokenCookie(token: string, expiresAt?: string) {
  // 优先使用后端返回的绝对过期时间，避免 Web 层和 API 层 TTL 配置漂移。
  (await cookies()).set(ACCESS_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: cookieMaxAge(expiresAt, DEFAULT_ACCESS_COOKIE_MAX_AGE_SECONDS),
  });
}

/** 删除 access token Cookie。 */
export async function clearAccessTokenCookie() {
  (await cookies()).delete(ACCESS_COOKIE);
}

/** 写入 refresh token Cookie。 */
export async function setRefreshTokenCookie(token: string, expiresAt?: string) {
  // refresh token 的 Cookie 生命周期也跟随后端实际会话过期时间。
  (await cookies()).set(REFRESH_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: cookieMaxAge(expiresAt, DEFAULT_REFRESH_COOKIE_MAX_AGE_SECONDS),
  });
}

/** 删除 refresh token Cookie。 */
export async function clearRefreshTokenCookie() {
  (await cookies()).delete(REFRESH_COOKIE);
}

/** 写入 trusted device Cookie，用于后端识别受信设备。 */
export async function setTrustedDeviceCookie(token: string) {
  (await cookies()).set(TRUSTED_DEVICE_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: TRUSTED_DEVICE_TTL_SECONDS,
  });
}

/** 删除 trusted device Cookie。 */
export async function clearTrustedDeviceCookie() {
  (await cookies()).delete(TRUSTED_DEVICE_COOKIE);
}

/**
 * 执行一次真实的后端请求，不包含 refresh 重试逻辑。
 */
async function backendFetchOnce(path: string, init: RequestInit | undefined, tokens: SessionTokens) {
  // 这是最底层的一次真实后端请求，不包含自动 refresh 重试逻辑。
  return fetch(`${apiBaseUrl()}${path}`, {
    ...init,
    headers: await buildBackendHeaders({
      initHeaders: init?.headers,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      trustedDeviceToken: tokens.trustedDeviceToken,
    }),
    cache: 'no-store',
  });
}

/**
 * 从 Next Cookie Store 与当前请求头中恢复本次服务端渲染所需的会话令牌。
 */
async function readSessionTokens(): Promise<SessionTokens> {
  // 这里统一收敛 Cookie 读取逻辑，避免页面和 action 到处散落同样代码。
  const cookieStore = await cookies();
  const requestCookies = parseCookieHeader((await nextHeaders()).get('cookie'));
  return {
    accessToken: cookieStore.get(ACCESS_COOKIE)?.value || requestCookies.get(ACCESS_COOKIE),
    refreshToken: cookieStore.get(REFRESH_COOKIE)?.value || requestCookies.get(REFRESH_COOKIE),
    trustedDeviceToken: cookieStore.get(TRUSTED_DEVICE_COOKIE)?.value || requestCookies.get(TRUSTED_DEVICE_COOKIE),
  };
}

/**
 * 构建发往 Rust API 的最终请求头，负责拼装 Cookie/Bearer/Trusted Device/审计上下文。
 */
async function buildBackendHeaders({
  initHeaders,
  accessToken,
  refreshToken,
  trustedDeviceToken,
  includeRefreshHeader = false,
}: BuildHeadersInput) {
  // 保留调用方已有 Header，再按认证协议补齐所需字段。
  const merged = new Headers(initHeaders);
  if (!merged.has('Content-Type')) {
    merged.set('Content-Type', 'application/json');
  }

  // 把服务端 Cookie Store 中的 token 转成转发给 Rust API 的 Cookie Header。
  const cookieParts = [
    accessToken ? `${ACCESS_COOKIE}=${accessToken}` : null,
    refreshToken ? `${REFRESH_COOKIE}=${refreshToken}` : null,
  ].filter((value): value is string => Boolean(value));

  if (cookieParts.length > 0) {
    merged.set('Cookie', cookieParts.join('; '));
  }

  // Bearer Header 主要服务于 API 自测与非浏览器客户端。
  if (accessToken && !merged.has('Authorization')) {
    merged.set('Authorization', `Bearer ${accessToken}`);
  }

  // Trusted Device Token 独立于 session token，单独透传给后端决策。
  if (trustedDeviceToken && !merged.has('X-Trusted-Device-Token')) {
    merged.set('X-Trusted-Device-Token', trustedDeviceToken);
  }

  // refresh 接口额外要求显式带 refresh token header，便于非 Cookie 客户端联调。
  if (includeRefreshHeader && refreshToken && !merged.has('X-Refresh-Token')) {
    merged.set('X-Refresh-Token', refreshToken);
  }

  // 把上游代理或浏览器传来的源 IP / UA 继续透传给后端，
  // 这样风险控制和审计事件能基于真实上下文工作。
  const requestHeaders = await nextHeaders();
  for (const headerName of FORWARDED_HEADER_NAMES) {
    const value = requestHeaders.get(headerName);
    if (value && !merged.has(headerName)) {
      merged.set(headerName, value);
    }
  }
  if (FORWARD_IP_HEADERS) {
    for (const headerName of OPTIONAL_IP_HEADERS) {
      const value = requestHeaders.get(headerName);
      if (value && !merged.has(headerName)) {
        merged.set(headerName, value);
      }
    }
  }

  return merged;
}

/**
 * 仅在“受保护接口返回 401 且当前持有 refresh token”时，才允许尝试静默续签。
 */
function shouldAttemptRefresh(path: string, status: number, refreshToken: string | undefined) {
  // 只对受保护接口做静默续签，避免把公开接口的 401 误判成 session 过期。
  return status === 401 && Boolean(refreshToken) && isProtectedPath(path) && path !== REFRESH_PATH;
}

/**
 * 判定路径是否属于需要登录态的接口范围。
 */
function isProtectedPath(path: string) {
  // 这里显式列出需要登录态的 API 范围，前端刷新行为因此是可审计、可推导的。
  return (
    path === '/api/auth/session' ||
    path === '/api/auth/logout' ||
    path.startsWith('/api/auth/mfa/') ||
    path.startsWith('/api/auth/passkey/register') ||
    path.startsWith('/api/sessions')
  );
}

/**
 * 使用 refresh token 申请一组新的访问/刷新令牌。
 */
async function refreshSessionTokens(refreshToken: string) {
  // refresh 是一个独立 HTTP 调用，避免把 token 轮换逻辑耦进任意业务请求。
  const response = await fetch(`${apiBaseUrl()}${REFRESH_PATH}`, {
    method: 'POST',
    headers: await buildBackendHeaders({ refreshToken, includeRefreshHeader: true }),
    cache: 'no-store',
  });

  if (!response.ok) {
    return null;
  }

  return (await response.json()) as RefreshResponse;
}

/**
 * 把 refresh 成功后的新令牌持久化到 Cookie；若当前执行上下文不允许写 Cookie，则返回 false。
 */
async function tryPersistRefreshedSessionCookies(payload: RefreshResponse) {
  try {
    await setAccessTokenCookie(payload.access_token, payload.access_expires_at);
    await setRefreshTokenCookie(payload.refresh_token, payload.refresh_expires_at);
    return true;
  } catch {
    return false;
  }
}

/**
 * 根据绝对过期时间换算 Cookie maxAge；若解析失败则退回默认 TTL。
 */
function cookieMaxAge(expiresAt: string | undefined, fallbackSeconds: number) {
  if (!expiresAt) {
    return fallbackSeconds;
  }

  const expiresAtMs = new Date(expiresAt).getTime();
  if (Number.isNaN(expiresAtMs)) {
    return fallbackSeconds;
  }

  return Math.max(Math.ceil((expiresAtMs - Date.now()) / 1000), 0);
}

/** 读取数字型环境变量，缺失或非法时回退默认值。 */
function parseEnvNumber(name: string, fallback: number) {
  const value = process.env[name];
  if (!value) {
    return fallback;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

/** 读取布尔型环境变量，支持常见 truthy 文本。 */
function parseEnvBoolean(name: string, fallback: boolean) {
  const value = process.env[name];
  if (!value) {
    return fallback;
  }

  return /^(1|true|yes|on)$/i.test(value.trim());
}

/**
 * 把原始 Cookie Header 解析为 name/value Map，便于在服务端 action 中兜底读取。
 */
function parseCookieHeader(header: string | null) {
  const cookies = new Map<string, string>();
  if (!header) {
    return cookies;
  }

  for (const part of header.split(';')) {
    const trimmed = part.trim();
    const separatorIndex = trimmed.indexOf('=');
    if (separatorIndex <= 0) {
      continue;
    }

    const name = trimmed.slice(0, separatorIndex).trim();
    const value = trimmed.slice(separatorIndex + 1).trim();
    if (!name || !value || cookies.has(name)) {
      continue;
    }
    cookies.set(name, value);
  }

  return cookies;
}
