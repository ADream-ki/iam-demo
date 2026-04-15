type PublicKeyEnvelope = {
  publicKey?: unknown;
};

type JsonRecord = Record<string, unknown>;

/**
 * 兼容后端返回的 `{ publicKey: ... }` 包装结构，统一提取浏览器库需要的 options 对象。
 */
export function normalizeWebAuthnOptions<T>(options: T | PublicKeyEnvelope): T {
  if (
    options &&
    typeof options === 'object' &&
    'publicKey' in options &&
    (options as PublicKeyEnvelope).publicKey !== undefined
  ) {
    return (options as PublicKeyEnvelope).publicKey as T;
  }

  return options as T;
}

/**
 * 在浏览器侧对注册参数做一次“最小且兼容”的标准化，
 * 避免 Windows Hello 因扩展字段或过严的 resident key 策略而直接中止。
 */
export function preparePasskeyRegistrationOptions(options: unknown) {
  const normalized = normalizeWebAuthnOptions<JsonRecord>(options as JsonRecord | PublicKeyEnvelope);
  const prepared = structuredClone(normalized) as JsonRecord;

  delete prepared.extensions;
  delete prepared.hints;

  const selection =
    prepared.authenticatorSelection &&
    typeof prepared.authenticatorSelection === 'object' &&
    !Array.isArray(prepared.authenticatorSelection)
      ? ({ ...prepared.authenticatorSelection } as JsonRecord)
      : {};

  selection.authenticatorAttachment = 'platform';
  selection.residentKey = 'preferred';
  selection.requireResidentKey = false;
  selection.userVerification = 'required';
  prepared.authenticatorSelection = selection;
  prepared.attestation = 'none';

  return prepared;
}

/**
 * 将浏览器抛出的 WebAuthn 异常映射成面向测试人员的可读提示。
 */
export function normalizeWebAuthnBrowserError(error: unknown, fallback: string) {
  if (!(error instanceof Error)) {
    return fallback;
  }

  if (error.name === 'NotAllowedError') {
    return '浏览器取消或拦截了 Passkey 操作。请直接点击按钮后立即完成系统弹窗，并确认当前页面是 http://localhost:13000。';
  }

  if (error.name === 'InvalidStateError') {
    return '该设备上的 Passkey 状态异常，可能已注册过同一凭证。请刷新页面后重试。';
  }

  return error.message || fallback;
}

/**
 * 提取浏览器 WebAuthn 异常中的关键诊断字段，供调试面板展示。
 */
export function describeWebAuthnError(error: unknown) {
  if (!(error instanceof Error)) {
    return null;
  }

  const extra = error as Error & { code?: unknown; cause?: unknown };
  return {
    name: error.name || 'Error',
    message: error.message || '',
    code: typeof extra.code === 'number' ? extra.code : null,
    cause:
      extra.cause instanceof Error
        ? `${extra.cause.name}: ${extra.cause.message}`
        : typeof extra.cause === 'string'
          ? extra.cause
          : null,
  };
}
