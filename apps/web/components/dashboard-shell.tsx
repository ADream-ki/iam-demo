'use client';

import { useState, useTransition } from 'react';
import { useRouter } from 'next/navigation';
import { startRegistration } from '@simplewebauthn/browser';

import {
  beginPasskeyRegisterAction,
  finishPasskeyRegisterAction,
  logoutAction,
  revokeOtherSessionsAction,
  revokeSessionAction,
} from '@/app/actions/auth';
import { SubjectKey, subjectThemes } from '@/lib/subjects';
import {
  describeWebAuthnError,
  normalizeWebAuthnBrowserError,
  preparePasskeyRegistrationOptions,
} from '@/lib/webauthn';

type SessionSummary = {
  id: string;
  device_name: string;
  user_agent?: string | null;
  ip?: string | null;
  mfa_level: 'none' | 'partial' | 'full';
  expires_at: string;
  last_seen_at: string;
  current: boolean;
};

type DashboardProps = {
  subject: SubjectKey;
  email: string;
  displayName: string;
  sessions: SessionSummary[];
};

type PasskeyDebugInfo = {
  origin: string;
  isSecureContext: boolean;
  platformAuthenticatorAvailable: boolean | null;
  rpId: string | null;
  userVerification: string | null;
  residentKey: string | null;
  hasExtensions: boolean;
  hasHints: boolean;
  browserErrorName?: string | null;
  browserErrorMessage?: string | null;
  browserErrorCode?: number | null;
  browserErrorCause?: string | null;
};

/**
 * 渲染已登录用户的控制台，并承载会话审计、Passkey 注册与远程下线操作。
 */
export function DashboardShell({ subject, email, displayName, sessions }: DashboardProps) {
  const theme = subjectThemes[subject];
  const router = useRouter();
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [passkeyDebug, setPasskeyDebug] = useState<PasskeyDebugInfo | null>(null);
  const [isRegisteringPasskey, setIsRegisteringPasskey] = useState(false);
  const [isPending, startTransition] = useTransition();

  /** 注销当前会话并返回主体选择页。 */
  function handleLogout() {
    startTransition(async () => {
      await logoutAction();
      router.push('/');
    });
  }

  /** 下线指定设备会话，并刷新当前仪表盘数据。 */
  function handleRevoke(sessionId: string) {
    startTransition(async () => {
      setBusyId(sessionId);
      setError(null);
      try {
        await revokeSessionAction(sessionId);
        router.refresh();
      } catch (actionError) {
        setError(actionError instanceof Error ? actionError.message : '设备下线失败');
      } finally {
        setBusyId(null);
      }
    });
  }

  /** 一键撤销除当前设备外的全部会话。 */
  function handleRevokeOthers() {
    startTransition(async () => {
      setError(null);
      try {
        await revokeOtherSessionsAction();
        router.refresh();
      } catch (actionError) {
        setError(actionError instanceof Error ? actionError.message : '批量下线失败');
      }
    });
  }

  /**
   * 发起 Passkey 注册流程：
   * 先取 challenge，再在浏览器中调起 WebAuthn，最后把 attestation 返回后端完成落库。
   */
  async function handlePasskeyEnroll() {
    setError(null);
    setPasskeyDebug(null);
    setIsRegisteringPasskey(true);
    try {
      const challengeResult = await beginPasskeyRegisterAction(email);
      if (!challengeResult.ok) {
        setError(challengeResult.error);
        return;
      }

      const challenge = challengeResult.data;
      const options = preparePasskeyRegistrationOptions(challenge.public_key);
      const webAuthnError = await detectPlatformAuthenticator();
      setPasskeyDebug({
        origin: window.location.origin,
        isSecureContext: window.isSecureContext,
        platformAuthenticatorAvailable: webAuthnError,
        rpId: readNestedString(options, ['rp', 'id']),
        userVerification: readNestedString(options, ['authenticatorSelection', 'userVerification']),
        residentKey: readNestedString(options, ['authenticatorSelection', 'residentKey']),
        hasExtensions: Object.prototype.hasOwnProperty.call(options, 'extensions'),
        hasHints: Object.prototype.hasOwnProperty.call(options, 'hints'),
      });
      const response = await startRegistration({
        optionsJSON: options as never,
      });
      const verifyResult = await finishPasskeyRegisterAction({
        challengeId: challenge.challenge_id,
        response,
      });
      if (!verifyResult.ok) {
        setError(verifyResult.error);
        return;
      }
      router.refresh();
    } catch (actionError) {
      const details = describeWebAuthnError(actionError);
      setPasskeyDebug((current) =>
        current
          ? {
              ...current,
              browserErrorName: details?.name ?? null,
              browserErrorMessage: details?.message ?? null,
              browserErrorCode: details?.code ?? null,
              browserErrorCause: details?.cause ?? null,
            }
          : null,
      );
      setError(normalizeWebAuthnBrowserError(actionError, 'Passkey 注册失败'));
    } finally {
      setIsRegisteringPasskey(false);
    }
  }

  return (
    <div className="dashboard-shell" style={{ ['--accent' as string]: theme.accent, ['--accent-soft' as string]: theme.accentSoft }}>
      <header className="dashboard-header">
        <div>
          <p className="eyebrow">{theme.shortTag}</p>
          <h1>{displayName}</h1>
          <p>{email}</p>
        </div>
        <div className="dashboard-actions">
          <button className="secondary-button" type="button" onClick={handlePasskeyEnroll} disabled={isPending || isRegisteringPasskey}>
            注册 Passkey
          </button>
          <button className="ghost-button" type="button" onClick={handleLogout}>
            退出登录
          </button>
        </div>
      </header>

      <section className="hero-panel">
        <div>
          <p className="eyebrow">Live Session Audit</p>
          <h2>终端会话审计</h2>
          <p>多主体会话按角色隔离，同一 Identity 下的不同 Subject 互不串扰。</p>
        </div>
        <button className="secondary-button" type="button" onClick={handleRevokeOthers}>
          下线其他设备
        </button>
      </section>

      {error && <p className="error-text">{error}</p>}
      {passkeyDebug && (
        <details className="session-card" open>
          <summary>Passkey 调试信息</summary>
          <pre style={{ marginTop: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
            {JSON.stringify(passkeyDebug, null, 2)}
          </pre>
        </details>
      )}

      <section className="session-grid">
        {sessions.map((session) => (
          <article key={session.id} className={`session-card${session.current ? ' session-card--active' : ''}`}>
            <div>
              <div className="session-card__title-row">
                <h3>{session.device_name}</h3>
                <span>{session.current ? 'Active Now' : session.mfa_level.toUpperCase()}</span>
              </div>
              <p>{session.user_agent || 'Browser Session'}</p>
              <p>{session.ip || 'IP unavailable'}</p>
              <p>最后活跃：{new Date(session.last_seen_at).toLocaleString()}</p>
            </div>
            <div className="session-card__actions">
              <p>过期时间：{new Date(session.expires_at).toLocaleString()}</p>
              {!session.current && (
                <button className="danger-button" type="button" onClick={() => handleRevoke(session.id)} disabled={busyId === session.id}>
                  远程下线
                </button>
              )}
            </div>
          </article>
        ))}
      </section>
    </div>
  );
}

/**
 * 探测当前浏览器是否声明支持“平台型且具备用户验证”的认证器。
 */
async function detectPlatformAuthenticator() {
  if (
    typeof window === 'undefined' ||
    typeof PublicKeyCredential === 'undefined' ||
    typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== 'function'
  ) {
    return null;
  }

  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return null;
  }
}

/**
 * 从 challenge/options 对象中安全读取嵌套字符串字段，避免调试输出时因路径缺失报错。
 */
function readNestedString(source: Record<string, unknown>, path: string[]) {
  let current: unknown = source;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current) || !(key in current)) {
      return null;
    }
    current = (current as Record<string, unknown>)[key];
  }

  return typeof current === 'string' ? current : null;
}
