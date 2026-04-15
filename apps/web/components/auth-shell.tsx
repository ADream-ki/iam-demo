'use client';

import { useActionState, useEffect, useState, useTransition } from 'react';
import { useRouter } from 'next/navigation';
import { startAuthentication } from '@simplewebauthn/browser';

import {
  ActionState,
  beginPasskeyLoginAction,
  finishPasskeyLoginAction,
  passwordLoginAction,
  requestMfaOtpAction,
  requestOtpAction,
  verifyOtpAction,
  verifyMfaOtpAction,
} from '@/app/actions/auth';
import { SubjectKey, subjectThemes } from '@/lib/subjects';
import { normalizeWebAuthnBrowserError, normalizeWebAuthnOptions } from '@/lib/webauthn';

type Props = {
  subject: SubjectKey;
  initialStage?: 'auth' | 'mfa';
};

/**
 * 渲染三类主体统一认证入口，覆盖密码、OTP、Passkey 登录以及后续 MFA OTP 补验。
 */
export function AuthShell({ subject, initialStage = 'auth' }: Props) {
  const theme = subjectThemes[subject];
  const router = useRouter();
  const [tab, setTab] = useState<'password' | 'otp' | 'passkey'>('password');
  const [stage, setStage] = useState<'auth' | 'mfa'>(initialStage);
  const [email, setEmail] = useState(subject === 'platform' ? 'platform@example.com' : 'alex@example.com');
  const [deviceName, setDeviceName] = useState('Secure Hub 浏览器');
  const [rememberDevice, setRememberDevice] = useState(false);
  const [passkeyError, setPasskeyError] = useState<string | null>(null);
  const [isPasskeyPending, setIsPasskeyPending] = useState(false);
  const [isPending, startTransition] = useTransition();

  const initialState: ActionState = { ok: false };
  const [passwordState, passwordFormAction] = useActionState(passwordLoginAction, initialState);
  const [otpRequestState, otpRequestFormAction] = useActionState(requestOtpAction, initialState);
  const [otpVerifyState, otpVerifyFormAction] = useActionState(verifyOtpAction, initialState);
  const [mfaOtpRequestState, mfaOtpRequestFormAction] = useActionState(requestMfaOtpAction, initialState);
  const [mfaOtpState, mfaOtpFormAction] = useActionState(verifyMfaOtpAction, initialState);

  useEffect(() => {
    setStage(initialStage);
  }, [initialStage]);

  useEffect(() => {
    const result = [mfaOtpState, otpVerifyState, passwordState].find((item) => item.ok && item.nextPath);
    if (!result) return;

    if (result.requiresMfa) {
      setStage('mfa');
      return;
    }

    router.push(result.nextPath!);
  }, [passwordState, otpVerifyState, mfaOtpState, router]);

  /**
   * 发起 Passkey 登录：
   * 浏览器先完成 assertion，再把签名结果交回后端换取正式会话。
   */
  async function handlePasskeyLogin() {
    setPasskeyError(null);
    setIsPasskeyPending(true);
    try {
      const challengeResult = await beginPasskeyLoginAction(email, subject);
      if (!challengeResult.ok) {
        setPasskeyError(challengeResult.error);
        return;
      }

      const challenge = challengeResult.data;
      const response = await startAuthentication({
        optionsJSON: normalizeWebAuthnOptions(challenge.public_key) as never,
      });
      const result = await finishPasskeyLoginAction({
        challengeId: challenge.challenge_id,
        email,
        subject,
        response,
        rememberDevice,
        deviceName,
      });

      if (!result.ok) {
        setPasskeyError(result.error || 'Passkey 登录失败');
        return;
      }

      if (result.requiresMfa) {
        setStage('mfa');
        return;
      }

      router.push(result.nextPath || `/dashboard/${subject}`);
    } catch (error) {
      setPasskeyError(normalizeWebAuthnBrowserError(error, 'Passkey 登录失败'));
    } finally {
      setIsPasskeyPending(false);
    }
  }

  return (
    <div className="auth-shell" style={{ ['--accent' as string]: theme.accent, ['--accent-soft' as string]: theme.accentSoft }}>
      <div className="auth-card">
        <div className="auth-card__progress" />
        <a className="ghost-link" href="/">
          返回主体选择
        </a>
        <div className="auth-card__header">
          <div className="subject-icon">{theme.title.slice(0, 1)}</div>
          <div>
            <p className="eyebrow">{theme.shortTag}</p>
            <h1>{stage === 'mfa' ? 'MFA 验证' : `${theme.title} 登录`}</h1>
            <p>{stage === 'mfa' ? '请先发送 OTP，再输入邮箱验证码以完成完整认证流程。' : theme.description}</p>
          </div>
        </div>

        {stage === 'auth' ? (
          <>
            <div className="tab-row">
              <button type="button" className={tab === 'password' ? 'active' : ''} onClick={() => setTab('password')}>
                账号密码
              </button>
              <button type="button" className={tab === 'otp' ? 'active' : ''} onClick={() => setTab('otp')}>
                OTP
              </button>
              <button type="button" className={tab === 'passkey' ? 'active' : ''} onClick={() => setTab('passkey')}>
                Passkey
              </button>
            </div>

            {tab === 'password' && (
              <form action={passwordFormAction} className="auth-form">
                <input type="hidden" name="role" value={theme.role} />
                <input type="hidden" name="device_name" value={deviceName} />
                <label>
                  邮箱
                  <input name="email" value={email} onChange={(event) => setEmail(event.target.value)} required />
                </label>
                <label>
                  密码
                  <input
                    name="password"
                    type="password"
                    defaultValue={subject === 'platform' ? 'Platf0rm!' : 'Passw0rd!'}
                    required
                  />
                </label>
                <label>
                  设备名称
                  <input name="device_name_preview" value={deviceName} onChange={(event) => setDeviceName(event.target.value)} />
                </label>
                <label className="remember-row">
                  <input name="remember_device" type="checkbox" checked={rememberDevice} onChange={(event) => setRememberDevice(event.target.checked)} />
                  记住此设备，7 天内跳过重复全链路 MFA
                </label>
                {passwordState.error && <p className="error-text">{passwordState.error}</p>}
                <button className="primary-button" type="submit">
                  立即登录
                </button>
              </form>
            )}

            {tab === 'otp' && (
              <div className="auth-form otp-stack">
                <form action={otpRequestFormAction}>
                  <input type="hidden" name="role" value={theme.role} />
                  <label>
                    邮箱
                    <input name="email" value={email} onChange={(event) => setEmail(event.target.value)} required />
                  </label>
                  <button className="secondary-button" type="submit">
                    发送 OTP
                  </button>
                </form>
                {otpRequestState.message && <p className="hint-text">{otpRequestState.message}</p>}
                {otpRequestState.demoCode && <p className="hint-text">开发环境 OTP：{otpRequestState.demoCode}</p>}
                {otpRequestState.error && <p className="error-text">{otpRequestState.error}</p>}
                <form action={otpVerifyFormAction}>
                  <input type="hidden" name="role" value={theme.role} />
                  <input type="hidden" name="email" value={email} />
                  <input type="hidden" name="device_name" value={deviceName} />
                  <label>
                    OTP 验证码
                    <input name="code" placeholder="6 位数字验证码" required />
                  </label>
                  <label className="remember-row">
                    <input name="remember_device" type="checkbox" checked={rememberDevice} onChange={(event) => setRememberDevice(event.target.checked)} />
                    登录后记住此设备
                  </label>
                  {otpVerifyState.error && <p className="error-text">{otpVerifyState.error}</p>}
                  <button className="primary-button" type="submit">
                    验证并登录
                  </button>
                </form>
              </div>
            )}

            {tab === 'passkey' && (
              <div className="passkey-panel">
                <label>
                  邮箱
                  <input value={email} onChange={(event) => setEmail(event.target.value)} />
                </label>
                <label>
                  设备名称
                  <input value={deviceName} onChange={(event) => setDeviceName(event.target.value)} />
                </label>
                <label className="remember-row">
                  <input type="checkbox" checked={rememberDevice} onChange={(event) => setRememberDevice(event.target.checked)} />
                  登录后记住此设备
                </label>
                {passkeyError && <p className="error-text">{passkeyError}</p>}
                <button className="passkey-button" type="button" onClick={handlePasskeyLogin} disabled={isPending || isPasskeyPending}>
                  使用 Passkey 登录
                </button>
              </div>
            )}
          </>
        ) : (
          <div className="auth-form otp-stack">
            <form action={mfaOtpRequestFormAction}>
              <button className="secondary-button" type="submit">
                发送 MFA OTP
              </button>
            </form>
            {mfaOtpRequestState.message && <p className="hint-text">{mfaOtpRequestState.message}</p>}
            {mfaOtpRequestState.demoCode && <p className="hint-text">开发环境 OTP：{mfaOtpRequestState.demoCode}</p>}
            {mfaOtpRequestState.error && <p className="error-text">{mfaOtpRequestState.error}</p>}
            <form action={mfaOtpFormAction} className="auth-form">
              <input type="hidden" name="subject" value={subject} />
              <label>
                OTP 验证码
                <input name="code" placeholder="6 位数字验证码" required />
              </label>
              {mfaOtpState.error && <p className="error-text">{mfaOtpState.error}</p>}
              <button className="primary-button" type="submit">
                完成 MFA
              </button>
            </form>
          </div>
        )}
      </div>
    </div>
  );
}



