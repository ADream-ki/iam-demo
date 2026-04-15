const { chromium } = require('../node_modules/playwright');

const BASE_URL = process.env.BASE_URL || 'http://localhost:13000';
const EDGE_PATH = process.env.EDGE_PATH || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';

async function textIfVisible(locator) {
  const count = await locator.count();
  if (count === 0) return null;
  const first = locator.first();
  if (!(await first.isVisible().catch(() => false))) return null;
  return (await first.textContent())?.trim() || null;
}

(async () => {
  const browser = await chromium.launch({ headless: true, executablePath: EDGE_PATH });
  const context = await browser.newContext();
  const page = await context.newPage();
  page.on('console', (msg) => console.log('[browser-console]', msg.type(), msg.text()));
  page.on('pageerror', (err) => console.log('[pageerror]', err.message));
  page.on('request', (request) => {
    if (request.method() === 'POST') console.log('[post-request]', request.url());
  });
  page.on('response', async (response) => {
    if (response.request().method() !== 'POST') return;
    let body = '';
    try { body = await response.text(); } catch {}
    console.log('[post-response]', response.status(), response.url(), body.slice(0, 500));
  });

  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  try {
    await page.goto(`${BASE_URL}/auth/platform`, { waitUntil: 'domcontentloaded' });
    await page.getByLabel('邮箱').first().fill('platform@example.com');
    await page.getByLabel('密码').fill('Platf0rm!');
    await page.getByRole('button', { name: '立即登录' }).click();

    await page.getByText('MFA 验证').waitFor({ timeout: 10000 });
    await page.getByRole('button', { name: '发送 MFA OTP' }).click();
    const demoText = await page.getByText(/开发环境 OTP：\d{6}/).textContent({ timeout: 10000 });
    const code = demoText.match(/(\d{6})/)[1];
    console.log('[info] mfa otp code:', code);
    await page.getByLabel('OTP 验证码').last().fill(code);
    await page.getByRole('button', { name: '完成 MFA' }).click();
    await page.waitForURL(/\/dashboard\/platform$/, { timeout: 10000 });
    console.log('[ok] password + otp login reached dashboard');

    await page.getByRole('button', { name: '注册 Passkey' }).click();
    await page.waitForTimeout(3000);
    const registerError = await textIfVisible(page.locator('.error-text'));
    const credentialsAfterEnroll = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
    console.log('[info] credentials after enroll:', JSON.stringify(credentialsAfterEnroll.credentials || []));
    if (registerError) throw new Error(`passkey enroll error: ${registerError}`);
    if (!credentialsAfterEnroll.credentials || credentialsAfterEnroll.credentials.length === 0) {
      throw new Error('passkey enroll did not create a credential');
    }
    console.log('[ok] passkey enrolled');
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
