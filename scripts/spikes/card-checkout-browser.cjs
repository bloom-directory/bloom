// Stage 0 only. Anonymous browsing; never fill or submit payment fields.
// Install playwright-core@1.64.0 in an isolated directory; pass it as arg 1.
// Arg 2 is an optional public HTTPS URL. No existing profile is opened.
const { chromium } = require(process.argv[2]);
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');

async function main() {
  const url = process.argv[3];
  if (url && new URL(url).protocol !== 'https:') throw new Error('HTTPS required');
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'bloom-card-spike-'));
  fs.chmodSync(profile, 0o700);
  const context = await chromium.launchPersistentContext(profile, {
    executablePath: '/usr/lib/chromium/chromium',
    headless: true,
    chromiumSandbox: true,
    args: ['--disable-extensions', '--enable-automation'],
  });
  try {
    const page = context.pages()[0];
    await page.setContent('<title>Stage 0 pipe probe</title><p>anonymous fixture</p>');
    assert.equal(await page.title(), 'Stage 0 pipe probe');
    const session = await context.newCDPSession(page);
    const { arguments: argv } = await session.send('Browser.getBrowserCommandLine');
    assert(argv.includes('--remote-debugging-pipe'));
    assert(!argv.some(a => a.startsWith('--remote-debugging-port')));
    assert(!argv.includes('--no-sandbox'));
    const result = {
      browser: context.browser().version(), uid: process.getuid(),
      transport: 'remote-debugging-pipe', chromiumSandbox: true,
      isolation: 'SAME UID: NOT CONFORMING',
      profileMode: (fs.statSync(profile).mode & 0o777).toString(8),
      profileRetained: profile,
      devToolsActivePort: fs.existsSync(path.join(profile, 'DevToolsActivePort')),
      fixtureRead: 'pass',
    };
    if (url) {
      try {
        const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
        await page.waitForTimeout(3000);
        result.publicPage = {
          requestedOrigin: new URL(url).origin,
          finalOrigin: new URL(page.url()).origin,
          httpStatus: response?.status(), title: (await page.title()).slice(0, 150),
          frameOrigins: [...new Set(page.frames().map(f => {
            try { return new URL(f.url()).origin; } catch { return 'unresolved'; }
          }))],
          paymentFieldCount: await page.locator('[autocomplete^="cc-"]').count(),
          acceptanceCheckout: false,
        };
      } catch (error) {
        // Never print exception text that could contain a token-bearing URL.
        result.publicPage = { requestedOrigin: new URL(url).origin, error: error.name };
      }
    }
    result.observation = 'No card, login, cookies, screenshot, trace, or submit';
    console.log(JSON.stringify(result, null, 2));
  } finally {
    await context.close();
    // Deliberately retain this anonymous profile; no recursive deletion.
  }
}
main().catch(error => { console.error(error.message.slice(0, 4000)); process.exitCode = 1; });
