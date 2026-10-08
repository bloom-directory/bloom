// Stage 0: exercise the unchanged Broker browser crypto with synthetic input.
// Args: isolated playwright-core module path, Broker app.js path.
const { chromium } = require(process.argv[2]);
const fs = require('node:fs');
const http = require('node:http');
const assert = require('node:assert/strict');

async function main() {
  const original = fs.readFileSync(process.argv[3], 'utf8');
  const startup = '\nload().catch(error => reportCeremonyError(';
  const index = original.lastIndexOf(startup);
  assert(index > 0, 'Broker startup changed: inspect before adapting spike');
  const source = original.slice(0, index);
  const ids = [...source.matchAll(/document\.getElementById\("([^"\n]+)"\)/g)];
  const html = ids.map(m => `<input id="${m[1]}">`).join('');
  const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.end(html);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({
      executablePath: '/usr/lib/chromium/chromium', chromiumSandbox: true,
      args: ['--disable-extensions'],
    });
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    await page.addScriptTag({ content: source });
    const result = await page.evaluate(async () => {
      await cryptoSelfTest();
      const keys = await crypto.subtle.generateKey({name:'X25519'}, true, ['deriveBits']);
      const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey));
      const recipient = {privateKey: keys.privateKey, publicKey};
      // No card is sent to a merchant, API, or ceremony. This is only a cipher test.
      const input = te.encode(JSON.stringify({
        credential_prf: 'A'.repeat(43),
        card: {number: '4242424242424242', expiry: '12/30', name: 'Synthetic Test'},
        cvc: '123',
      }));
      const info = te.encode('bloom-custody-input/v1');
      const aad = te.encode('{"stage0":true,"request":"synthetic-only"}');
      const envelope = await hpkeSeal(publicKey, info, aad, input);
      const opened = await hpkeOpen(recipient, info, aad, envelope);
      const matches = opened.length === input.length && opened.every((v,i) => v === input[i]);
      async function rejects(changedInfo, changedAad, changedEnvelope) {
        try { await hpkeOpen(recipient, changedInfo, changedAad, changedEnvelope); return false; }
        catch { return true; }
      }
      const altered = decodeUrl(envelope.ciphertext);
      altered[0] ^= 1;
      return {
        browserSelfTest: 'pass', syntheticRoundTrip: matches,
        plaintextBytes: input.length,
        decodedEnvelopeBytes: decodeUrl(envelope.kem_output).length + decodeUrl(envelope.ciphertext).length,
        tamperRejected: await rejects(info, aad, {...envelope, ciphertext: encodeUrl(altered)}),
        changedBindingRejected: await rejects(info, te.encode('{"stage0":false}'), envelope),
        changedDomainRejected: await rejects(te.encode('different-domain'), aad, envelope),
        realPasskey: 'NOT TESTED', signerInterop: 'NOT TESTED',
        newCeremonyKind: 'NOT IMPLEMENTED; current enums reject card kinds',
      };
    });
    assert(result.syntheticRoundTrip && result.tamperRejected && result.changedBindingRejected && result.changedDomainRejected);
    assert(result.decodedEnvelopeBytes <= 4096);
    console.log(JSON.stringify(result, null, 2));
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
}
main().catch(error => { console.error(error.name); process.exitCode = 1; });
