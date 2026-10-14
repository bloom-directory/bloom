// Synthetic data only; use a fresh developer Triad with fixture TLS enabled.
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {spawn, spawnSync} from 'node:child_process';
import {mkdtempSync, readFileSync, chmodSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {createRequire} from 'node:module';
import https from 'node:https';
const require = createRequire(resolve(process.env.BLOOM_CHECKOUT_PLAYWRIGHT_ROOT, 'package.json'));
const {chromium} = require('playwright-core');
const binary = process.env.BLOOM_BIN;
const endpoint = process.env.BLOOM_TRAVELER_TEST_SOCKET;
const home = process.env.BLOOM_TRAVELER_TEST_HOME;
const output = process.argv[2];
assert(binary && endpoint && home && output);
const id = () => randomBytes(32).toString('hex');
const transcript = [];
async function vfs(command, path, body) {
  const child = spawn(binary, ['--quiet', '--connect', `unix:${endpoint}`, '--home', home, 'vfs', command, path], {stdio: ['pipe', 'pipe', 'pipe'], timeout: 45000});
  let stdout = ''; child.stdout.on('data', bytes => stdout += bytes); child.stderr.resume();
  child.stdin.end(body === undefined ? undefined : JSON.stringify(body));
  const code = await new Promise((resolve, reject) => {child.once('error', reject); child.once('close', resolve);});
  assert.equal(code, 0, `VFS ${command} ${path}`);
  if (command === 'cat') {const result = JSON.parse(stdout); transcript.push({path, result}); return result;}
}
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function poll(path, state) {
  for (let i = 0; i < 100; i++) {const result = await vfs('cat', path); if (result.state === state) return result; await pause(200);}
  throw new Error(`Expected ${state}`);
}
const slot = id();
async function browse(body) {await vfs('write', `/checkout/browse/${slot}/in.json`, body); return vfs('cat', `/checkout/browse/${slot}/out.json`);}
const root = mkdtempSync(join(tmpdir(), 'bloom-private-travelers-')); chmodSync(root, 0o700);
assert.equal(spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(root, 'key.pem'), '-out', join(root, 'cert.pem'), '-days', '1', '-subj', '/CN=localhost'], {stdio: 'ignore'}).status, 0);
let submitted = 0;
const server = https.createServer({key: readFileSync(join(root, 'key.pem')), cert: readFileSync(join(root, 'cert.pem'))}, (request, response) => {
  response.setHeader('content-type', 'text/html');
  if (request.url.startsWith('/done')) {submitted++; response.end('<h1>Order confirmed</h1><p>Order ID: SYNTHETIC</p><p>Total USD 3.99</p>'); return;}
  response.end(`<h1>Private passenger fixture</h1><p data-bloom-total-minor="399" data-bloom-currency="USD">Total USD 3.99</p>
    <form action="/done"><input autocomplete="given-name"><input autocomplete="family-name"><input autocomplete="bday" type="date">
    <input type="email"><input autocomplete="cc-number"><input autocomplete="cc-exp"><input autocomplete="cc-csc"><button type="submit">Pay</button></form>
    <script>document.addEventListener('input',()=>{document.title=document.querySelector('[autocomplete=given-name]').value;});</script>`);
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const merchant = `https://localhost:${server.address().port}/`;
const browser = await chromium.launch({executablePath: '/usr/lib/chromium/chromium', headless: true, args: ['--no-sandbox']});
const context = await browser.newContext();
const page = await context.newPage();
const cdp = await context.newCDPSession(page);
await cdp.send('WebAuthn.enable');
await cdp.send('WebAuthn.addVirtualAuthenticator', {options: {protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true}});
async function approve(url, values = {}) {
  await page.goto(url); await page.locator('#approve').waitFor();
  for (const [field, value] of Object.entries(values)) await page.locator(`#${field}`).fill(value);
  await page.locator('#approve').click();
  await page.waitForFunction(() => /saved|deleted|Approved/.test(document.getElementById('status').textContent), null, {timeout: 20000});
}
try {
  // Enroll through a traveler without requiring a card, then save a second person.
  const passengers = process.env.BLOOM_TRAVELER_TEST_ONE_PERSON === '1'
    ? [['wife', 'SyntheticWife']] : [['self', 'SyntheticSelf'], ['wife', 'SyntheticWife']];
  for (const [traveler, given] of passengers) {
    const operation = id();
    await vfs('write', '/travelers/save.json', {operation_id: operation, traveler_id: traveler, label: traveler});
    await approve((await vfs('cat', `/travelers/operations/${operation}/ceremony.json`)).ceremony_url, {
      'traveler-given_name': given, 'traveler-family_name': 'FixtureFamily',
      'traveler-born_on': '1992-02-29', 'traveler-email': `${traveler}@example.com`
    });
    await poll(`/travelers/operations/${operation}/status.json`, 'succeeded');
  }
  const people = await vfs('cat', '/travelers/index.json');
  console.log('Saved private travelers');
  assert.equal(people.length, passengers.length);
  for (const person of people) assert.deepEqual(Object.keys(person).sort(), ['fields', 'label', 'traveler_id']);
  // Card enrollment uses the same existing passkey.
  const add = id();
  await vfs('write', '/cards/add.json', {operation_id: add, card_id: 'fixture-card', label: 'Synthetic card'});
  await approve((await vfs('cat', `/cards/operations/${add}/ceremony.json`)).ceremony_url, {'card-number': '4242424242424242', 'card-expiry': '12/34', 'card-name': 'Synthetic Cardholder'});
  await poll(`/cards/operations/${add}/status.json`, 'succeeded');
  console.log('Saved card with existing passkey');
  await browse({action: 'open', url: merchant}); await pause(400);
  const fill = id();
  await vfs('write', `/checkout/requests/${fill}/in.json`, {traveler_id: 'wife', agent_description: 'Synthetic wife passenger'});
  const viewPromise = context.waitForEvent('page');
  await approve((await vfs('cat', `/checkout/requests/${fill}/status.json`)).ceremony_url);
  const view = await viewPromise;
  await poll(`/checkout/requests/${fill}/status.json`, 'filled');
  console.log('Private traveler autofill completed');
  assert.equal(submitted, 0);
  await assert.rejects(browse({action: 'snapshot'}));
  // Only test code observes synthetic private fields, never a real traveler view.
  await view.locator('#finish').click();
  await poll(`/checkout/requests/${fill}/status.json`, 'ready_for_payment');
  console.log('Ready for payment');
  const facts = await vfs('cat', `/checkout/requests/${fill}/facts.json`);
  assert.equal(facts.total_minor, 399); assert.equal(facts.currency, 'USD');
  console.log('Financial facts verified');
  const payment = id();
  const paymentViewPromise = context.waitForEvent('page', {timeout: 30000});
  await vfs('write', `/checkout/requests/${payment}/in.json`, {card_id: 'fixture-card', continue_private: fill, agent_description: 'Synthetic fare USD 3.99'});
  await approve((await vfs('cat', `/checkout/requests/${payment}/status.json`)).ceremony_url, {'card-cvc': '937'});
  const paymentView = await paymentViewPromise;
  await poll(`/checkout/requests/${payment}/status.json`, 'paid');
  assert.equal(submitted, 1);
  await paymentView.close(); await view.close();
  const publicResults = JSON.stringify(transcript);
  for (const secret of ['SyntheticSelf', 'SyntheticWife', 'FixtureFamily', 'wife@example.com', '1992-02-29', '4242424242424242']) assert(!publicResults.includes(secret));
  writeFileSync(output, JSON.stringify({result: 'passed', private_passengers_saved: passengers.length, real_broker_js: true, same_passkey_card: true, autofill_then_separate_payment: true, public_nondisclosure: true, submitted}, null, 2));
} catch (error) {console.error(error); process.exitCode = 1;}
finally {await browser.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve));}
