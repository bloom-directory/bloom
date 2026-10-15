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
  // Like an airline: the passenger page echoes the name, contact details follow on the payment page.
  if (request.url.startsWith('/payment')) {response.end(`<html lang="es"><h1>Pago</h1><div>Total</div><div>:</div><div>$3,99</div><div>USD</div>
    <form action="/done"><div><div>Correo electrónico</div><input name="email"></div>
    <input autocomplete="cc-number"><input autocomplete="cc-exp"><input autocomplete="cc-csc"><button type="submit">Pagar Ahora</button></form></html>`); return;}
  response.end(`<h1>Passenger fixture</h1><div><div>Nombres</div><input name="firstName-0"></div><div><div>Apellidos</div><input name="lastName-0"></div>
    <input autocomplete="bday" type="date"><h2 id="echo"></h2><a href="/payment">Continuar</a>
    <script>document.addEventListener('input',()=>{const n=document.querySelector('[name=firstName-0]').value;echo.textContent='Hola '+n;document.title=n;});</script>`);
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
  // One approval unlocks the person for this website; the agent keeps shopping.
  const unlock = id();
  await vfs('write', `/checkout/requests/${unlock}/in.json`, {traveler_id: 'wife', agent_description: 'Synthetic wife passenger'});
  await approve((await vfs('cat', `/checkout/requests/${unlock}/status.json`)).ceremony_url);
  await poll(`/checkout/requests/${unlock}/status.json`, 'unlocked');
  console.log('Traveler unlocked with one approval');
  const first = await browse({action: 'fill_traveler'});
  assert.deepEqual(first.filled_fields, ['given_name', 'family_name', 'born_on']);
  let snapshot = await browse({action: 'snapshot'});
  assert(JSON.stringify(snapshot).includes('Hola [saved given_name]'));
  assert(snapshot.elements.some(e => e.label === 'Apellidos' && e.value === '[saved family_name]'));
  const next = snapshot.elements.find(e => e.label === 'Continuar');
  await browse({action: 'click', element_ref: next.ref}); await pause(600);
  const second = await browse({action: 'fill_traveler'});
  assert.deepEqual(second.filled_fields, ['email']);
  snapshot = await browse({action: 'snapshot'});
  assert(snapshot.elements.some(e => e.value === '[saved email]'));
  console.log('Filled passenger and payment pages without exposing values');
  assert.equal(submitted, 0);
  const payment = id();
  await vfs('write', `/checkout/requests/${payment}/in.json`, {card_id: 'fixture-card', agent_description: 'Synthetic fare USD 3.99'});
  await approve((await vfs('cat', `/checkout/requests/${payment}/status.json`)).ceremony_url, {'card-cvc': '937'});
  await poll(`/checkout/requests/${payment}/status.json`, 'paid');
  assert.equal(submitted, 1);
  for (const privatePage of context.pages().filter(candidate => candidate !== page)) await privatePage.close();
  const publicResults = JSON.stringify(transcript);
  for (const secret of ['SyntheticSelf', 'SyntheticWife', 'FixtureFamily', 'wife@example.com', '1992-02-29', '4242424242424242']) assert(!publicResults.includes(secret));
  writeFileSync(output, JSON.stringify({result: 'passed', private_passengers_saved: passengers.length, real_broker_js: true, same_passkey_card: true, unlock_once_fill_two_pages_then_pay: true, public_nondisclosure: true, submitted}, null, 2));
} catch (error) {console.error(error); process.exitCode = 1;}
finally {await browser.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve));}
