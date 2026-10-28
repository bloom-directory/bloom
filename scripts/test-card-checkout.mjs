// A fresh developer Triad, real Broker/Signer, real ceremony JS, synthetic card.
// Requires --checkout-fixture-tls only for the local manual/site fixtures.
// Card release goes to Stripe's public test checkout, never a live merchant.
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {spawn, spawnSync} from 'node:child_process';
import {mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {createRequire} from 'node:module';
import https from 'node:https';
import http from 'node:http';

const binary = process.env.BLOOM_BIN;
const home = process.env.BLOOM_HOME;
const endpoint = process.env.BLOOM_RPC_ENDPOINT;
const ceremonyOrigin = process.env.BLOOM_CHECKOUT_CEREMONY_ORIGIN;
const viewOrigin = process.env.BLOOM_CHECKOUT_VIEW_ORIGIN;
const output = process.argv[2];
assert(binary && home && endpoint && ceremonyOrigin && viewOrigin && output,
  'Set explicit candidate binary, home, endpoint, ceremony/view origins and result path');
assert(endpoint.startsWith('unix:'));
assert.equal(new URL(ceremonyOrigin).hostname, 'localhost');
assert.notEqual(new URL(ceremonyOrigin).port, '18734', 'Leave installed custody alone');
assert.equal(new URL(viewOrigin).hostname, 'localhost');
const require = createRequire(resolve(process.env.BLOOM_CHECKOUT_PLAYWRIGHT_ROOT || '.', 'package.json'));
const {chromium} = require('playwright-core');
const id = () => randomBytes(32).toString('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const slot = id();
const checks = [];
let stage = 'fresh candidate';
let fixtureSubmissions = 0;
function checkpoint(name, details = {}) {
  checks.push({name, ...details});
  writeFileSync(output, JSON.stringify({result:'running', checks}, null, 2));
  console.log(`PASS ${name}`);
  stage = name;
}
async function vfs(command, path, value) {
  const child = spawn(binary, ['--quiet', '--home', home, '--connect', endpoint, 'vfs', command, path],
    {stdio:['pipe','pipe','pipe'], timeout:90000});
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', bytes => stdout += bytes);
  child.stderr.on('data', bytes => { stderr = (stderr+bytes).slice(-4096); });
  child.stdin.end(value === undefined ? undefined : JSON.stringify(value));
  const status = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
  const diagnostic = stderr.replaceAll('4242424242424242','[test card]')
    .replaceAll('Bloom Synthetic Cardholder','[test holder]')
    .replace(/private\?token=[^\s"']+/g,'private?[redacted]');
  assert.equal(status, 0, `VFS ${command} ${path} failed: ${diagnostic}`);
  if (command !== 'cat') return;
  assert(!stdout.includes('4242424242424242') && !stdout.includes('Bloom Synthetic Cardholder')
    && !stdout.includes('private?token='), 'Private fixture values leaked through VFS');
  return JSON.parse(stdout);
}
async function browse(request) {
  for (let attempt = 0; ; attempt++) {
    try {
      await vfs('write', `/checkout/browse/${slot}/in.json`, request);
      return await vfs('cat', `/checkout/browse/${slot}/out.json`);
    } catch (error) {
      // Reading through changing payment/captcha frames can lose a document.
      // Reobserve as the VFS guidance says; never replay an action or payment.
      if (request.action !== 'snapshot' || attempt === 4 || !/snapshot|page could not be read or changed/i.test(error.message)) {
        error.message = `${request.action}: ${error.message}`;
        throw error;
      }
      await delay(500);
    }
  }
}
async function typeVisible(label, text, required = true) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const snapshot = await browse({action:'snapshot'});
    const field = snapshot.elements.find(e => e.role === 'input' && label.test(e.label));
    if (!field) { if (!required) return; await delay(500); continue; }
    try { await browse({action:'type',element_ref:field.ref,text}); return; }
    catch (error) {
      // Stripe replaces ordinary contact controls while its frames load.
      // Reobserve a stale binding; never retry a payment action here.
      if (!/snapshot|stale|page could not be read or changed/i.test(error.message)) throw error;
      await delay(500);
    }
  }
  throw Error(`Contact field did not stabilize: ${label}`);
}
async function poll(path, states) {
  let lastState = 'unavailable';
  for (let attempt = 0; attempt < 150; attempt++) {
    const status = await vfs('cat', path);
    if (states.includes(status.state)) return status;
    lastState = status.state;
    await delay(250);
  }
  throw Error(`State timeout during ${stage}; last state: ${lastState}`);
}
async function returnedToShopping() {
  for (let attempt = 0; attempt < 50; attempt++) {
    try { const s = await browse({action:'snapshot'}); assert.equal(s.url, 'about:blank'); return; }
    catch { await delay(100); }
  }
  throw Error('Shopping did not return after closing private checkout');
}

// Fixture keys are generated by this test and never leave this process.
const root = mkdtempSync(join(tmpdir(), 'bloom-shopping-e2e-'));
assert.equal(spawnSync('openssl', ['req','-x509','-newkey','rsa:2048','-nodes',
  '-keyout',join(root,'key.pem'),'-out',join(root,'cert.pem'),'-days','1',
  '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'], {stdio:'ignore'}).status, 0);
const server = https.createServer({key:readFileSync(join(root,'key.pem')),cert:readFileSync(join(root,'cert.pem'))}, (request,response) => {
  const url = new URL(request.url, 'https://localhost');
  response.setHeader('content-type','text/html');
  if (url.pathname === '/manual') response.end('<h1>Manual fixture</h1><p>Total unavailable</p>');
  else if (url.pathname === '/ambiguous') response.end('<p>Total USD 3.99</p><form action="/done"><button>Pay</button></form><form action="/done"><button>Subscribe USD 12.00 monthly</button></form>');
  else if (url.pathname === '/installments') response.end('<p>Total USD 3.99</p><form action="/done"><label>Installments<select name="installments"><option>Choose a schedule</option></select></label><button>Pay</button></form>');
  else if (url.pathname === '/site') response.end('<h1>Fixture shop</h1><p>Order total USD 3.99</p><form action="/done"><button>Place order</button></form>');
  else if (url.pathname === '/done') { fixtureSubmissions++; response.end('<h1>Order confirmed</h1><p>Order ID: FIXTURE-ONE</p><p>Total USD 3.99</p>'); }
  else if (url.pathname === '/login') response.end('<form action="/account"><input name="user" aria-label="User" style="width:90vw;height:80vh;font-size:40px"></form>');
  else if (url.pathname === '/account') response.end(`<h1>Signed in as ${(url.searchParams.get('user') || '').replace(/[^a-z]/g,'')}</h1>`);
  else { response.statusCode = 404; response.end('Not found'); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const ambientCredentials = {cookie:false,authorization:false};
const neighborServer = http.createServer((request,response) => {
  ambientCredentials.cookie ||= /bloom_checkout_/.test(request.headers.cookie || '');
  ambientCredentials.authorization ||= !!request.headers.authorization;
  response.end('<title>Other local app fixture</title>');
});
await new Promise(resolve => neighborServer.listen(0,'127.0.0.1',resolve));
const merchant = `https://localhost:${server.address().port}/`;
const browser = await chromium.launch({executablePath:process.env.BLOOM_CHECKOUT_TEST_CHROMIUM || '/usr/lib/chromium/chromium',headless:true,args:['--no-sandbox']});
const context = await browser.newContext();
const page = await context.newPage();
const cdp = await context.newCDPSession(page);
await cdp.send('WebAuthn.enable');
await cdp.send('WebAuthn.addVirtualAuthenticator', {options:{protocol:'ctap2',ctap2Version:'ctap2_1',transport:'internal',
  hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true,hasPrf:true}});
async function approve(url, kind) {
  assert.equal(new URL(url).origin, ceremonyOrigin, 'Unexpected ceremony origin');
  stage = `approve ${kind}`;
  await page.goto(url);
  await page.locator('#approve').waitFor();
  if (kind === 'add') {
    await page.locator('#card-number').fill('4242424242424242');
    await page.locator('#card-expiry').fill('12/34');
    await page.locator('#card-name').fill('Bloom Synthetic Cardholder');
  }
  if (kind === 'card') await page.locator('#card-cvc').fill('937');
  await page.locator('#approve').click();
  await page.waitForFunction(() => /Completed\.|Approved\.|Card saved\.|Card deleted\.|Private view authorized|browser is yours/.test(document.getElementById('status').textContent), null, {timeout:30000});
}
async function checkoutStatus(operation) { return vfs('cat', `/checkout/requests/${operation}/status.json`); }
try {
  assert.deepEqual(await vfs('cat','/cards/index.json'), [], 'Use a fresh disposable candidate');
  assert.deepEqual(await vfs('cat','/checkout/history.json'), [], 'Preserve existing shopping history');
  for (const [path, reason] of [['manual','facts_unreadable'], ['ambiguous','payment_action_ambiguous'], ['installments','charge_terms_unreadable']]) {
    await browse({action:'open',url:merchant+path});
    await delay(500);
    const operation = id();
    await vfs('write',`/checkout/requests/${operation}/in.json`,{card_id:'missing-refusal-fixture',agent_description:'Synthetic refusal diagnostic; deliberately absent card; no approval or payment'});
    const status = await checkoutStatus(operation);
    assert.equal(status.state,'failed_before_release');
    assert.equal(status.reason,reason);
    assert.deepEqual(status.filled_fields,[]);
    const history = await vfs('cat','/checkout/history.json');
    assert.equal(history.find(entry => entry.status.operation_id === operation).status.reason,reason);
    await returnedToShopping();
    assert.equal(fixtureSubmissions,0,'Refusal must not try any payment action');
  }
  checkpoint('bounded refusal reasons survive real services, VFS status and history without submitting');
  const started = Date.now();
  const add = id();
  await vfs('write','/cards/add.json',{operation_id:add,card_id:'stack-card',label:'Synthetic acceptance card'});
  await approve((await vfs('cat',`/cards/operations/${add}/ceremony.json`)).ceremony_url,'add');
  await poll(`/cards/operations/${add}/status.json`, ['succeeded']);
  const cards = await vfs('cat','/cards/index.json');
  assert.equal(cards.length, 1); assert.equal(cards[0].last4,'4242');
  checkpoint('card enrolled through Broker and Signer');

  await browse({action:'open',url:merchant+'manual'}); await delay(500);
  const manual = id();
  await vfs('write',`/checkout/requests/${manual}/in.json`,{card_id:'stack-card',agent_description:'Synthetic manual fallback; no saved card release'});
  const opened = context.waitForEvent('page');
  await approve((await checkoutStatus(manual)).ceremony_url,'manual');
  let privatePage = await opened;
  const manualStatus = await poll(`/checkout/requests/${manual}/status.json`, ['manual_required']);
  assert.deepEqual(manualStatus.filled_fields, []);
  assert.equal(manualStatus.view_url, viewOrigin+'/view');
  await privatePage.locator('#screen').waitFor({state:'visible'});
  const neighbor = await context.newPage();
  await neighbor.goto(`http://localhost:${neighborServer.address().port}/`);
  assert.equal(await neighbor.evaluate(() => localStorage.getItem('bloom.checkout.session')),null);
  assert.deepEqual(ambientCredentials,{cookie:false,authorization:false});
  await neighbor.close();
  assert(await privatePage.evaluate(() => /^[a-f0-9]{64}$/.test(localStorage.getItem('bloom.checkout.session') || '')));
  checkpoint('private view session stays on its exact browser origin');
  await privatePage.close();
  privatePage = await context.newPage();
  assert.equal((await privatePage.goto(manualStatus.view_url)).status(),200);
  await privatePage.locator('#finish').click();
  await poll(`/checkout/requests/${manual}/status.json`, ['uncertain']);
  await returnedToShopping(); await privatePage.close();
  await vfs('write',`/checkout/requests/${manual}/resolve`,{});
  checkpoint('manual fallback releases no card; lost private tab reopens; shopping returns');

  stage = 'Stripe sandbox checkout';
  await browse({action:'open',url:'https://buy.stripe.com/test_28o7u4eQMcaUgWk8ww'}); await delay(10000);
  let snapshot = await browse({action:'snapshot'});
  assert(snapshot.url.startsWith('https://buy.stripe.com/test_'), 'Refuse a live payment page');
  await typeVisible(/^email$/i,'fixture-buyer@example.com');
  await typeVisible(/postal|zip/i,'12345',false);
  const payment = id();
  await vfs('write',`/checkout/requests/${payment}/in.json`,{card_id:'stack-card',agent_description:'Stripe public TEST subscription; synthetic card; no real funds'});
  const awaiting = await checkoutStatus(payment);
  assert.equal(awaiting.state,'awaiting_approval'); assert(!awaiting.reason, 'Payment discovery fell back to manual');
  await approve(awaiting.ceremony_url,'card');
  const paid = await poll(`/checkout/requests/${payment}/status.json`, ['paid','declined','uncertain','manual_required','disclosure_unknown','partially_filled']);
  assert.equal(paid.state,'paid'); assert(paid.filled_fields.includes('number'));
  await returnedToShopping();
  checkpoint('real Stripe sandbox paid after Broker/Signer approval and sealed card release');

  await browse({action:'open',url:merchant+'login'}); await delay(500);
  const takeOver = id();
  await vfs('write',`/checkout/requests/${takeOver}/in.json`,{take_over:true,agent_description:'Log in to the synthetic fixture shop'});
  const takeoverOpened = context.waitForEvent('page');
  await approve((await checkoutStatus(takeOver)).ceremony_url,'take-over');
  const takeoverPage = await takeoverOpened;
  await poll(`/checkout/requests/${takeOver}/status.json`, ['human_control']);
  await takeoverPage.locator('#screen').waitFor();
  await takeoverPage.locator('#screen').click({position:{x:40,y:40}});
  await takeoverPage.keyboard.type('ada',{delay:100}); await takeoverPage.keyboard.press('Enter'); await delay(800);
  await takeoverPage.locator('#finish').click();
  await poll(`/checkout/requests/${takeOver}/status.json`, ['returned']);
  snapshot = await browse({action:'snapshot'}); assert.equal(snapshot.url,merchant+'account'); assert.match(snapshot.text,/Signed in as ada/);
  await takeoverPage.close();
  checkpoint('approved take-over returns the logged-in page');

  // Keep Broker's production anonymous-ceremony admission limit intact.
  stage = 'waiting for ceremony quota';
  const remaining = Math.max(0, started+305000-Date.now());
  console.log(`Waiting ${Math.ceil(remaining/1000)}s for the four-ceremony admission window`);
  await delay(remaining);
  await browse({action:'open',url:merchant+'site'}); await delay(500);
  const site = id();
  await vfs('write',`/checkout/requests/${site}/in.json`,{agent_description:'Synthetic shop-saved payment'});
  await approve((await checkoutStatus(site)).ceremony_url,'site');
  await poll(`/checkout/requests/${site}/status.json`, ['paid']);
  await returnedToShopping(); assert.equal(fixtureSubmissions,1);
  checkpoint('shop-saved payment submits exactly once');
  const del = id();
  await vfs('write','/cards/delete.json',{operation_id:del,card_id:'stack-card'});
  await approve((await vfs('cat',`/cards/operations/${del}/ceremony.json`)).ceremony_url,'delete');
  await poll(`/cards/operations/${del}/status.json`, ['succeeded']);
  assert.deepEqual(await vfs('cat','/cards/index.json'), []);
  checkpoint('saved card deleted through custody ceremony');
  writeFileSync(output, JSON.stringify({result:'passed',checks,real_services:true,software_passkey:true,
    stripe_test_payment:true,live_funds:false,principal_isolation_tested:false},null,2));
} catch (error) {
  const message = String(error.message).replace(/https?:\/\/\S+/g,'[URL]').replaceAll('4242424242424242','[test card]');
  writeFileSync(output,JSON.stringify({result:'failed',stage,message,checks},null,2));
  console.error(`FAIL ${stage}: ${message}`); process.exitCode = 1;
} finally {
  await browser.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
  neighborServer.closeAllConnections(); await new Promise(resolve => neighborServer.close(resolve));
}
