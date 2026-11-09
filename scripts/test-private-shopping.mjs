// Run against a fresh, isolated four-service developer installation.
// All identities, travelers, cards, merchants and charges here are synthetic.
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {spawn, spawnSync} from 'node:child_process';
import {mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {createRequire} from 'node:module';
import https from 'node:https';

const binary = process.env.BLOOM_BIN;
const home = process.env.BLOOM_HOME;
const endpoint = process.env.BLOOM_RPC_ENDPOINT;
const ceremony = process.env.BLOOM_CHECKOUT_CEREMONY_ORIGIN;
const view = process.env.BLOOM_CHECKOUT_VIEW_ORIGIN;
const output = process.argv[2];
assert(binary && home && endpoint && ceremony && view && output);
assert(endpoint.startsWith('unix:'));
assert.equal(new URL(ceremony).hostname, 'localhost');
assert.notEqual(new URL(ceremony).port, '18734');
const require = createRequire(resolve(process.env.BLOOM_CHECKOUT_PLAYWRIGHT_ROOT || '.', 'package.json'));
const {chromium} = require('playwright-core');
const id = () => randomBytes(32).toString('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const checks = [];
const checkpoint = name => {
  checks.push(name);
  writeFileSync(output, JSON.stringify({result:'running', checks}, null, 2));
  console.log('PASS '+name);
};
async function vfs(command, path, value) {
  const child = spawn(binary, ['--quiet','--home',home,'--connect',endpoint,'vfs',command,path],
    {stdio:['pipe','pipe','pipe'],timeout:60000});
  let stdout = '', stderr = '';
  child.stdout.on('data', b => stdout += b);
  child.stderr.on('data', b => stderr = (stderr+b).slice(-1000));
  child.stdin.end(value === undefined ? undefined : JSON.stringify(value));
  const code = await new Promise((resolve,reject) => {child.once('error',reject);child.once('close',resolve);});
  assert.equal(code,0,`VFS ${command} ${path}: ${stderr}`);
  for (const secret of ['4242424242424242','SyntheticAlice','SyntheticTraveler']) assert(!stdout.includes(secret));
  return command === 'cat' ? JSON.parse(stdout) : undefined;
}
async function poll(read, predicate, label) {
  let value;
  for (let i=0;i<150;i++) {
    value = await read();
    if (predicate(value)) return value;
    await delay(200);
  }
  throw Error('Timed out: '+label);
}
const slot = id();
async function browse(request) {
  await vfs('write',`/checkout/browse/${slot}/in.json`,request);
  return vfs('cat',`/checkout/browse/${slot}/out.json`);
}
const root = mkdtempSync(join(tmpdir(),'bloom-private-shopping-'));
assert.equal(spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes',
  '-keyout',join(root,'key.pem'),'-out',join(root,'cert.pem'),'-days','1',
  '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],{stdio:'ignore'}).status,0);
const tls = {key:readFileSync(join(root,'key.pem')),cert:readFileSync(join(root,'cert.pem'))};
let charges = 0;
let filled = false;
const bank = https.createServer(tls, (_request,response) => response.end(
  '<button style="position:absolute;left:20px;top:20px;width:300px;height:60px" onclick="opener.postMessage(\'bank-confirmed\',\'*\');window.close()">Confirm synthetic bank check</button>'));
await new Promise(resolve => bank.listen(0,'127.0.0.1',resolve));
const bankOrigin = `https://localhost:${bank.address().port}`;
const merchant = https.createServer(tls, (request,response) => {
  const url = new URL(request.url,'https://localhost');
  response.setHeader('content-type','text/html');
  if (url.pathname === '/search') response.end(`<button style="position:absolute;left:20px;top:20px;width:300px;height:60px"
    onclick="sessionStorage.itinerary='FLIGHT-ONE';document.cookie='cart=FLIGHT-ONE;SameSite=Strict';location.href='/seller?uncertain=${url.searchParams.get('uncertain') === '1' ? '1' : '0'}'">Choose flight</button>`);
  else if (url.pathname === '/seller') {
    if (!(request.headers.cookie || '').includes('cart=FLIGHT-ONE')) {response.statusCode=409;response.end('Cart lost');return;}
    response.end(`<h1>FLIGHT-ONE · Synthetic airline</h1><p>Total USD 3.99</p>
      <form onsubmit="event.preventDefault();if(sessionStorage.itinerary!=='FLIGHT-ONE')throw Error('lost itinerary');
        fetch('/charge',{method:'POST',body:JSON.stringify(Object.fromEntries(new FormData(this)))}).then(()=>{
          document.body.innerHTML='<h1>Finish bank verification</h1>';
          ${url.searchParams.get('uncertain') === '1' ? '' : `window.open('${bankOrigin}/','bank')`}
        })">
      <label>First name<input name="given" autocomplete="given-name"></label>
      <label>Last name<input name="family" autocomplete="family-name"></label>
      <label>Cardholder<input name="holder" autocomplete="cc-name"></label>
      <label>Card number<input name="card" autocomplete="cc-number"></label>
      <label>Expiry<input name="expiry" autocomplete="cc-exp"></label>
      <label>CVC<input name="cvc" autocomplete="cc-csc"></label><button>Pay USD 3.99</button></form>
      <script>addEventListener('message',e=>{if(e.origin===${JSON.stringify(bankOrigin)}&&e.data==='bank-confirmed'){
        document.body.innerHTML='<h1>Order confirmed</h1><p>Order ID: FLIGHT-ONE</p>';}});</script>`);
  } else if (url.pathname === '/charge') {
    let bytes = '';
    request.on('data', b => bytes += b);
    request.on('end', () => {
      const data = JSON.parse(bytes);
      filled = data.given === 'SyntheticAlice' && data.family === 'SyntheticTraveler' && data.card.replaceAll(' ','') === '4242424242424242';
      charges++;
      response.end('accepted');
    });
  } else {response.statusCode=404;response.end('missing');}
});
await new Promise(resolve => merchant.listen(0,'127.0.0.1',resolve));
const merchantOrigin = `https://localhost:${merchant.address().port}`;
const browser = await chromium.launch({executablePath:process.env.BLOOM_CHECKOUT_TEST_CHROMIUM || '/usr/bin/chromium',headless:true,args:['--no-sandbox']});
const context = await browser.newContext();
const auth = await context.newPage();
const cdp = await context.newCDPSession(auth);
await cdp.send('WebAuthn.enable');
await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',ctap2Version:'ctap2_1',transport:'internal',
  hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true,hasPrf:true}});
async function approve(url, kind, cancel = false) {
  assert.equal(new URL(url).origin,ceremony);
  await auth.goto(url);
  await auth.locator('#approve').waitFor();
  if (cancel) {await auth.locator('#cancel').click();return;}
  if (kind === 'add') {
    await auth.locator('#card-number').fill('4242424242424242');
    await auth.locator('#card-expiry').fill('12/34');
    await auth.locator('#card-name').fill('Synthetic cardholder');
  }
  if (kind === 'traveler') {
    await auth.locator('#traveler-given_name').fill('SyntheticAlice');
    await auth.locator('#traveler-family_name').fill('SyntheticTraveler');
  }
  if (kind === 'card') await auth.locator('#card-cvc').fill('937');
  await auth.locator('#approve').click();
  await auth.waitForFunction(() => /Approved\.|saved( privately)?\.|browser is yours/.test(document.getElementById('status').textContent),null,{timeout:30000});
}
async function privateClick(page,x,y) {
  await page.locator('#screen').waitFor({state:'visible'});
  const point = await page.locator('#screen').evaluate((image,{x,y}) => ({
    x:x*image.clientWidth/image.naturalWidth,y:y*image.clientHeight/image.naturalHeight}),{x,y});
  await page.locator('#screen').click({position:point});
}
async function privateState(page) {
  return page.evaluate(async () => (await fetch('/state',{headers:{Authorization:'Bearer '+localStorage.getItem('bloom.checkout.session')}})).json());
}
async function startJourney(uncertain) {
  await browse({action:'open',url:merchantOrigin+'/search?uncertain='+(uncertain?'1':'0')});
  await delay(500);
  const operation = id();
  await vfs('write',`/checkout/requests/${operation}/in.json`,{take_over:true,agent_description:'Select synthetic flight and use saved details. No real purchase.'});
  const prepared = await vfs('cat',`/checkout/requests/${operation}/status.json`);
  const opened = context.waitForEvent('page');
  await approve(prepared.ceremony_url,'takeover');
  const page = await opened;
  await page.waitForURL(view+'/view');
  await privateClick(page,70,45);
  await delay(700);
  return page;
}
async function fillTraveler(page) {
  await page.locator('#saved-traveler').selectOption('synthetic');
  await page.locator('#fill-traveler').click();
  await page.locator('#saved-approval').waitFor({state:'visible'});
  const link = await page.locator('#saved-approval').getAttribute('href');
  await approve(link,'fill');
  await poll(()=>privateState(page),s=>s.saved?.status?.state==='traveler_filled','traveler fill');
}
// The fixture's card fields sit on the seller page, not in a known payment
// provider's frame, so Checkout must refuse to release a saved card there.
// Saved-card payment into a provider frame is covered by test-card-checkout.mjs.
async function payRefused(page) {
  await page.locator('#saved-card').selectOption('synthetic');
  await page.locator('#unpaid-checked').check();
  await page.locator('#pay-saved').click();
  await page.waitForFunction(() => /not from a known payment provider/.test(document.getElementById('saved-status').textContent),null,{timeout:30000});
  // The reason must survive the view's status refresh.
  await delay(3000);
  assert.match(await page.locator('#saved-status').textContent(), /not from a known payment provider/);
  assert(await page.locator('#saved-approval').isHidden());
  assert.equal((await privateState(page)).closed,false);
}
try {
  assert.deepEqual(await vfs('cat','/cards/index.json'),[]);
  assert.deepEqual(await vfs('cat','/travelers/index.json'),[]);
  for (const [route,kind,record] of [['cards','add',{card_id:'synthetic'}],['travelers','traveler',{traveler_id:'synthetic'}]]) {
    const operation=id();
    await vfs('write',`/${route}/${route==='cards'?'add':'save'}.json`,{operation_id:operation,...record,label:'Synthetic fixture'});
    await approve((await vfs('cat',`/${route}/operations/${operation}/ceremony.json`)).ceremony_url,kind);
  }
  checkpoint('saved records enrolled through real passkey ceremonies');
  let page = await startJourney(false);
  await fillTraveler(page);
  checkpoint('private seller selection and saved traveler fill preserve itinerary');
  await payRefused(page);
  assert.equal(charges,0);
  checkpoint('saved card is never released into card fields outside a payment provider frame');
  writeFileSync(output,JSON.stringify({result:'passed',checks,syntheticCharges:charges},null,2));
} catch (error) {
  writeFileSync(output,JSON.stringify({result:'failed',checks,error:error.message},null,2));
  throw error;
} finally {
  await browser.close();
  merchant.close();bank.close();
}
