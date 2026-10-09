// Run against a fresh developer Triad launched with --checkout-fixture-tls.
// Only synthetic inputs. Never use this harness for a live-card ceremony.
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {spawnSync,spawn} from 'node:child_process';
import {mkdtempSync,readFileSync,writeFileSync,chmodSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createRequire} from 'node:module';
import https from 'node:https';
const require=createRequire(process.env.BLOOM_CHECKOUT_PLAYWRIGHT_ROOT ? resolve(process.env.BLOOM_CHECKOUT_PLAYWRIGHT_ROOT,'package.json') : import.meta.url);
const {chromium}=require('playwright-core');
const binary=process.env.BLOOM_BIN;
assert(binary,'Source the candidate triad.env');
const output=process.argv[2];assert(output,'Pass a public result JSON path');
const id=()=>randomBytes(32).toString('hex');
const transcript=[];
async function vfs(command,path,value) {
  const args=['--quiet','vfs',command,path];
  const child=spawn(binary,args,{stdio:['pipe','pipe','pipe'],timeout:45000});
  let stdout='';child.stdout.on('data',bytes=>stdout+=bytes);child.stderr.resume();
  child.stdin.end(value===undefined ? undefined : JSON.stringify(value));
  const status=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',resolve);});
  if(status!==0) throw new Error(`VFS ${command} ${path} failed`);
  if(command==='cat') {const result=JSON.parse(stdout);transcript.push({path,result});return result;}
}
const slot=id();
async function browse(request){await vfs('write',`/checkout/browse/${slot}/in.json`,request);return vfs('cat',`/checkout/browse/${slot}/out.json`);}
async function poll(path,states){for(let i=0;i<100;i++){const status=await vfs('cat',path);if(states.includes(status.state))return status;await new Promise(r=>setTimeout(r,200));}throw new Error('Operation did not reach expected state');}
const root=mkdtempSync(join(tmpdir(),'bloom-checkout-stack-'));chmodSync(root,0o700);
const cert=spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(root,'key.pem'),'-out',join(root,'cert.pem'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],{stdio:'ignore'});assert.equal(cert.status,0);
let submits=0;
const server=https.createServer({key:readFileSync(join(root,'key.pem')),cert:readFileSync(join(root,'cert.pem'))},(request,response)=>{
  response.setHeader('content-type','text/html');
  if(new URL(request.url,'https://localhost').pathname==='/manual'){response.end('<h1>Manual fixture</h1><p>Total is unavailable</p><button>Continue</button>');return;}
  if(new URL(request.url,'https://localhost').pathname==='/recover'){
    response.end('<h1>Recoverable fixture</h1><p data-bloom-total-minor="399" data-bloom-currency="USD">Total USD 3.99</p><form action="/done"><input autocomplete="cc-number"><input autocomplete="cc-exp"><input autocomplete="cc-csc"><input aria-label="Billing postal code" required><button type="submit">Pay</button></form>');return;
  }
  if(new URL(request.url,'https://localhost').pathname==='/done'){submits++;response.end('<h1>Order confirmed</h1><p>Order ID: FIXTURE-ONE</p><p>Total USD 3.99</p>');return;}
  response.end(`<!doctype html><h1>Digital fixture</h1><p data-bloom-total-minor="399" data-bloom-currency="USD">Total USD 3.99</p>
    <form action="/done"><input autocomplete="cc-number"><input autocomplete="cc-exp"><input autocomplete="cc-csc"><button type="submit">Pay</button></form>`);
});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const merchant=`https://localhost:${server.address().port}/`;
const browser=await chromium.launch({executablePath:process.env.BLOOM_CHECKOUT_TEST_CHROMIUM||'/usr/lib/chromium/chromium',headless:true,args:['--no-sandbox']});
const context=await browser.newContext();const page=await context.newPage();
const cdp=await context.newCDPSession(page);
await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',ctap2Version:'ctap2_1',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true,hasPrf:true}});
async function approve(url,kind) {
  await page.goto(url);await page.locator('#approve').waitFor();
  if(kind==='add'){
    await page.locator('#card-number').fill('4242424242424242');
    await page.locator('#card-month').fill('12');await page.locator('#card-year').fill('2034');
    await page.locator('#card-name').fill('Bloom Synthetic Cardholder');
  }
  if(kind==='checkout')await page.locator('#card-cvc').fill('937');
  await page.locator('#approve').click();
  try {await page.waitForFunction(()=>/Completed\.|Approved\.|Private view authorized/.test(document.getElementById('status').textContent),null,{timeout:20000});}
  catch (_) {throw new Error(`Ceremony ${kind}: ${await page.locator('#status').innerText()}`);}
}
async function returnedToShopping() {
  for(let i=0;i<50;i++) {
    try {const snapshot=await browse({action:'snapshot'});assert.equal(snapshot.url,'about:blank');return;}
    catch (_) {await new Promise(r=>setTimeout(r,100));}
  }
  throw new Error('Private pages did not close before shopping returned');
}
try {
  const add=id();await vfs('write','/cards/add.json',{operation_id:add,card_id:'stack-card',label:'Full-stack fixture'});
  await approve((await vfs('cat',`/cards/operations/${add}/ceremony.json`)).ceremony_url,'add');
  assert.equal((await poll(`/cards/operations/${add}/status.json`,['succeeded'])).state,'succeeded');
  const cards=await vfs('cat','/cards/index.json');assert.equal(cards.length,1);assert.deepEqual(Object.keys(cards[0]).sort(),['brand','card_id','label','last4']);
  // Unreadable facts authorize only a private human view. The same real
  // Broker JS/passkey path must not silently release the saved card.
  await browse({action:'open',url:merchant+'manual'});await new Promise(r=>setTimeout(r,400));
  const manual=id();await vfs('write',`/checkout/requests/${manual}/in.json`,{card_id:'stack-card',agent_description:'Unverified manual fixture'});
  const manualAwaiting=await vfs('cat',`/checkout/requests/${manual}/status.json`);
  const privatePagePromise=context.waitForEvent('page');
  await approve(manualAwaiting.ceremony_url,'manual');
  const privatePage=await privatePagePromise;
  const manualStatus=await poll(`/checkout/requests/${manual}/status.json`,['manual_required']);
  assert.deepEqual(manualStatus.filled_fields,[]);assert.equal(submits,0);
  await privatePage.locator('#finish').click();
  assert.equal((await poll(`/checkout/requests/${manual}/status.json`,['uncertain'])).state,'uncertain');
  await returnedToShopping();await privatePage.close();
  // Missing billing information prevents the one automated submission. A
  // human can finish in the private view; read-only outcome watching must
  // then report the merchant's confirmation without an automatic retry.
  await browse({action:'open',url:merchant+'recover'});await new Promise(r=>setTimeout(r,400));
  const recover=id();await vfs('write',`/checkout/requests/${recover}/in.json`,{card_id:'stack-card',agent_description:'Fixture missing billing information'});
  const recoveryPagePromise=context.waitForEvent('page');
  await approve((await vfs('cat',`/checkout/requests/${recover}/status.json`)).ceremony_url,'checkout');
  const recoveryPage=await recoveryPagePromise;
  const uncertain=await poll(`/checkout/requests/${recover}/status.json`,['uncertain']);
  assert.equal(uncertain.filled_fields.length,3);assert.equal(submits,0);
  await recoveryPage.locator('#screen').waitFor();
  async function privateAction(button) {
    const response=recoveryPage.waitForResponse(r=>new URL(r.url()).pathname==='/action');
    await button.click();assert.equal((await response).status(),200);
  }
  for(let i=0;i<4;i++)await privateAction(recoveryPage.getByRole('button',{name:'Tab',exact:true}));
  await recoveryPage.locator('#text').fill('12345');
  await privateAction(recoveryPage.getByRole('button',{name:'Send text',exact:true}));
  await privateAction(recoveryPage.getByRole('button',{name:'Tab',exact:true}));
  await privateAction(recoveryPage.getByRole('button',{name:'Enter',exact:true}));
  const recovered=await poll(`/checkout/requests/${recover}/status.json`,['paid']);
  assert.equal(recovered.outcome.source,'merchant-reported');assert.equal(submits,1);
  await returnedToShopping();await recoveryPage.close();
  await browse({action:'open',url:merchant});await new Promise(r=>setTimeout(r,400));await browse({action:'snapshot'});
  const checkout=id();await vfs('write',`/checkout/requests/${checkout}/in.json`,{card_id:'stack-card',agent_description:'One fixture digital item (unverified agent text)'});
  const awaiting=await vfs('cat',`/checkout/requests/${checkout}/status.json`);assert.equal(awaiting.state,'awaiting_approval');
  const blocked=spawnSync(binary,['--quiet','vfs','write',`/checkout/browse/${slot}/in.json`],{input:JSON.stringify({action:'snapshot'}),encoding:'utf8'});assert.notEqual(blocked.status,0);
  await approve(awaiting.ceremony_url,'checkout');
  const paid=await poll(`/checkout/requests/${checkout}/status.json`,['paid','declined','uncertain','manual_required','disclosure_unknown','partially_filled']);
  assert.equal(paid.state,'paid');assert.equal(paid.outcome.source,'merchant-reported');assert.equal(paid.outcome.merchant_reported_total_minor,399);assert.equal(submits,2);
  // The durable payment result precedes closing the private tabs. Observation
  // stays revoked during that cleanup; wait only for the fresh browsing tab.
  await returnedToShopping();
  const del=id();await vfs('write','/cards/delete.json',{operation_id:del,card_id:'stack-card'});
  await approve((await vfs('cat',`/cards/operations/${del}/ceremony.json`)).ceremony_url,'delete');
  await poll(`/cards/operations/${del}/status.json`,['succeeded']);assert.equal((await vfs('cat','/cards/index.json')).length,0);
  const encoded=JSON.stringify(transcript);assert(!encoded.includes('4242424242424242'));assert(!encoded.includes('Bloom Synthetic Cardholder'));assert(!encoded.includes('private?token='));assert(!/"cvc"\s*:\s*"?937/.test(encoded));
  writeFileSync(output,JSON.stringify({result:'passed',actual_broker_js:true,virtual_authenticator_prf:true,manual_fallback_without_release:true,user_completed_uncertain_checkout:true,submission_count:submits,transcript,retained_fixture_directory:root},null,2));
  console.log('Full-stack card add, approval, fill, single submission, merchant-reported result, fresh-tab return and delete passed.');
} finally {await browser.close();server.closeAllConnections();await new Promise(r=>server.close(r));}
