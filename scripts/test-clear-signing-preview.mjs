// Requires playwright-core and an installed Chromium; no live ceremony connection.
const {chromium}=await import(process.env.PLAYWRIGHT_MODULE ?? 'playwright-core');
import fs from 'node:fs';
if(!process.env.BLOOM_BROKER_ROOT || !process.env.BLOOM_UI_FIXTURE_DIR) throw Error('Set BLOOM_BROKER_ROOT and BLOOM_UI_FIXTURE_DIR');
const assets=`${process.env.BLOOM_BROKER_ROOT}/crates/bloom-broker/src/ceremony_assets`;
const out=process.env.BLOOM_UI_FIXTURE_DIR;
const html=fs.readFileSync(`${assets}/index.html`,'utf8').replace(/<link[^>]*>/g,'').replace('<script src="/assets/app.js"></script>','');
const css=fs.readFileSync(`${assets}/style.css`,'utf8');
const js=fs.readFileSync(`${assets}/token-artwork.js`,'utf8')+'\n'+fs.readFileSync(`${assets}/app.js`,'utf8').split('\nload().catch')[0];
const browser=await chromium.launch({executablePath:process.env.CHROMIUM_BIN ?? '/usr/bin/chromium',headless:true,args:['--no-sandbox']});
const page=await browser.newPage();
const errors=[]; page.on('pageerror',e=>errors.push(e.message));
await page.route('**/assets/**',route=>{
 const name=new URL(route.request().url()).pathname.slice('/assets/'.length);
 const path=name.endsWith('.png')?`${assets}/tokens/generated/${name.split('/').at(-1)}`:`${assets}/${name}`;
 return route.fulfill({status:fs.existsSync(path)?200:404,contentType:name.endsWith('.png')?'image/png':name.endsWith('.svg')?'image/svg+xml':'text/plain',body:fs.existsSync(path)?fs.readFileSync(path):''});
});
await page.route('http://bloom-preview.local/preview/**',route=>route.fulfill({contentType:'text/html',body:html.replace('</head>',`<style>${css}</style></head>`)}));
await page.goto('http://bloom-preview.local/preview/enso'); await page.addScriptTag({content:js});
const call=JSON.parse(fs.readFileSync(`${out}/enso-shortcut.json`));
const results=[];
for(const width of [1280,390]) {
 await page.setViewportSize({width,height:1000});
 await page.evaluate(call=>renderReview(previewApproval([previewPayload({chain_id:'8453',chain:'base',destination:call.contract,contract_call:call})],previewClearSigning('8453',call.contract))),call);
 const visible=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth,text:document.querySelector('#ceremony-panel').innerText}));
 for(const expected of ['Encoded command 1','2.5 USDC','Encoded command 2','runtime']) if(!visible.text.includes(expected)) throw Error('Missing primary '+expected);
 if(visible.overflow)throw Error('Primary overflow');
 await page.screenshot({path:`${out}/enso-shortcut-${width}.png`,fullPage:true});
 await page.evaluate(()=>document.querySelectorAll('details').forEach(d=>d.open=true));
 if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw Error('Expanded overflow');
 results.push({width,primarySummaries:true,overflow:false});
}
if(errors.length)throw Error(JSON.stringify(errors));
fs.writeFileSync(`${out}/results.json`,JSON.stringify({results,errors},null,2));
console.log(JSON.stringify({results,errors})); await browser.close();
