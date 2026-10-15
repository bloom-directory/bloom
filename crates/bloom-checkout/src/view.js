const screen = document.getElementById('screen');
const status = document.getElementById('status');
const pages = document.getElementById('pages');
screen.hidden = true;
screen.addEventListener('load', () => { screen.hidden = false; });
screen.addEventListener('error', () => {
  screen.hidden = true;
  status.textContent = 'Browser image unavailable. Wait for reconnection; do not repeat a payment.';
});
pages.addEventListener('change',()=>act({action:'select_page',target:pages.value}));
// One action at a time, so keystrokes arrive in order.
let queue = Promise.resolve();
function act(action) {
  queue = queue.then(async () => {
    const response = await fetch('/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(action)});
    if (!response.ok) status.textContent = 'Action was not confirmed. Inspect the page before trying again.';
  }).catch(() => {});
}
// Typing straight onto the screen goes to the page's focused field.
const keys = new Set(['Tab','Enter','Backspace','Escape','ArrowDown','ArrowUp']);
screen.addEventListener('keydown', event => {
  if (event.ctrlKey || event.metaKey || event.altKey) return;
  if (keys.has(event.key)) act({action:'key',key:event.key});
  else if (event.key.length === 1) act({action:'type',text:event.key});
  else return;
  event.preventDefault();
});
document.addEventListener('paste', event => {
  if (document.activeElement !== screen) return;
  event.preventDefault();const text=event.clipboardData.getData('text');if(text)act({action:'type',text});
});
screen.addEventListener('click', event => {
  screen.focus();
  const rect = screen.getBoundingClientRect();
  act({action:'click',x:(event.clientX-rect.left)*screen.naturalWidth/rect.width,y:(event.clientY-rect.top)*screen.naturalHeight/rect.height});
});
screen.addEventListener('wheel', event => {
  event.preventDefault();const rect=screen.getBoundingClientRect();
  act({action:'scroll',x:(event.clientX-rect.left)*screen.naturalWidth/rect.width,y:(event.clientY-rect.top)*screen.naturalHeight/rect.height,delta_y:Math.max(-3000,Math.min(3000,event.deltaY))});
},{passive:false});
document.getElementById('typing').addEventListener('submit', event => {
  event.preventDefault();const input = document.getElementById('text');const text=input.value;input.value='';act({action:'type',text});
});
document.querySelectorAll('[data-key]').forEach(button=>button.addEventListener('click',()=>act({action:'key',key:button.dataset.key})));
document.getElementById('finish').addEventListener('click',()=>act({action:'finish'}));
// What each state means for the person watching, in plain words.
const describe = state => ({
  submitted: 'Payment sent. Waiting for the site to confirm it. Keep this window open.',
  needs_attention: 'The site needs something from you before the payment completes. Check what the page highlights or asks to confirm, then press its button.',
  paid: 'Done: the site confirmed the purchase.' + (state.outcome?.order_id ? ` Booking or order code: ${state.outcome.order_id}.` : ''),
  declined: 'The payment was declined. Bloom will not try again.',
  uncertain: 'Bloom could not confirm the result. Do not pay again yet: check your email and bank or card app first.',
  manual_required: 'Finish the payment yourself in this window.',
}[state.state] || state.state.replaceAll('_', ' '));
async function refresh() {
  try {
    const response=await fetch('/state');
    if (!response.ok) {status.textContent='Private checkout has closed. Return to Bloom for the outcome.';screen.hidden=true;screen.removeAttribute('src');return;}
    const state=await response.json();status.textContent=describe(state);
    if(state.state==='human_control'){
      document.getElementById('heading').textContent="Bloom's browser";
      document.getElementById('purpose').textContent='Log in, enter a code or pass a check here. The agent cannot see this view. When you are done, hand the browser back.';
      document.getElementById('finish').textContent='Done, hand back to the agent';
      document.getElementById('note').hidden=true;
    }
    if(state.closed) {
      status.textContent=describe(state);
      screen.hidden=true;screen.removeAttribute('src');return;
    }
    pages.replaceChildren(...state.pages.map(page=>{const option=document.createElement('option');option.value=page.target;option.textContent=page.origin;option.selected=page.target===state.selected_page;return option;}));
    screen.src='/frame?refresh='+Date.now();
    setTimeout(refresh,800);
  } catch (_) {status.textContent='Connection lost. Check Bloom status; do not repeat a payment.';}
}
refresh();
