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
function stateText(state) {
  if (state.state === 'booked') {
    const code = state.outcome?.order_id;
    return code ? `Booked — reservation code ${code}` : 'Booked — check your confirmation email for the reservation code.';
  }
  if (state.state === 'paid') return 'Payment confirmed by the merchant.';
  if (state.state === 'declined') return 'Payment declined by the merchant or bank.';
  if (state.state === 'needs_input') return state.traveler
    ? 'Payment approval has not started. Complete the highlighted booking fields.'
    : 'Payment was not submitted. Complete the highlighted fields, then click Pay once.';
  if (state.state === 'not_submitted') return 'Payment was not submitted.';
  if (state.state === 'submitted') return 'Payment sent once. Waiting for the merchant confirmation; do not click Pay again.';
  if (state.state === 'uncertain') return 'Bloom cannot confirm the result. Check the airline email and your bank; do not pay again.';
  return state.state.replaceAll('_',' ');
}
async function refresh() {
  try {
    const response=await fetch('/state');
    if (!response.ok) {status.textContent='Private checkout has closed. Return to Bloom for the outcome.';screen.hidden=true;screen.removeAttribute('src');return;}
    const state=await response.json();status.textContent=stateText(state);
    if(state.state==='human_control'){
      document.getElementById('heading').textContent="Bloom's browser";
      document.getElementById('purpose').textContent='Log in, enter a code or pass a check here. The agent cannot see this view. When you are done, hand the browser back.';
      document.getElementById('finish').textContent='Done, hand back to the agent';
      document.getElementById('note').hidden=true;
    }
    if(state.traveler) {
      document.getElementById('heading').textContent='Private traveler autofill';
      document.getElementById('purpose').textContent='Saved details are filled privately. Complete any unsupported fields, continue to payment, then click Ready. Payment still needs a separate approval.';
      document.getElementById('finish').textContent='Ready for payment approval';
      document.getElementById('note').hidden=true;
    }
    if(state.state==='needs_input' && state.traveler) {
      document.getElementById('heading').textContent='Fix the booking details';
      document.getElementById('purpose').textContent='Correct the highlighted fields, then click Ready for payment approval. Do not click Pay on the airline page; no card has been approved yet.';
      document.getElementById('finish').textContent='Ready for payment approval';
      document.getElementById('note').textContent='Payment still requires a separate approval.';
      document.getElementById('note').hidden=false;
    } else if(state.state==='needs_input') {
      document.getElementById('heading').textContent='Finish the payment form';
      document.getElementById('purpose').textContent='The page rejected one or more fields before charging. Correct the highlighted fields here, then click Pay once. The agent cannot see this view.';
      document.getElementById('finish').textContent='Close without paying';
      document.getElementById('note').textContent='Closing now records that Bloom did not submit payment.';
      document.getElementById('note').hidden=false;
    } else if(state.state==='submitted') {
      document.getElementById('purpose').textContent='Bloom clicked Pay once. Complete any bank or email verification here and wait for the booking result.';
      document.getElementById('finish').textContent='Close and verify separately';
    }
    if(state.closed) {
      status.textContent=state.state==='ready_for_payment' ? 'Ready for payment approval. Traveler details remain hidden from the agent.' : stateText(state);
      screen.hidden=true;screen.removeAttribute('src');return;
    }
    pages.replaceChildren(...state.pages.map(page=>{const option=document.createElement('option');option.value=page.target;option.textContent=page.origin;option.selected=page.target===state.selected_page;return option;}));
    screen.src='/frame?refresh='+Date.now();
    setTimeout(refresh,800);
  } catch (_) {status.textContent='Connection lost. Check Bloom status; do not repeat a payment.';}
}
refresh();
