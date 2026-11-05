const screen = document.getElementById('screen');
const status = document.getElementById('status');
const pages = document.getElementById('pages');
let closed = false;
const sessionKey = 'bloom.checkout.session';
let session = '';
let frameUrl;
document.getElementById('controls').disabled = true;
function privateFetch(path, options = {}) {
  return fetch(path, {...options, credentials:'omit', headers:{...options.headers,Authorization:`Bearer ${session}`}});
}
function closeView(message) {
  closed = true;
  document.title = 'Private checkout closed · Bloom';
  document.getElementById('heading').textContent = 'Private checkout closed';
  status.textContent = message;
  document.getElementById('controls').hidden = true;
  document.getElementById('controls').disabled = true;
  document.getElementById('text').value = '';
  pages.replaceChildren();
  screen.hidden = true;
  screen.removeAttribute('src');
  if (frameUrl) { URL.revokeObjectURL(frameUrl); frameUrl = undefined; }
}
screen.hidden = true;
screen.addEventListener('load', () => { if (!closed) { screen.hidden = false; document.getElementById('controls').disabled = false; } });
screen.addEventListener('error', () => {
  if (closed) return;
  screen.hidden = true;
  document.getElementById('controls').disabled = true;
  status.textContent = 'Browser image unavailable. Wait for reconnection; do not repeat a payment.';
});
pages.addEventListener('change',()=>act({action:'select_page',target:pages.value}));
// One action at a time, so keystrokes arrive in order.
let queue = Promise.resolve();
function act(action) {
  queue = queue.then(async () => {
    if (closed) return;
    const response = await privateFetch('/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(action)});
    if (!response.ok) status.textContent = 'Action was not confirmed. Inspect the page before trying again.';
  }).catch(() => { if (!closed) status.textContent = 'Action was not confirmed. Inspect the page before trying again.'; });
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
  submitted: 'Payment sent once. Waiting for the site to confirm it; do not click Pay again. Finish any bank or email check here.',
  needs_input: 'The site needs attention. A form error does not prove no charge. Check the merchant and your bank before attempting payment again.',
  booked: 'The site confirmed the booking.' + (state.outcome?.order_id ? ` Booking code: ${state.outcome.order_id}.` : ' The booking code is in the confirmation email.'),
  paid: 'Done: the site confirmed the purchase.' + (state.outcome?.order_id ? ` Order code: ${state.outcome.order_id}.` : ''),
  declined: 'The payment was declined. Bloom will not try again.',
  uncertain: 'Bloom could not confirm the result. Do not pay again yet: check your email and bank or card app first.',
  manual_required: 'Finish the payment yourself in this window.',
}[state.state] || state.state.replaceAll('_', ' '));
async function refresh() {
  try {
    const response=await privateFetch('/state');
    if (!response.ok) {
      if (![401,403,410].includes(response.status)) throw Error('View temporarily unavailable');
      closeView('Return to Bloom for the recorded outcome. Closing this view does not prove whether a payment succeeded. Do not pay again until you have checked.');
      return;
    }
    const state=await response.json();status.textContent=describe(state);
    if(state.state==='human_control'){
      document.getElementById('heading').textContent="Bloom's browser";
      document.getElementById('purpose').textContent='Log in, enter a code or pass a check here. The agent cannot see this view. When you are done, hand the browser back.';
      document.getElementById('finish').textContent='Done, hand back to the agent';
      document.getElementById('note').hidden=true;
    }
    if(state.state==='needs_input') {
      document.getElementById('finish').textContent='Close without paying';
      document.getElementById('note').textContent='A form error does not prove no payment was sent. Check the merchant and your bank before paying again.';
      document.getElementById('note').hidden=false;
    }
    if(state.closed) {
      closeView(describe(state) + ' You can close this tab and return to Bloom.');
      return;
    }
    pages.replaceChildren(...state.pages.map(page=>{const option=document.createElement('option');option.value=page.target;option.textContent=page.origin;option.selected=page.target===state.selected_page;return option;}));
    const frame = await privateFetch('/frame');
    if (!frame.ok) throw Error('Browser image unavailable');
    if (frame.ok && !closed) {
      const previous = frameUrl;
      frameUrl = URL.createObjectURL(await frame.blob());
      screen.src = frameUrl;
      if (previous) URL.revokeObjectURL(previous);
    }
  } catch (_) {
    screen.hidden = true;
    document.getElementById('controls').disabled = true;
    status.textContent='Connection lost. Reconnecting; do not repeat a payment.';
  } finally { if (!closed) setTimeout(refresh,800); }
}
async function openView() {
  try {
    session = localStorage.getItem(sessionKey) || '';
    const bootstrap = new URLSearchParams(location.search).get('token');
    if (bootstrap) {
      const response = await privateFetch('/claim',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:bootstrap})});
      if (!response.ok) throw Error('Approval access unavailable');
      session = (await response.json()).session;
      localStorage.setItem(sessionKey,session);
      history.replaceState(null,'','/view');
    }
    if (!session) throw Error('Approval access unavailable');
    await refresh();
  } catch (_) {
    closeView('Private access is unavailable. Reopen the approval link in the browser you used to approve. Do not request another payment.');
  }
}
openView();
