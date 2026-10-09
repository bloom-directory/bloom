const screen = document.getElementById('screen');
const status = document.getElementById('status');
async function act(action) {
  const response = await fetch('/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(action)});
  if (!response.ok) status.textContent = 'Action was not confirmed. Inspect the page before trying again.';
}
screen.addEventListener('click', event => {
  const rect = screen.getBoundingClientRect();
  act({action:'click',x:(event.clientX-rect.left)*screen.naturalWidth/rect.width,y:(event.clientY-rect.top)*screen.naturalHeight/rect.height});
});
document.getElementById('typing').addEventListener('submit', event => {
  event.preventDefault();const input = document.getElementById('text');const text=input.value;input.value='';act({action:'type',text});
});
document.querySelectorAll('[data-key]').forEach(button=>button.addEventListener('click',()=>act({action:'key',key:button.dataset.key})));
document.getElementById('finish').addEventListener('click',()=>act({action:'finish'}));
async function refresh() {
  try {
    const response=await fetch('/state');
    if (!response.ok) {status.textContent='Private checkout has closed. Return to Bloom for the outcome.';screen.removeAttribute('src');return;}
    const state=await response.json();status.textContent=state.state.replaceAll('_',' ');
    screen.src='/frame?refresh='+Date.now();
    setTimeout(refresh,800);
  } catch (_) {status.textContent='Connection lost. Check Bloom status; do not repeat a payment.';}
}
refresh();
