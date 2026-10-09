const screen = document.getElementById('screen');
const status = document.getElementById('status');
const pages = document.getElementById('pages');
pages.addEventListener('change',()=>act({action:'select_page',target:pages.value}));
async function act(action) {
  const response = await fetch('/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(action)});
  if (!response.ok) status.textContent = 'Action was not confirmed. Inspect the page before trying again.';
}
screen.addEventListener('click', event => {
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
async function refresh() {
  try {
    const response=await fetch('/state');
    if (!response.ok) {status.textContent='Private checkout has closed. Return to Bloom for the outcome.';screen.removeAttribute('src');return;}
    const state=await response.json();status.textContent=state.state.replaceAll('_',' ');
    if(state.closed) {status.textContent += ' (merchant-reported when paid or declined)';screen.removeAttribute('src');return;}
    pages.replaceChildren(...state.pages.map(page=>{const option=document.createElement('option');option.value=page.target;option.textContent=page.origin;option.selected=page.target===state.selected_page;return option;}));
    screen.src='/frame?refresh='+Date.now();
    setTimeout(refresh,800);
  } catch (_) {status.textContent='Connection lost. Check Bloom status; do not repeat a payment.';}
}
refresh();
