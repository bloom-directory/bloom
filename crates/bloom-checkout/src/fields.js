(() => {
  const kind = e => {
    const autocomplete = e.autocomplete?.toLowerCase().split(' ').pop();
    const direct = {'cc-number':'number','cc-exp':'expiry','cc-exp-month':'month','cc-exp-year':'year','cc-csc':'cvc','cc-name':'name'};
    if (direct[autocomplete]) return direct[autocomplete];
    const label = [e.name,e.id,e.getAttribute('aria-label'),e.placeholder,e.labels?.[0]?.innerText].filter(Boolean).join(' ').toLowerCase();
    if (/card.?number|cardnumber/.test(label)) return 'number';
    if (/cvc|cvv|security.?code/.test(label)) return 'cvc';
    if (/expir.*month/.test(label)) return 'month';
    if (/expir.*year/.test(label)) return 'year';
    if (/expir|mm.?\/.?yy/.test(label)) return 'expiry';
    if (/cardholder|name.?on.?card/.test(label)) return 'name';
    return null;
  };
  const candidates = () => [...document.querySelectorAll('input')].filter(e => kind(e));
  const visible = e => {
    if (!e.getClientRects().length || e.disabled || e.readOnly || e.type === 'hidden') return false;
    for (let node=e;node;node=node.parentElement) {
      const style=getComputedStyle(node);
      if (style.visibility !== 'visible' || style.display === 'none' || Number(style.opacity) === 0) return false;
    }
    return true;
  };
  const nodes = candidates();
  if (nodes.some(e => !visible(e))) return null;
  const bindings = nodes.map(e => ({kind:kind(e),type:e.type,autocomplete:e.autocomplete,name:e.name,id:e.id}));
  globalThis.__bloomPaymentNodes = nodes;
  globalThis.__bloomPaymentValid = () => {
    const current = candidates();
    return current.length === nodes.length && nodes.every((e,i) => current[i] === e && e.isConnected && visible(e)
      && JSON.stringify({kind:kind(e),type:e.type,autocomplete:e.autocomplete,name:e.name,id:e.id}) === JSON.stringify(bindings[i]));
  };
  return bindings.map((b,index) => ({kind:b.kind,index}));
})()
