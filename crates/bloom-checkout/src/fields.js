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
  const shopify = location.origin === 'https://checkout.pci.shopifyinc.com'
    && /^\/build\/[a-f0-9]{7,40}\/(number|name|expiry|verification_value|issue_date|issue_number)-ltr\.html$/.test(location.pathname);
  const shopifyId = shopify ? location.pathname.split('/').pop().replace('-ltr.html','') : null;
  const candidates = () => {
    const all = [...document.querySelectorAll('input')].filter(e => kind(e));
    if (!shopify) return all;
    // Shopify's named PCI frames include off-screen proxy inputs for the
    // other fields. Accept only the real field named by this frame's URL.
    const active = all.filter(e => {
      const r=e.getBoundingClientRect();return r.width>0 && r.height>0 && r.right>0 && r.bottom>0;
    });
    if (active.some(e => e.id !== shopifyId) || active.length > 1) return null;
    if (['issue_date','issue_number'].includes(shopifyId)) return active.length ? null : [];
    return active.length === 1 && active[0].getBoundingClientRect().width >= 16
      && active[0].getBoundingClientRect().height >= 16 ? active : null;
  };
  const visible = e => {
    if (!e.getClientRects().length || e.disabled || e.readOnly || e.type === 'hidden') return false;
    const rect=e.getBoundingClientRect();
    if (rect.width<=0 || rect.height<=0 || rect.right<=0 || rect.bottom<=0) return false;
    for (let node=e;node;node=node.parentElement) {
      const style=getComputedStyle(node);
      if (style.visibility !== 'visible' || style.display === 'none' || Number(style.opacity) === 0) return false;
    }
    return true;
  };
  const nodes = candidates();
  if (!nodes || nodes.some(e => !visible(e))) return null;
  const bindings = nodes.map(e => ({kind:kind(e),type:e.type,autocomplete:e.autocomplete,name:e.name,id:e.id}));
  globalThis.__bloomPaymentNodes = nodes;
  globalThis.__bloomPaymentValid = () => {
    const current = candidates();
    return current && current.length === nodes.length && nodes.every((e,i) => current[i] === e && e.isConnected && visible(e)
      && JSON.stringify({kind:kind(e),type:e.type,autocomplete:e.autocomplete,name:e.name,id:e.id}) === JSON.stringify(bindings[i]));
  };
  return bindings.map((b,index) => ({kind:b.kind,index}));
})()
