(() => {
  const secret = BLOOM_CARD_SECRET;
  const kind = e => {
    // Some sites caption a field with text beside it instead of a <label>.
    let caption = '';
    for (let a = e.parentElement, depth = 0; a && depth < 4; a = a.parentElement, depth++) {
      if (a.querySelectorAll('input,select').length > 1) break;
      const t = (a.innerText || '').trim();
      if (t) { if (t.length <= 60) caption = t; break; }
    }
    const label = [e.name,e.id,e.getAttribute('aria-label'),e.placeholder,e.labels?.[0]?.innerText,caption].filter(Boolean).join(' ')
      .normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
    // Contact fields are never card fields, whatever their markup says
    // (JetSMART marks its confirm-email box autocomplete=cc-csc).
    if (/e-?mail|correo|telefono|phone/.test(label)) return null;
    const autocomplete = e.autocomplete?.toLowerCase().split(' ').pop();
    const direct = {'cc-number':'number','cc-exp':'expiry','cc-exp-month':'month','cc-exp-year':'year','cc-csc':'cvc','cc-name':'name'};
    if (direct[autocomplete]) return direct[autocomplete];
    if (secret(e, label) && /card.?number|cardnumber|numero de (la )?tarjeta|nro\.? de tarjeta/.test(label)) return 'number';
    if (secret(e, label) && /cvc|cvv|security.?code|codigo de seguridad/.test(label)) return 'cvc';
    // Jettzy's reviewed inline form names these selects rather than labelling
    // each expiry part. Keep the aliases on the reviewed receiving origins.
    if (['https://en.jettzy.com.hk','https://www.jettzy.com.my','https://www.jettzy.com.vn'].includes(location.origin) && e instanceof HTMLSelectElement) {
      if ([e.name,e.id].includes('validity_begin')) return 'month';
      if ([e.name,e.id].includes('validity_end')) return 'year';
    }
    if (/expir.*month|month.*expir|vencimiento.*mes|mes.*vencimiento|^mes$/.test(label)) return 'month';
    if (/expir.*year|year.*expir|vencimiento.*ano|ano.*vencimiento|^ano$/.test(label)) return 'year';
    if (/expir|mm.?\/.?(yy|aa)|vencimiento|fecha de expiracion/.test(label)) return 'expiry';
    if (/cardholder|name.?on.?card|titular|nombre (impreso|como figura|en la tarjeta)/.test(label)) return 'name';
    return null;
  };
  const shopify = location.origin === 'https://checkout.pci.shopifyinc.com'
    && /^\/build\/[a-f0-9]{7,40}\/(number|name|expiry|verification_value|issue_date|issue_number)-ltr\.html$/.test(location.pathname);
  const shopifyId = shopify ? location.pathname.split('/').pop().replace('-ltr.html','') : null;
  const candidates = () => {
    // A read-only or disabled box takes no typing, so it is never a card field
    // (JetSMART shows one captioned like a security code beside its frames).
    const all = [...document.querySelectorAll('input,select')].filter(e => !e.readOnly && !e.disabled && kind(e));
    // Inactive alternative forms are not receivers. Revalidation below also
    // detects an alternative becoming visible after approval.
    if (!shopify) return all.filter(visible);
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
