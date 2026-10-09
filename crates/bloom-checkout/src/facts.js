(async () => {
  const visible = e => e.getClientRects().length && getComputedStyle(e).visibility === 'visible';
  const text = document.body.innerText;
  const controls = [...document.querySelectorAll('button,input[type=submit]')].filter(visible);
  const pay = controls.filter(e => /^(pay|buy|place order|complete (order|purchase)|subscribe|pagar|comprar)\b/i.test(e.innerText || e.value));
  if (pay.length !== 1) return null;
  const explicit = [...document.querySelectorAll('[data-bloom-total-minor][data-bloom-currency]')].filter(visible);
  let total, currency;
  let processorRecurring = null;
  if (location.origin === 'https://js.stripe.com' && location.pathname === '/v3/embedded-checkout-inner.html') {
    // Observed bootstrap: read facts without submitting card data or a payment.
    const url = new URL(location.href);
    const session = url.searchParams.get('checkoutSessionId');
    const key = url.searchParams.get('publishableKey');
    if (!/^cs_(test|live)_[A-Za-z0-9]+$/.test(session || '') || !/^pk_(test|live)_[A-Za-z0-9]+$/.test(key || '')) return null;
    const response = await fetch(`https://api.stripe.com/v1/payment_pages/${session}/init`, {
      method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:new URLSearchParams({key,browser_locale:navigator.language,browser_timezone:Intl.DateTimeFormat().resolvedOptions().timeZone}),
      signal:AbortSignal.timeout(5000)
    });
    if (!response.ok) return null;
    const page = await response.json();
    if (!['payment','subscription'].includes(page.mode)) return null;
    total = page.total_summary?.due; currency = page.currency?.toUpperCase();
    const displayed = document.querySelector('[data-testid="product-summary-total-amount"] .CurrencyAmount');
    if (!displayed || displayed.textContent.replace(/\D/g,'').replace(/^0+(?=\d)/,'') !== String(total)) return null;
    processorRecurring = page.mode === 'subscription';
  } else if (explicit.length === 1) {
    total = Number(explicit[0].dataset.bloomTotalMinor); currency = explicit[0].dataset.bloomCurrency;
  } else {
    const lines = text.split('\n').map(s => s.trim()).filter(Boolean);
    const amounts = [];
    for (let i = 0; i < lines.length; i++) {
      if (!/^(total|order total|amount due|total due)\b/i.test(lines[i])) continue;
      const nearby = lines.slice(i, i + 2).join(' ');
      const match = nearby.match(/\b(USD|CAD|EUR|GBP|BRL|MXN|ARS|CLP|COP|JPY)\s*[$€£R]*\s*([\d,]+(?:\.\d{1,2})?)\b/)
        || nearby.match(/[$€£R]*\s*([\d,]+(?:\.\d{1,2})?)\s*(USD|CAD|EUR|GBP|BRL|MXN|ARS|CLP|COP|JPY)\b/);
      if (!match) return null;
      const code = /^[A-Z]{3}$/.test(match[1]) ? match[1] : match[2];
      const amount = code === match[1] ? match[2] : match[1];
      const scale = new Intl.NumberFormat('en', {style:'currency',currency:code}).resolvedOptions().maximumFractionDigits;
      amounts.push({total:Math.round(Number(amount.replaceAll(',', '')) * 10 ** scale),currency:code});
    }
    if (amounts.length !== 1) return null;
    ({total,currency} = amounts[0]);
  }
  const selectors = [...document.querySelectorAll('select')].filter(e => visible(e) && /installment|cuotas|parcelas/i.test([e.name,e.id,e.labels?.[0]?.innerText].join(' ')));
  let installments = 1;
  if (selectors.length > 1) return null;
  if (selectors.length === 1) {
    const match = selectors[0].selectedOptions[0]?.text.match(/^(\d+)\s*(?:x|installments?|cuotas|parcelas)\b/i);
    if (!match) return null;
    installments = Number(match[1]);
  } else if (/installments?|cuotas|parcelas/i.test(text)) return null;
  const recurring = processorRecurring ?? /\b(subscription|recurring|auto.?renew|monthly|annually|suscripci[oó]n)\b/i.test(text);
  globalThis.__bloomPayButton = pay[0];
  return {origin:location.origin,payment_frame_origins:[],total_minor:total,currency,installments,recurring};
})()
