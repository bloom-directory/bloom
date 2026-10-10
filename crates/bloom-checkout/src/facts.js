(async () => {
  // Read the one amount labelled as the total. Labels and number formats cover
  // the main European and American checkout languages; anything unclear
  // returns null so the human finishes in the private view.
  const isoCodes = new Set(Intl.supportedValuesOf('currency'));
  const symbols = [['US$','USD'],['U$S','USD'],['USD$','USD'],['R$','BRL'],['CA$','CAD'],['C$','CAD'],['MX$','MXN'],['AR$','ARS'],
    ['CLP$','CLP'],['COL$','COP'],['$U','UYU'],['S/.','PEN'],['S/','PEN'],['SFr.','CHF'],['Fr.','CHF'],['zł','PLN'],['€','EUR'],['£','GBP'],['$','$']];
  const dollars = new Set(['USD','CAD','MXN','ARS','CLP','COP','UYU','AUD','NZD','SGD','HKD']);
  const currencyToken = /US\$|U\$S|USD\$|R\$|CA\$|C\$|MX\$|AR\$|CLP\$|COL\$|\$U|S\/\.?|SFr\.|Fr\.|zł|[€£$]|\b[A-Z]{3}\b/gu;
  const label = /^(montant à payer|importo totale|total a pagar|total à payer|importe total|montant total|total amount|total to pay|gesamtbetrag|totaalbedrag|grand total|order total|monto total|valor total|gesamtsumme|gesamtpreis|amount due|te betalen|do zapłaty|total due|total ttc|endbetrag|zu zahlen|totale|gesamt|totaal|total|summe|razem|suma)(?![\p{L}\p{N}])/iu;
  // An amount line holds only currency marks, digits, separators and spacing.
  const amountOnly = line => !/\p{L}/u.test(line.replace(/\([^)]*\)/g, '').replace(currencyToken, ''));
  const declared = () => {
    const codes = new Set([...document.querySelectorAll('[itemprop=priceCurrency],meta[property="og:price:currency"],meta[property="product:price:currency"]')]
      .map(e => (e.getAttribute('content') || e.textContent).trim().toUpperCase()));
    for (const script of document.querySelectorAll('script[type="application/ld+json"]')) {
      for (const match of script.textContent.matchAll(/"priceCurrency"\s*:\s*"([A-Za-z]{3})"/g)) codes.add(match[1].toUpperCase());
    }
    return codes.size === 1 ? [...codes][0] : null;
  };
  const dollarCurrency = () => {
    const page = declared();
    if (page) return page;
    // A bare "$" otherwise follows the page language's region (es-AR, en-US, ...).
    const region = (document.documentElement.lang || '').split('-')[1]?.toUpperCase();
    return {US:'USD',CA:'CAD',MX:'MXN',AR:'ARS',CL:'CLP',CO:'COP',UY:'UYU'}[region] || null;
  };
  const minorUnits = (number, code) => {
    if (!isoCodes.has(code)) return null;
    const scale = new Intl.NumberFormat('en', {style:'currency',currency:code}).resolvedOptions().maximumFractionDigits;
    let whole = number, fraction = '';
    const last = number.search(/[.,][^.,]*$/);
    const tail = last >= 0 ? number.slice(last + 1) : '';
    // A final '.' or ',' followed by 1..scale digits is decimal; three digits
    // are always grouping for currencies with fewer than three decimals.
    if (last >= 0 && /^\d+$/.test(tail) && tail.length <= scale && tail.length !== 3) {
      whole = number.slice(0, last); fraction = tail;
    } else if (scale >= 3 && last >= 0) return null;
    const grouping = [...new Set(whole.replace(/\d/g, ''))];
    if (grouping.length > 1 || (fraction && grouping[0] === number[last])) return null;
    if (grouping.length === 1 && !new RegExp(`^\\d{1,3}(?:[${grouping[0]}]\\d{3})+$`).test(whole)) return null;
    const minor = Number(whole.replace(/\D/g, '')) * 10 ** scale + Number(fraction.padEnd(scale, '0') || 0);
    return Number.isSafeInteger(minor) && minor > 0 ? minor : null;
  };
  const parseAmount = segment => {
    segment = segment.replace(/(\d)[.,][–-]+/g, '$1');
    const numbers = segment.match(/\d{1,3}(?:[.,'’\u00a0\u202f ]\d{3})+(?:[.,]\d+)?|\d+(?:[.,]\d+)?/g) || [];
    if (numbers.length !== 1) return null;
    const marks = [...segment.matchAll(currencyToken)].map(m => m[0]);
    const codes = new Set(marks.map(mark => symbols.find(([symbol]) => symbol === mark)?.[1] ?? (isoCodes.has(mark) ? mark : null)));
    codes.delete(null);
    const iso = [...codes].filter(code => code !== '$');
    if (iso.length > 1 || (codes.has('$') && iso.length && !dollars.has(iso[0]))) return null;
    const currency = iso[0] || (codes.has('$') ? dollarCurrency() : null);
    if (!currency) return null;
    const total = minorUnits(numbers[0].replace(/[\u00a0\u202f ]/g, ' '), currency);
    return total ? {total, currency} : null;
  };
  const pageTotal = lines => {
    const amounts = [];
    for (let i = 0; i < lines.length; i++) {
      const match = lines[i].match(label);
      if (!match) continue;
      const rest = lines[i].slice(match[0].length).replace(/\([^)]*\)/g, '').replace(/^[\s:]+/, '');
      if (!amountOnly(rest)) continue;
      const segment = [rest];
      for (let j = i + 1; j < Math.min(lines.length, i + 3) && !/\d/.test(segment.join(' ')) && amountOnly(lines[j]); j++) segment.push(lines[j]);
      if (/\d/.test(segment.join(' ')) === false) return null;
      const amount = parseAmount(segment.join(' '));
      if (!amount) return null;
      amounts.push(amount);
    }
    if (!amounts.length || amounts.some(a => a.total !== amounts[0].total || a.currency !== amounts[0].currency)) return null;
    return amounts[0];
  };
  const visible = e => e.getClientRects().length && getComputedStyle(e).visibility === 'visible';
  const text = document.body.innerText;
  const controls = [...document.querySelectorAll('button,input[type=submit]')].filter(visible);
  // The one final payment button, in the main checkout languages (observed on
  // Shopify de/fr/es/pt/it/en checkouts and common shop systems).
  const pay = controls.filter(e => /^(pay|buy|place( your)? order|complete (order|purchase)|subscribe|pagar|comprar|finalizar (compra|pedido)|confirmar (compra|pedido)|realizar (el )?pedido|jetzt (kaufen|bezahlen)|(zahlungspflichtig|kostenpflichtig) bestellen|kaufen|bezahlen|payer|commander|(valider|finaliser|confirmer) (la |ma )?commande|paga|acquista|conferma (l'ordine|ordine|acquisto)|betalen|bestelling plaatsen|zapłać|kupuję)(?![\p{L}\p{N}])/iu.test((e.innerText || e.value).trim()));
  if (pay.length !== 1) return null;
  const explicit = [...document.querySelectorAll('[data-bloom-total-minor][data-bloom-currency]')].filter(visible);
  let total, currency;
  let processorRecurring = null;
  if (location.origin === 'https://buy.stripe.com') {
    const processor = globalThis.__bloomHostedStripeFacts;
    const displayed = [...document.querySelectorAll('.CurrencyAmount')].filter(visible);
    if (!processor || displayed.length !== 1 || displayed[0].textContent.replace(/\D/g,'').replace(/^0+(?=\d)/,'') !== String(processor.total_minor)) return null;
    total=processor.total_minor;currency=processor.currency;processorRecurring=processor.recurring;
  } else if (location.origin === 'https://js.stripe.com' && location.pathname === '/v3/embedded-checkout-inner.html') {
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
    const found = pageTotal(text.split('\n').map(line => line.trim()).filter(Boolean));
    if (!found) return null;
    ({total,currency} = found);
  }
  const selectors = [...document.querySelectorAll('select')].filter(e => visible(e) && /installment|cuotas|parcelas/i.test([e.name,e.id,e.labels?.[0]?.innerText].join(' ')));
  const shopifyCard = /^\/checkouts\/cn\/[A-Za-z0-9]+\//.test(location.pathname)
    && [...document.querySelectorAll('iframe')].some(e => {
      try {return new URL(e.src).origin === 'https://checkout.pci.shopifyinc.com';} catch {return false;}
    })
    && document.querySelector('input#basic-creditCards[name=basic]')?.checked === true
    && [...document.querySelectorAll('input[name=basic]:checked')].length === 1;
  let installments = 1;
  if (selectors.length > 1) return null;
  if (selectors.length === 1) {
    const match = selectors[0].selectedOptions[0]?.text.match(/^(\d+)\s*(?:x|installments?|cuotas|parcelas)\b/i);
    if (!match) return null;
    installments = Number(match[1]);
  } else if (/installments?|cuotas|parcelas/i.test(text) && !shopifyCard) return null;
  const recurring = processorRecurring ?? /\b(subscription|recurring|auto.?renew|monthly|annually|suscripci[oó]n)\b/i.test(text);
  globalThis.__bloomPayButton = pay[0];
  return {origin:location.origin,payment_frame_origins:[],total_minor:total,currency,installments,recurring};
})()
