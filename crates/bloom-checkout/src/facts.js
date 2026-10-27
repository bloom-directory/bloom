(async () => {
  // Read the one amount labelled as the total. Labels and number formats cover
  // the main European and American checkout languages; anything unclear
  // returns null so the human finishes in the private view.
  const isoCodes = new Set(Intl.supportedValuesOf('currency'));
  const symbols = [['US$','USD'],['U$S','USD'],['USD$','USD'],['HK$','HKD'],['₺','TRY'],['Türk Lirası','TRY'],['Norske kroner','NOK'],['Forint','HUF'],['Ft','HUF'],['R$','BRL'],['CA$','CAD'],['C$','CAD'],['MX$','MXN'],['AR$','ARS'],
    ['CLP$','CLP'],['COL$','COP'],['$U','UYU'],['S/.','PEN'],['S/','PEN'],['SFr.','CHF'],['SFr','CHF'],['Fr.','CHF'],['zł','PLN'],['€','EUR'],['£','GBP'],['$','$']];
  const dollars = new Set(['USD','CAD','MXN','ARS','CLP','COP','UYU','AUD','NZD','SGD','HKD']);
  const currencyToken = /US\$|U\$S|USD\$|HK\$|₺|Türk Lirası|Norske kroner|Forint|Ft|R\$|CA\$|C\$|MX\$|AR\$|CLP\$|COL\$|\$U|S\/\.?|SFr\.?|Fr\.|zł|[€£$]|(?<!\p{L})[A-Z]{3}(?!\p{L})/gu;
  // Zalando renders "Gesamtsumme" and "inkl. MwSt." with no space between.
  const label = /^(precio total final|montant à payer|importo totale|precio total|total a pagar|total final|gesamtsumme\s*inkl\.\s*mwst\.|total à payer|importe total|montant total|total payment due|total amount due|total amount|total to pay|amount to pay|zu zahlender betrag|ödenecek miktar|số tiền cần thanh toán|tổng cộng|beløp å betale|fizetendő összeg|paying|gesamtbetrag|totaalbedrag|grand total|order total|monto total|valor total|gesamtsumme|gesamtpreis|amount due|te betalen|do zapłaty|total due|total ttc|endbetrag|zu zahlen|totale|gesamt|totaal|total|summe|razem|suma)(?![\p{L}\p{N}])/iu;
  // An amount line holds only currency marks, digits, separators and spacing.
  const amountOnly = line => !/\p{L}/u.test(line.replace(/\([^)]*\)/g, '').replace(currencyToken, ''));
  const declared = () => {
    const codes = new Set([...document.querySelectorAll('[itemprop=priceCurrency],meta[property="og:price:currency"],meta[property="product:price:currency"]')]
      .map(e => (e.getAttribute('content') || e.textContent).trim().toUpperCase()));
    for (const script of document.querySelectorAll('script[type="application/ld+json"]')) {
      for (const match of script.textContent.matchAll(/"priceCurrency"\s*:\s*"([A-Za-z]{3})"/g)) codes.add(match[1].toUpperCase());
    }
    // Ovago states the currency separately from its bare-dollar total.
    for (const match of document.body.innerText.matchAll(/^Prices quoted in ([A-Z]{3}) incl\. taxes and fees[ \t]*$/gm)) codes.add(match[1]);
    return codes;
  };
  const dollarCurrency = () => {
    const codes = declared();
    // Conflicting or invalid declarations must not fall back to language.
    if (codes.size) return codes.size === 1 && dollars.has([...codes][0]) ? [...codes][0] : null;
    // A bare "$" otherwise follows the page language's region (es-AR, en-US, ...).
    const region = (document.documentElement.lang || '').split('-')[1]?.toUpperCase();
    return {US:'USD',CA:'CAD',MX:'MXN',AR:'ARS',CL:'CLP',CO:'COP',UY:'UYU'}[region] || null;
  };
  const minorUnits = (number, code) => {
    if (!isoCodes.has(code)) return null;
    // ISO 4217 minor units (SIX list, 2026-09-17), not CLDR display digits.
    const scale = ({
      BIF:0,CLP:0,DJF:0,GNF:0,ISK:0,JPY:0,KMF:0,KRW:0,PYG:0,RWF:0,UGX:0,UYI:0,VND:0,VUV:0,XAF:0,XOF:0,XPF:0,
      BHD:3,IQD:3,JOD:3,KWD:3,LYD:3,OMR:3,TND:3,
      CLF:4,UYW:4,
    })[code] ?? 2;
    let whole = number, fraction = '';
    const last = number.search(/[.,][^.,]*$/);
    const tail = last >= 0 ? number.slice(last + 1) : '';
    const head = last >= 0 ? number.slice(0, last) : number;
    // A final '.' or ',' followed by 1..scale digits is decimal; three digits
    // are always grouping for currencies with fewer than three decimals. For
    // three-decimal currencies a three-digit tail is decimal when the whole
    // part groups with a different separator ("IQD 1,250.125"); a lone
    // separator ("KWD 1.234") stays ambiguous and finishes in the private view.
    const unambiguous = tail.length === 3 && scale >= 3
      && /[.,'\u2019 ]/.test(head) && !head.includes(number[last]);
    if (last >= 0 && /^\d+$/.test(tail) && (tail.length <= scale && tail.length !== 3 || unambiguous)) {
      whole = head; fraction = tail;
    } else if (scale >= 3 && last >= 0) return null;
    const grouping = [...new Set(whole.replace(/\d/g, ''))];
    if (grouping.length > 1 || (fraction && grouping[0] === number[last])) return null;
    if (grouping.length === 1 && !new RegExp(`^\\d{1,3}(?:[${grouping[0]}]\\d{3})+$`).test(whole)) return null;
    const minor = Number(whole.replace(/\D/g, '')) * 10 ** scale + Number(fraction.padEnd(scale, '0') || 0);
    return Number.isSafeInteger(minor) && minor >= 0 ? minor : null;
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
    return total === null ? null : {total, currency};
  };
  let totalRefusal = 'total_or_currency';
  const pageTotal = lines => {
    // A converted display total is not the charge. Gotogate labels the actual
    // charge separately; unclear or conflicting charge labels stay manual.
    const chargeLabel = /^el precio se cobrar[aá] en(?![\p{L}\p{N}])/iu;
    const amountLabel = lines.some(line => chargeLabel.test(line)) ? chargeLabel : label;
    const amounts = [];
    for (let i = 0; i < lines.length; i++) {
      const match = lines[i].match(amountLabel);
      if (!match) continue;
      const rest = lines[i].slice(match[0].length).replace(/\([^)]*\)/g, '').replace(/^[\s:]+/, '');
      // A price-breakdown heading has no amount of its own. Keep the actual
      // labelled totals below it, including their disagreement checks.
      if (!rest && ((/^total amount\s*:?$/i.test(lines[i]) && /^subtotal/i.test(lines[i + 1] || '')) ||
          (/^gesamtsumme\s*:?$/i.test(lines[i]) && /^zwischensumme/i.test(lines[i + 1] || '')))) continue;
      if (!amountOnly(rest)) continue;
      const segment = [rest];
      // Take the amount from the next lines, then at most one currency line
      // after it (JetSMART: "Total", ":", "$371.805,17", "ARS").
      for (let j = i + 1; j < Math.min(lines.length, i + 4) && amountOnly(lines[j]); j++) {
        const priced = /\d/.test(segment.join(' '));
        if (priced && /\d/.test(lines[j])) break;
        segment.push(lines[j]);
        if (priced) break;
      }
      if (/\d/.test(segment.join(' ')) === false) { totalRefusal = 'total_without_amount'; return null; }
      const amount = parseAmount(segment.join(' '));
      if (!amount) return null;
      amounts.push(amount);
    }
    if (!amounts.length) { totalRefusal = 'total_not_found'; return null; }
    if (amounts.some(a => a.total !== amounts[0].total || a.currency !== amounts[0].currency)) { totalRefusal = 'conflicting_totals'; return null; }
    return amounts[0];
  };
  const visible = e => e.getClientRects().length && getComputedStyle(e).visibility === 'visible';
  // YouTube prints "$8.99\u200b/month": a zero-width space between the amount
  // and its period. These characters are invisible to the reader, carry no
  // meaning, and are not whitespace to a regular expression, so they come
  // out before anything is matched against the page.
  const text = document.body.innerText.replace(/[\u00ad\u200b-\u200d\u2060\ufeff]/g, '');
  const controls = [...document.querySelectorAll('button,input[type=submit],input[type=button],a,[role=button]')].filter(visible);
  // The one final payment button, in the main checkout languages (observed on
  // Shopify de/fr/es/pt/it/en checkouts, common shop systems, and Booking.com,
  // Ryanair and Airbnb final pages, 2026-10-11). Labels may use non-breaking spaces.
  const pay = controls.filter(e => BLOOM_PAY_WORDS.test((e.innerText || e.value || '').replace(/\s+/g, ' ').trim()));
  if (pay.length !== 1) return {refusal:'pay_control_count'};
  // Test fixtures declare their total; a merchant page never chooses its own.
  const fixture = BLOOM_FIXTURE_TOTALS && ['localhost', '127.0.0.1'].includes(location.hostname);
  const explicit = fixture ? [...document.querySelectorAll('[data-bloom-total-minor][data-bloom-currency]')].filter(visible) : [];
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
    if (!found) return {refusal:totalRefusal};
    ({total,currency} = found);
  }
  const selectors = [...document.querySelectorAll('select')].filter(e => visible(e) && /installment|cuotas|parcelas/i.test([e.name,e.id,e.labels?.[0]?.innerText].join(' ')));
  const selectedInstallments = [...text.matchAll(/\b(?:you selected|selected|seleccionaste|seleccionado|seleccionada|escolheu)\s+(\d+)\s*(?:x|installments?|cuotas?|parcelas?)\b/giu)]
    .map(match => Number(match[1]));
  const selectedCounts = new Set(selectedInstallments);
  const shopifyCard = /^\/checkouts\/cn\/[A-Za-z0-9]+\//.test(location.pathname)
    && [...document.querySelectorAll('iframe')].some(e => {
      try {return new URL(e.src).origin === 'https://checkout.pci.shopifyinc.com';} catch {return false;}
    })
    && document.querySelector('input#basic-creditCards[name=basic]')?.checked === true
    && [...document.querySelectorAll('input[name=basic]:checked')].length === 1;
  let installments = 1;
  if (selectors.length > 1 || selectedCounts.size > 1) return {refusal:'installment_choice'};
  if (selectors.length === 1) {
    const match = selectors[0].selectedOptions[0]?.text.match(/^(\d+)\s*(?:x|installments?|cuotas|parcelas)\b/i);
    if (!match) return {refusal:'installment_choice'};
    installments = Number(match[1]);
  } else if (selectedCounts.size === 1) {
    installments = [...selectedCounts][0];
  } else if (/installments?|cuotas|parcelas/i.test(text) && !shopifyCard) return {refusal:'installment_choice'};
  const recurring = processorRecurring ?? /\b(subscription|recurring|auto.?renew|monthly|annually|suscripci[oó]n)\b/i.test(text);
  // A trial price hides what a subscription really costs. Read the ongoing
  // price the page prints as "<amount> per <period>", and the day it starts
  // when the page writes a date no reader could take two ways. Anything less
  // clear stays unset: the review says only what the page is plain about.
  const periodWords = {month:'month',months:'month',monthly:'month',mo:'month',mes:'month',meses:'month',mensual:'month',monat:'month',monate:'month',monatlich:'month',mois:'month',mensuel:'month',mese:'month',mesi:'month',mensile:'month',
    year:'year',years:'year',yearly:'year',annually:'year',annual:'year',yr:'year','año':'year','años':'year',anual:'year',jahr:'year',jahre:'year','jährlich':'year',an:'year',annuel:'year',anno:'year',anni:'year',annuale:'year',
    week:'week',weeks:'week',weekly:'week',semana:'week',semanal:'week',woche:'week','wöchentlich':'week',semaine:'week',settimana:'week',
    day:'day',days:'day',daily:'day','día':'day',dias:'day',diario:'day',tag:'day','täglich':'day',jour:'day',giorno:'day'};
  const period = new RegExp(`^\\s*(?:\\/|per|every|each|a|an|al|por|pro|par|the|ogni)?\\s*(${Object.keys(periodWords).join('|')})(?![\\p{L}\\p{N}])`, 'iu');
  const money = new RegExp(`(?:${currencyToken.source})\\s*\\d[\\d.,'’\\u00a0\\u202f ]*|\\d[\\d.,'’\\u00a0\\u202f ]*\\s*(?:${currencyToken.source})`, 'gu');
  const renewalPrice = () => {
    const found = new Map();
    for (const match of text.matchAll(money)) {
      const after = text.slice(match.index + match[0].length, match.index + match[0].length + 24);
      const unit = after.match(period);
      if (!unit) continue;
      const priced = parseAmount(match[0]);
      if (!priced || !priced.total || priced.currency !== currency) continue;
      found.set(`${priced.total}/${periodWords[unit[1].toLowerCase()]}`,
        {renewal_minor: priced.total, renewal_period: periodWords[unit[1].toLowerCase()]});
    }
    // Two different ongoing prices on one page is a plan chooser, not a fact.
    return found.size === 1 ? [...found.values()][0] : null;
  };
  const months = ['january','february','march','april','may','june','july','august','september','october','november','december'];
  const iso = (year, month, day) =>
    `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
  const renewalDate = () => {
    const dates = new Set();
    const named = months.join('|');
    for (const sentence of text.split(/[.\n]/)) {
      if (!/\b(then|thereafter|starting|starts|start|begins|beginning|renews|renewal|first charge|next charge|after (?:the )?(?:trial|free)|danach|luego|despu[ée]s|ensuite|a partir del|à partir du|ab dem)\b/iu.test(sentence)) continue;
      for (const match of sentence.matchAll(/\b(\d{4})-(\d{2})-(\d{2})\b/g)) dates.add(iso(match[1], Number(match[2]), Number(match[3])));
      for (const match of sentence.matchAll(new RegExp(`\\b(\\d{1,2})(?:st|nd|rd|th)?\\s+(${named})\\w*,?\\s+(\\d{4})\\b`, 'gi')))
        dates.add(iso(match[3], months.indexOf(match[2].toLowerCase()) + 1, Number(match[1])));
      for (const match of sentence.matchAll(new RegExp(`\\b(${named})\\w*\\s+(\\d{1,2})(?:st|nd|rd|th)?,?\\s+(\\d{4})\\b`, 'gi')))
        dates.add(iso(match[3], months.indexOf(match[1].toLowerCase()) + 1, Number(match[2])));
      // 11/25/2026 and 25/11/2026 are the same day only because 25 cannot be
      // a month. 05/06/2026 could be either, so it is not a date here.
      for (const match of sentence.matchAll(/\b(\d{1,2})[\/.](\d{1,2})[\/.](\d{4})\b/g)) {
        const [first, second] = [Number(match[1]), Number(match[2])];
        if ((first > 12) === (second > 12)) continue;
        dates.add(first > 12 ? iso(match[3], second, first) : iso(match[3], first, second));
      }
    }
    return dates.size === 1 ? [...dates][0] : null;
  };
  let renewal = {};
  if (recurring) {
    const price = renewalPrice();
    if (price) {
      const starts = renewalDate();
      renewal = starts ? {...price, renewal_starts_on: starts} : price;
    }
  }
  // Nothing to charge today is only meaningful as a subscription that starts
  // later: the renewal terms are what the person would be approving. Without
  // them there is no amount on this page to approve at all.
  if (!total && !renewal.renewal_minor) { totalRefusal = 'total_not_found'; return {refusal: totalRefusal}; }
  globalThis.__bloomPayButton = pay[0];
  return {origin:location.origin,payment_frame_origins:[],total_minor:total,currency,installments,recurring,...renewal};
})()
