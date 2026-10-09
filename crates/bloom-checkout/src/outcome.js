(() => {
  const text = document.body.innerText;
  if (location.origin === 'https://buy.stripe.com' && /We are unable to authenticate your payment method\./.test(text))
    return {state:'declined',source:'merchant-reported',confirmation_reached:false};
  if (/card (?:was |has been )?declined|payment (?:was )?(?:declined|failed)|insufficient funds/i.test(text))
    return {state:'declined',source:'merchant-reported',confirmation_reached:false};
  const hostedSubscription = location.origin === 'https://buy.stripe.com' && /\bThanks for subscribing\b/.test(text);
  if (!hostedSubscription && !/payment (?:successful|succeeded|complete)|order confirmed|thank you for (?:your order|your purchase|shopping)|purchase complete/i.test(text)) return {state:'waiting'};
  const match = text.match(/(?:order|confirmation|receipt)\s*(?:number\s*[:#]?|id\s*[:#]?|#|:)\s*([A-Za-z0-9-]{3,64})/i);
  const id = match && (!/^\d{11,}$/.test(match[1])) ? match[1] : null;
  const amounts=[...text.matchAll(/(?:total|amount paid|charged)\s*[:]?\s*([A-Z]{3})\s*([0-9]+)\.([0-9]{2})\b/gi)];
  const amount=amounts.length===1 ? amounts[0] : null;
  const total=amount ? Number(amount[2])*100+Number(amount[3]) : null;
  return {state:'paid',source:'merchant-reported',confirmation_reached:true,order_id:id,
    merchant_reported_total_minor:Number.isSafeInteger(total) ? total : null,currency:amount ? amount[1].toUpperCase() : null};
})()
