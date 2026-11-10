(() => {
  const text = document.body.innerText;
  // This is only a page phrase, not proof that a charge did not happen.
  const failed = (location.origin === 'https://buy.stripe.com' && /We are unable to authenticate your payment method\./.test(text)) || /card (?:was |has been )?declined|payment (?:was )?(?:declined|failed)|insufficient funds|payment details couldn.t be verified|(?:zahlung|karte) (?:wurde )?abgelehnt|zahlung fehlgeschlagen|paiement (?:a été )?refusé|carte (?:a été )?refusée|paiement échoué|(?:pago|tarjeta) (?:fue )?(?:rechazad[oa]|denegad[oa])|pagamento (?:foi )?recusado|cartão (?:foi )?recusado|pagamento (?:è stato )?rifiutato|carta rifiutata|betaling (?:is )?mislukt|betaling geweigerd/i.test(text);
  // A reservation reference can exist before payment. Require the merchant to
  // report a purchase/payment confirmation or an issued ticket as well.
  // `phrase` is the success evidence; checkout ignores it if the page already
  // showed it before submission. Failure wording beside it is never success.
  const booking = text.match(/(?:[Cc][oó]digo (?:de |da )?reserva|[Bb]ooking (?:reference|code|number)|[Rr]eservation code|[Ll]ocalizador|\bPNR)\s*[:#]?\s*([A-Z0-9]{5,8})\b/);
  const purchaseConfirmed = /(?:payment|purchase) (?:was |has been )?(?:confirmed|successful|received|approved|completed)|(?:compra|pago) (?:ha sido |fue |está )?(?:confirmad[oa]|aprobad[oa]|exitos[oa]|acreditad[oa])|pagamento (?:aprovado|confirmado)|zahlung erfolgreich|paiement (?:confirmé|accepté)|(?:e-?ticket|ticket number|n[uú]mero (?:de )?(?:billete|boleto))\s*[:#]?\s*\d{3}[- ]?\d{10}\b/i.exec(text);
  if (booking && purchaseConfirmed && !failed) return {state:'booked',source:'merchant-reported',confirmation_reached:true,order_id:booking[1],
    merchant_reported_total_minor:null,currency:null,phrase:purchaseConfirmed[0].toLowerCase()};
  // A request to re-enter contact details: the payment may be in progress, so
  // the state stays as it is; checkout copies the details for the human.
  const attention = globalThis.__bloomAttention?.();
  if (attention?.confirm_contact) return {state:'waiting',reason:'confirm_contact'};
  // A form error after the click: the merchant kept the human on the form.
  if (attention && (attention.errors.length || attention.invalid)) return {state:'needs_input',reason:'form_errors'};
  if (booking) return {state:'waiting',reason:'reservation_reference_only',order_id:booking[1]};
  const hostedSubscription = location.origin === 'https://buy.stripe.com' && /\bThanks for subscribing\b/.exec(text);
  // Shopify's thank-you page is reached only after the order is created.
  const shopifyThankYou = /^(?:\/\d+)?\/checkouts\/(?:[a-z]+\/)?[A-Za-z0-9]+(?:\/[a-z]{2}(?:-[a-z]{2})?)?\/thank[-_]you(?:\/|$)/i.exec(location.pathname);
  const success = /payment (?:successful|succeeded|complete)|order (?:is )?confirmed|thank you for (?:your order|your purchase|shopping)|purchase complete|bestellung (?:ist )?bestätigt|vielen dank für (?:ihre|deine) bestellung|zahlung erfolgreich|commande (?:est )?confirmée|merci pour votre commande|paiement réussi|pedido (?:está )?confirmado|gracias por (?:tu|su) (?:compra|pedido)|(?:reserva|reservación) (?:ha sido |está )?(?:confirmada|completada)|(?:compra|pago) (?:ha sido )?(?:confirmad[oa]|aprobad[oa]|exitos[oa]|acreditad[oa])|obrigad[oa] pela (?:sua )?compra|pagamento aprovado|ordine (?:è )?confermato|grazie per (?:il tuo|il suo) ordine|bestelling (?:is )?bevestigd|bedankt voor je bestelling/i.exec(text);
  const phrase = (hostedSubscription || shopifyThankYou || success)?.[0];
  if (!phrase) return failed ? {state:'declined',source:'merchant-reported',confirmation_reached:false} : {state:'waiting'};
  // Mixed success and failure copy (help text, FAQs) proves neither.
  if (failed) return {state:'waiting',reason:'mixed_outcome'};
  const match = text.match(/(?:order|confirmation|receipt)\s*(?:number\s*[:#]?|id\s*[:#]?|#|:)\s*([A-Za-z0-9-]{3,64})/i);
  const id = match && (!/^\d{11,}$/.test(match[1])) ? match[1] : null;
  const amounts=[...text.matchAll(/(?:total|amount paid|charged)\s*[:]?\s*([A-Z]{3})\s*([0-9]+)\.([0-9]{2})\b/gi)];
  const amount=amounts.length===1 ? amounts[0] : null;
  // This reader accepts two decimal places only. Do not misstate currencies
  // whose ISO minor unit has a different exponent.
  const nonTwoDecimal = new Set('BIF CLP DJF GNF ISK JPY KMF KRW PYG RWF UGX UYI VND VUV XAF XOF XPF BHD IQD JOD KWD LYD OMR TND CLF UYW'.split(' '));
  const total=amount && !nonTwoDecimal.has(amount[1].toUpperCase()) ? Number(amount[2])*100+Number(amount[3]) : null;
  // A success phrase is not paid. Checkout accepts it only after a recorded
  // submission, only from the top document, and only if it is new.
  return {state:'payment_phrase',source:'merchant-reported',confirmation_reached:true,order_id:id,
    merchant_reported_total_minor:Number.isSafeInteger(total) ? total : null,currency:amount ? amount[1].toUpperCase() : null,
    phrase:phrase.toLowerCase()};
})()
