(() => {
  const text = document.body.innerText;
  if (location.origin === 'https://buy.stripe.com' && /We are unable to authenticate your payment method\./.test(text))
    return {state:'declined',source:'merchant-reported',confirmation_reached:false};
  // Declines, in the main checkout languages. Shopify: "Your payment details couldn’t be verified."
  if (/card (?:was |has been )?declined|payment (?:was )?(?:declined|failed)|insufficient funds|payment details couldn.t be verified|(?:zahlung|karte) (?:wurde )?abgelehnt|zahlung fehlgeschlagen|paiement (?:a été )?refusé|carte (?:a été )?refusée|paiement échoué|(?:pago|tarjeta) (?:fue )?(?:rechazad[oa]|denegad[oa])|pagamento (?:foi )?recusado|cartão (?:foi )?recusado|pagamento (?:è stato )?rifiutato|carta rifiutata|betaling (?:is )?mislukt|betaling geweigerd/i.test(text))
    return {state:'declined',source:'merchant-reported',confirmation_reached:false};
  const hostedSubscription = location.origin === 'https://buy.stripe.com' && /\bThanks for subscribing\b/.test(text);
  // Shopify's thank-you page is reached only after the order is created.
  const shopifyThankYou = /^(?:\/\d+)?\/checkouts\/(?:[a-z]+\/)?[A-Za-z0-9]+(?:\/[a-z]{2}(?:-[a-z]{2})?)?\/thank[-_]you(?:\/|$)/i.test(location.pathname);
  const success = /payment (?:successful|succeeded|complete)|order (?:is )?confirmed|thank you for (?:your order|your purchase|shopping)|purchase complete|bestellung (?:ist )?bestätigt|vielen dank für (?:ihre|deine) bestellung|zahlung erfolgreich|commande (?:est )?confirmée|merci pour votre commande|paiement réussi|pedido (?:está )?confirmado|gracias por (?:tu|su) (?:compra|pedido)|(?:reserva|reservación) (?:ha sido |está )?(?:confirmada|completada)|(?:compra|pago) (?:ha sido )?(?:confirmad[oa]|aprobad[oa]|exitos[oa]|acreditad[oa])|obrigad[oa] pela (?:sua )?compra|pagamento aprovado|ordine (?:è )?confermato|grazie per (?:il tuo|il suo) ordine|bestelling (?:is )?bevestigd|bedankt voor je bestelling/i.test(text);
  if (!hostedSubscription && !shopifyThankYou && !success) {
    // A validation message after the click proves the merchant kept the user
    // on the form. Keep private control open so the human can correct it; this
    // is not an unknown payment outcome.
    const invalid = [...document.querySelectorAll('input,select,textarea')]
      .some(e => e.getClientRects().length && !e.disabled
        && (e.getAttribute('aria-invalid') === 'true' || !e.checkValidity()));
    const formError = /(?:fill|complete|check|review) (?:in |out )?(?:all )?(?:the )?(?:required )?fields|(?:debes |debe |por favor,? )?(?:completar|completa|complete|revisa|revise) (?:todos )?(?:los )?campos|campos (?:obligatorios|requeridos)|preencha (?:todos )?os campos|champs (?:obligatoires|requis)/i.test(text);
    if (invalid || formError)
      return {state:'needs_input',source:'merchant-form',confirmation_reached:false,order_id:null,
        merchant_reported_total_minor:null,currency:null};
    return {state:'waiting'};
  }
  const match = text.match(/(?:order|confirmation|receipt)\s*(?:number\s*[:#]?|id\s*[:#]?|#|:)\s*([A-Za-z0-9-]{3,64})/i)
    || text.match(/(?:c[oó]digo (?:de )?reserva|localizador|booking reference|reservation code|record locator)\s*[:#]?\s*([A-Z0-9]{5,8})\b/i);
  const id = match && (!/^\d{11,}$/.test(match[1])) ? match[1] : null;
  const amounts=[...text.matchAll(/(?:total|amount paid|charged)\s*[:]?\s*([A-Z]{3})\s*([0-9]+)\.([0-9]{2})\b/gi)];
  const amount=amounts.length===1 ? amounts[0] : null;
  const total=amount ? Number(amount[2])*100+Number(amount[3]) : null;
  return {state:id && /(?:reserva|reservación|booking|reservation|locator|localizador)/i.test(match[0]) ? 'booked' : 'paid',source:'merchant-reported',confirmation_reached:true,order_id:id,
    merchant_reported_total_minor:Number.isSafeInteger(total) ? total : null,currency:amount ? amount[1].toUpperCase() : null};
})()
