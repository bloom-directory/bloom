(index, kind, value) => {
  const e = globalThis.__bloomRefs?.[index];
  if (!e || !e.isConnected || e.disabled || e.getAttribute('aria-disabled') === 'true' || !e.getClientRects().length) throw Error('stale');
  const label = (e.innerText || e.value || e.getAttribute('aria-label') || '').replace(/\s+/g, ' ').trim();
  if (kind === 'click' && /^(pay|place( your)? order|complete (purchase|booking)|confirm (and|&) pay|submit payment|buy now|request (uber|ride)|pagar|comprar ahora|finalizar (compra|pedido|reserva)|confirmar (compra|pedido|reserva)|confirmar y pagar|completar reserva|realizar (el )?pedido|jetzt (kaufen|bezahlen)|(zahlungspflichtig|kostenpflichtig) (bestellen|buchen)|buchung abschließen|payer|acheter maintenant|(valider|finaliser|confirmer) (la |ma )?(commande|réservation)|confirmer et payer|paga ora|compra ora|conferma (l'ordine|ordine|acquisto|e paga)|nu betalen|bestelling plaatsen|zapłać)(?![\p{L}\p{N}])/iu.test(label)) throw Error('payment requires approval');
  if (kind === 'click') e.click(); else {
    if ((e.autocomplete || '').split(' ').some(s => s.startsWith('cc-'))) throw Error('private payment input');
    if (kind === 'select' && e.tagName !== 'SELECT') throw Error('wrong field');
    if (kind === 'type' && !['INPUT', 'TEXTAREA'].includes(e.tagName)) throw Error('wrong field');
    if (kind === 'type') {
      // Native editing updates controlled inputs and fires their input
      // handlers. Focus and insertion run in one call so navigation cannot
      // redirect a later insertion.
      e.focus();
      if (!e.isConnected || document.activeElement !== e || (e.autocomplete || '').split(' ').some(s => s.startsWith('cc-'))) throw Error('stale');
      e.select();
      if (!e.isConnected || document.activeElement !== e || (e.autocomplete || '').split(' ').some(s => s.startsWith('cc-'))) throw Error('stale');
      if (!document.execCommand('insertText', false, value)) throw Error('input unsupported');
      e.dispatchEvent(new KeyboardEvent('keyup', {key: value.slice(-1), bubbles: true}));
    } else {
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set.call(e, value);
      e.dispatchEvent(new Event('input', {bubbles: true}));
    }
    e.dispatchEvent(new Event('change', {bubbles: true}));
  }
  return {state: 'acted'};
}
