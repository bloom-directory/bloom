// What the merchant page asks of the human: visible form errors, and a request
// to re-enter contact details. Defined for outcome.js and the pre-payment check.
globalThis.__bloomAttention = () => {
  const visible = e => e.getClientRects().length && getComputedStyle(e).visibility === 'visible';
  const strong = /debes completar|complet[aá] (?:todos )?los campos|(?:es|son) obligatori[oa]s?|deben coincidir|debe coincidir|is required|are required|must match|please (?:enter|fill in|complete)/i;
  const reentry = /reingresa tu (?:correo|n[uú]mero|tel[eé]fono)|re-?enter your (?:email|phone)|confirm your (?:email|phone)/i;
  const weak = /requerid|obligatori|inv[aá]lid|incorrect|required|invalid/i;
  const errorish = e => { for (let a = e, d = 0; a && d < 3; a = a.parentElement, d++)
    if (a.getAttribute('role') === 'alert' || /error|invalid|danger/i.test(String(a.className))) return true; return false; };
  const errors = [...document.querySelectorAll('body *')]
    .filter(e => !e.children.length && visible(e))
    .map(e => [e, e.textContent.replace(/\s+/g, ' ').trim()])
    // The site's request to re-enter contact details is an instruction, not an error.
    .filter(([e, t]) => t && t.length < 160 && !reentry.test(t) && (strong.test(t) || (weak.test(t) && errorish(e))))
    // Plain legends and card-entry hints are not failed validation. Card
    // fields are still empty before approval. Keep marked alerts/errors.
    .filter(([e, t]) => !/^(?:all fields are required|please enter the full name exactly as it appears on the card)[.!]?$/i.test(t) || errorish(e))
    .map(([, t]) => t);
  const invalid = [...document.querySelectorAll('input[aria-invalid=true],select[aria-invalid=true],textarea[aria-invalid=true]')].filter(visible).length;
  const confirmContact = reentry.test(document.body.innerText);
  return {errors: [...new Set(errors)].slice(0, 3), invalid, confirm_contact: confirmContact};
};
