// What the merchant page asks of the human: visible form errors, and a request
// to re-enter contact details. Defined for outcome.js and the pre-payment check.
globalThis.__bloomAttention = () => {
  const visible = e => e.getClientRects().length && getComputedStyle(e).visibility === 'visible';
  const strong = /debes completar|complet[aá] (?:todos )?los campos|(?:es|son) obligatori[oa]s?|deben coincidir|debe coincidir|is required|are required|must match|please (?:enter|fill in|complete)/i;
  const weak = /requerid|obligatori|inv[aá]lid|incorrect|required|invalid/i;
  const errorish = e => { for (let a = e, d = 0; a && d < 3; a = a.parentElement, d++)
    if (a.getAttribute('role') === 'alert' || /error|invalid|danger/i.test(String(a.className))) return true; return false; };
  const errors = [...document.querySelectorAll('body *')]
    .filter(e => !e.children.length && visible(e))
    .map(e => [e, e.textContent.replace(/\s+/g, ' ').trim()])
    .filter(([e, t]) => t && t.length < 160 && (strong.test(t) || (weak.test(t) && errorish(e))))
    .map(([, t]) => t);
  const invalid = [...document.querySelectorAll('input[aria-invalid=true],select[aria-invalid=true],textarea[aria-invalid=true]')].filter(visible).length;
  const confirmContact = /reingresa tu (?:correo|n[uú]mero|tel[eé]fono)|re-?enter your (?:email|phone)|confirm your (?:email|phone)/i.test(document.body.innerText);
  return {errors: [...new Set(errors)].slice(0, 3), invalid, confirm_contact: confirmContact};
};
