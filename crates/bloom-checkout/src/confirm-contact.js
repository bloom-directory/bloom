(() => {
  // The site asks to re-enter the contact email and phone, before or after Pay.
  // Copy them from the contact form on the same page into the empty re-entry
  // fields: those inside the site's re-entry dialog or labelled "confirm".
  const visible = e => e.getClientRects().length && getComputedStyle(e).visibility === 'visible';
  const norm = s => (s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
  const prompt = [...document.querySelectorAll('[role=dialog],[aria-modal=true],[class*=modal i]')]
    .filter(visible).find(d => /reingresa|re-?enter your|confirm your/i.test(d.innerText));
  // Text beside the field, up to the nearest ancestor holding another field.
  const caption = e => { for (let a = e.parentElement, d = 0; a && d < 3 && a.querySelectorAll('input').length === 1; a = a.parentElement, d++)
    if (a.innerText.trim()) return a.innerText; return ''; };
  // Visible text decides; names come last (JetSMART names its phone box
  // jetsmartcontact.emailaddress).
  const shown = e => norm([e.placeholder, e.getAttribute('aria-label'), e.labels?.[0]?.innerText, caption(e)].join(' '));
  const label = e => shown(e) + ' ' + norm([e.type, e.name, e.id].join(' '));
  const kindOf = l => /mail|correo/.test(l) ? 'email' : /tel|phone|fono|celular|movil/.test(l) ? 'phone' : null;
  const kind = e => kindOf(shown(e)) || kindOf(norm([e.type, e.name, e.id].join(' ')));
  const reentry = e => prompt?.contains(e) || /confirm|reingres|repet|repeat|verif/.test(label(e));
  // A phone value is digits; the country prefix field ("Argentina (+54)") is not.
  const usable = (k, value) => k === 'email' ? /^[^@\s]+@[^@\s]+$/.test(value) : /^\+?[\d\s()-]{6,}$/.test(value);
  const sources = {};
  for (const e of document.querySelectorAll('input')) {
    const k = kind(e);
    if (k && !sources[k] && !reentry(e) && visible(e) && usable(k, e.value)) sources[k] = e.value;
  }
  let copied = 0;
  for (const e of document.querySelectorAll('input')) {
    const k = kind(e);
    if (!k || !reentry(e) || e.value || !visible(e) || !sources[k]) continue;
    e.focus(); e.select();
    if (!document.execCommand('insertText', false, sources[k])) continue;
    e.dispatchEvent(new KeyboardEvent('keyup', {key: sources[k].slice(-1), bubbles: true}));
    e.dispatchEvent(new Event('change', {bubbles: true}));
    e.blur();
    copied++;
  }
  return {copied};
})()
