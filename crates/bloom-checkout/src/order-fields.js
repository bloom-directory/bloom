(() => {
  // Every visible filled field except card and password fields, labelled as
  // the page captions it: the human checks these before approving payment.
  const text = e => (e?.innerText || '').replace(/\s+/g, ' ').trim();
  const caption = e => {
    for (let a = e.parentElement, depth = 0; a && depth < 4; a = a.parentElement, depth++) {
      if (a.querySelectorAll('input,select,textarea').length > 1) return '';
      const t = text(a);
      if (t) return t.length <= 80 ? t : '';
    }
    return '';
  };
  // Card markup on a box captioned email or phone is a site's autofill guard
  // (JetSMART's confirm boxes), not a card field.
  const secret = (e, label) => e.type === 'password'
    || (/^cc-/.test((e.autocomplete || '').split(' ').at(-1)) && !/e-?mail|correo|tel[eé]fono|phone/i.test(label));
  const fields = [];
  for (const e of document.querySelectorAll('input,select,textarea')) {
    if (!e.getClientRects().length || e.type === 'hidden' || e.disabled) continue;
    let label = e.getAttribute('aria-label') || text(e.labels?.[0]) || e.placeholder || caption(e) || e.name || '';
    if (secret(e, label)) continue;
    let value;
    if (e.type === 'checkbox') { if (!e.checked) continue; value = 'Yes'; }
    else if (e.type === 'radio') { if (!e.checked) continue; value = text(e.labels?.[0]) || e.value;
      label = text(e.closest('fieldset')?.querySelector('legend')) || e.name || label; }
    else if (e.tagName === 'SELECT') value = e.selectedOptions[0]?.text || '';
    else value = e.value;
    // A site-drawn list may show its choice beside an empty input.
    if (!value && e.getAttribute('role') === 'combobox') value = text(e.parentElement?.parentElement);
    if (!value) continue;
    fields.push({label: label.slice(0, 120), value: String(value).slice(0, 200)});
    if (fields.length >= 60) break;
  }
  return fields;
})()
