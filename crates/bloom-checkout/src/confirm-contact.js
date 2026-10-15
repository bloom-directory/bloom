(() => {
  // The site asks to re-enter the contact email and phone after Pay. Copy them
  // from the contact form on the same page into the empty re-entry fields;
  // the human checks them and presses the site's own button.
  const visible = e => e.getClientRects().length && getComputedStyle(e).visibility === 'visible';
  const norm = s => (s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
  const prompt = [...document.querySelectorAll('[role=dialog],[aria-modal=true],[class*=modal i]')]
    .filter(visible).find(d => /reingresa|re-?enter your|confirm your/i.test(d.innerText));
  if (!prompt) return {copied: 0};
  const kind = e => {
    const label = norm([e.type, e.name, e.id, e.placeholder, e.getAttribute('aria-label'), e.labels?.[0]?.innerText].join(' '));
    return /mail|correo/.test(label) ? 'email' : /tel|phone|fono|celular|movil/.test(label) ? 'phone' : null;
  };
  // A phone value is digits; the country prefix field ("Argentina (+54)") is not.
  const usable = (k, value) => k === 'email' ? /^[^@\s]+@[^@\s]+$/.test(value) : /^\+?[\d\s()-]{6,}$/.test(value);
  const sources = {};
  for (const e of document.querySelectorAll('input')) {
    const k = kind(e);
    if (k && !sources[k] && !prompt.contains(e) && visible(e) && usable(k, e.value)) sources[k] = e.value;
  }
  let copied = 0;
  for (const e of prompt.querySelectorAll('input')) {
    const k = kind(e);
    if (!k || e.value || !visible(e) || !sources[k]) continue;
    e.focus(); e.select();
    if (!document.execCommand('insertText', false, sources[k])) continue;
    e.dispatchEvent(new KeyboardEvent('keyup', {key: sources[k].slice(-1), bubbles: true}));
    e.dispatchEvent(new Event('change', {bubbles: true}));
    e.blur();
    copied++;
  }
  return {copied};
})()
