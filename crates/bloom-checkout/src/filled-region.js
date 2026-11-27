(() => {
  // Page area covering every visible filled field except card and password
  // fields, in document coordinates; null when nothing is filled.
  const fields = [...document.querySelectorAll('input,select,textarea')].filter(e => {
    if (!e.getClientRects().length || e.type === 'hidden' || e.type === 'password') return false;
    if (/^cc-/.test((e.autocomplete || '').split(' ').at(-1))) return false;
    if (e.type === 'checkbox' || e.type === 'radio') return e.checked;
    return Boolean(e.value);
  });
  if (!fields.length) return null;
  const boxes = fields.map(e => e.getBoundingClientRect());
  const top = Math.min(...boxes.map(b => b.top)) + scrollY;
  const bottom = Math.max(...boxes.map(b => b.bottom)) + scrollY;
  return {top, height: bottom - top};
})()
