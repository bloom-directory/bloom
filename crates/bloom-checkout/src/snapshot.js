(() => {
  const visible = e => e.getClientRects().length && getComputedStyle(e).visibility === 'visible';
  const nodes = [...document.querySelectorAll('a[href],button,input,textarea,select,[role="button"]')]
    .filter(e => visible(e) && !e.disabled && e.type !== 'hidden').slice(0, 300);
  globalThis.__bloomRefs = nodes;
  const elements = nodes.map(e => ({
    role: e.tagName.toLowerCase(),
    label: (e.getAttribute('aria-label') || e.labels?.[0]?.innerText || e.innerText || e.placeholder || '').slice(0, 200),
    type: e.type || null,
    options: e.tagName === 'SELECT' ? [...e.options].map(o => ({value: o.value, label: o.text})) : undefined
  }));
  // Values and child frames are deliberately absent from the shopping projection.
  return {url: location.origin + location.pathname, elements};
})()
