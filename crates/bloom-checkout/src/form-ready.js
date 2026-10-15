(() => {
  const visible = e => {
    if (!e.getClientRects().length) return false;
    for (let node = e; node; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (style.display === 'none' || style.visibility !== 'visible' || Number(style.opacity) === 0) return false;
    }
    return true;
  };
  const payment = e => globalThis.__bloomPaymentNodes?.includes(e)
    || (e.autocomplete || '').split(' ').some(part => part.startsWith('cc-'));
  const controls = [...document.querySelectorAll('input,select,textarea')]
    .filter(e => visible(e) && !e.disabled && !payment(e));
  return !controls.some(e => e.getAttribute('aria-invalid') === 'true' || !e.checkValidity());
})()
