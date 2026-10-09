(() => {
  const e = globalThis.__bloomPayButton;
  if (!e || !e.isConnected || e.disabled || !e.getClientRects().length) return false;
  if ([...document.querySelectorAll('input,select,textarea')].some(e => e.getClientRects().length && e.required && !e.checkValidity())) return false;
  e.click();
  return true;
})()
