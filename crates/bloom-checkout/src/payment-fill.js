(origin, index, value) => {
  // One call binds the insertion to the approved document: a focus-driven
  // navigation cannot redirect a later insertion.
  if (location.origin !== origin || !globalThis.__bloomPaymentValid()) throw Error('changed');
  const e = globalThis.__bloomPaymentNodes[index];
  e.focus();
  if (!e.isConnected || !globalThis.__bloomPaymentValid()) throw Error('changed');
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(e, value);
  e.dispatchEvent(new Event('input', {bubbles: true}));
  e.dispatchEvent(new Event('change', {bubbles: true}));
  return true;
}
