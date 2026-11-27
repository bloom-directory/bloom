(origin, index, value) => {
  // One call binds the insertion to the approved document: a focus-driven
  // navigation cannot redirect a later insertion.
  if (location.origin !== origin || !globalThis.__bloomPaymentValid()) throw Error('changed');
  const e = globalThis.__bloomPaymentNodes[index];
  e.focus();
  if (!e.isConnected || !globalThis.__bloomPaymentValid()) throw Error('changed');
  let prototype = HTMLInputElement.prototype;
  if (e instanceof HTMLSelectElement) {
    const matches = [...e.options].filter(o => !o.disabled && !o.closest('optgroup[disabled]')
      && (o.value === value || o.text.trim() === value
        || (/^\d+$/.test(o.value) && /^\d+$/.test(value) && Number(o.value) === Number(value))));
    if (matches.length !== 1) throw Error('ambiguous card choice');
    value = matches[0].value;
    prototype = HTMLSelectElement.prototype;
  }
  Object.getOwnPropertyDescriptor(prototype, 'value').set.call(e, value);
  e.dispatchEvent(new Event('input', {bubbles: true}));
  e.dispatchEvent(new Event('change', {bubbles: true}));
  return true;
}
