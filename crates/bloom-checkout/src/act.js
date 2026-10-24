(index, kind, value) => {
  const e = globalThis.__bloomRefs?.[index];
  if (!e || !e.isConnected || e.disabled || e.getAttribute('aria-disabled') === 'true' || !e.getClientRects().length) throw Error('stale');
  const label = (e.innerText || e.value || e.getAttribute('aria-label') || '').replace(/\s+/g, ' ').trim();
  if (kind === 'click' && BLOOM_PAY_WORDS.test(label)) throw Error('payment requires approval');
  if (kind === 'click') {
    // Styled labels can cancel clicks on the label itself. Activate their
    // associated checkbox/radio, as clicking the visible control would.
    const target = e.tagName === 'LABEL' && ['checkbox', 'radio'].includes(e.control?.type) ? e.control : e;
    if (target.disabled) throw Error('stale');
    target.click();
  } else {
    if ((e.autocomplete || '').split(' ').some(s => s.startsWith('cc-'))) throw Error('private payment input');
    if (kind === 'select' && e.tagName !== 'SELECT') throw Error('wrong field');
    if (kind === 'type' && !['INPUT', 'TEXTAREA'].includes(e.tagName)) throw Error('wrong field');
    if (kind === 'type') {
      // Native editing updates controlled inputs and fires their input
      // handlers. Focus and insertion run in one call so navigation cannot
      // redirect a later insertion.
      e.focus();
      if (!e.isConnected || document.activeElement !== e || (e.autocomplete || '').split(' ').some(s => s.startsWith('cc-'))) throw Error('stale');
      e.select();
      if (!e.isConnected || document.activeElement !== e || (e.autocomplete || '').split(' ').some(s => s.startsWith('cc-'))) throw Error('stale');
      if (!document.execCommand('insertText', false, value)) throw Error('input unsupported');
      e.dispatchEvent(new KeyboardEvent('keyup', {key: value.slice(-1), bubbles: true}));
    } else {
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set.call(e, value);
      e.dispatchEvent(new Event('input', {bubbles: true}));
    }
    e.dispatchEvent(new Event('change', {bubbles: true}));
  }
  return {state: 'acted'};
}
