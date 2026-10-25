(index, kind, value, savedField) => {
  const e = globalThis.__bloomRefs?.[index];
  if (!e || !e.isConnected || e.disabled || e.getAttribute('aria-disabled') === 'true' || !e.getClientRects().length) throw Error('stale');
  const guardPayment = () => {
    const namedBy = (e.getAttribute('aria-labelledby') || '').split(/\s+/).filter(Boolean)
      .map(id => e.getRootNode().getElementById(id)?.textContent || '').join(' ');
    const slotted = [...e.querySelectorAll('slot')].flatMap(s => s.assignedNodes({flatten: true}))
      .map(n => n.nodeType === Node.TEXT_NODE ? n.textContent : n.innerText || '').join(' ');
    const labels = [e.innerText, e.value, e.getAttribute('aria-label'), namedBy, slotted];
    if (labels.some(label => BLOOM_PAY_WORDS.test((label || '').replace(/\s+/g, ' ').trim()))) throw Error('payment requires approval');
  };
  if (kind === 'click') {
    guardPayment();
    // Styled labels can cancel clicks on the label itself. Activate their
    // associated checkbox/radio, as clicking the visible control would.
    const target = e.tagName === 'LABEL' && ['checkbox', 'radio'].includes(e.control?.type) ? e.control : e;
    if (target.disabled) throw Error('stale');
    // Custom lists often open on mouse-down, which HTMLElement.click omits.
    // Keep the whole interaction bound to this node, not screen coordinates.
    if (target === e) {
      target.scrollIntoView({block: 'nearest', inline: 'nearest'});
      const rect = target.getBoundingClientRect();
      const mouse = {bubbles: true, composed: true, cancelable: true, view: window, button: 0,
        clientX: rect.x + rect.width / 2, clientY: rect.y + rect.height / 2};
      if (target.dispatchEvent(new MouseEvent('mousedown', {...mouse, buttons: 1}))) target.focus?.();
      if (!target.isConnected || target.disabled) throw Error('stale');
      guardPayment();
      target.dispatchEvent(new MouseEvent('mouseup', {...mouse, buttons: 0}));
      if (!target.isConnected || target.disabled) throw Error('stale');
      guardPayment();
    }
    target.click();
  } else {
    if ((e.autocomplete || '').split(' ').some(s => s.startsWith('cc-'))) throw Error('private payment input');
    if (kind === 'select' && e.tagName !== 'SELECT') throw Error('wrong field');
    if (kind === 'type' && !['INPUT', 'TEXTAREA'].includes(e.tagName)) throw Error('wrong field');
    if (savedField) (globalThis.__bloomPrivateFields ||= new WeakMap()).set(e, savedField);
    if (kind === 'type') {
      // Native editing updates controlled inputs and fires their input
      // handlers. Focus and insertion run in one call so navigation cannot
      // redirect a later insertion.
      e.focus();
      if (!e.isConnected || e.getRootNode().activeElement !== e || (e.autocomplete || '').split(' ').some(s => s.startsWith('cc-'))) throw Error('stale');
      e.select();
      if (!e.isConnected || e.getRootNode().activeElement !== e || (e.autocomplete || '').split(' ').some(s => s.startsWith('cc-'))) throw Error('stale');
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
