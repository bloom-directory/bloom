(index, kind, value, savedField) => {
  const e = globalThis.__bloomRefs?.[index];
  if (!e || !e.isConnected || e.disabled || e.getAttribute('aria-disabled') === 'true' || !e.getClientRects().length) throw Error('stale');
  const guardPayment = () => {
    const targets = [e];
    // Clicking a label can activate its submit/button control, even when that
    // control is hidden and the label itself says only "Continue".
    if (e.tagName === 'LABEL' && e.control?.matches('button,input[type=submit],input[type=button],input[type=image]')) targets.push(e.control);
    for (const target of targets) {
      if (target.disabled || target.getAttribute('aria-disabled') === 'true') throw Error('stale');
      const namedBy = (target.getAttribute('aria-labelledby') || '').split(/\s+/).filter(Boolean)
        .map(id => target.getRootNode().getElementById(id)?.textContent || '').join(' ');
      const slotted = [...target.querySelectorAll('slot')].flatMap(s => s.assignedNodes({flatten: true}))
        .map(n => n.nodeType === Node.TEXT_NODE ? n.textContent : n.innerText || '').join(' ');
      const labels = [target.innerText, target.value, target.getAttribute('aria-label'), target.getAttribute('alt'), namedBy, slotted];
      if (labels.some(label => BLOOM_PAY_WORDS.test((label || '').replace(/\s+/g, ' ').trim()))) throw Error('payment requires approval');
    }
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
    const privateInput = globalThis.__bloomPrivateInput;
    if (typeof privateInput !== 'function') throw Error('stale');
    if ((e.autocomplete || '').split(' ').some(s => s.startsWith('cc-')) || (kind === 'type' && privateInput(e))) throw Error('payment requires approval');
    if (kind === 'select' && e.tagName !== 'SELECT') throw Error('wrong field');
    if (kind === 'select' && ![...e.options].some(o => o.value === value && !o.disabled && !o.closest('optgroup[disabled]'))) throw Error('option unavailable');
    if (kind === 'type' && !['INPUT', 'TEXTAREA'].includes(e.tagName)) throw Error('wrong field');
    if (savedField) (globalThis.__bloomPrivateFields ||= new WeakMap()).set(e, savedField);
    if (kind === 'type') {
      // Native editing updates controlled inputs and fires their input
      // handlers. Focus and insertion run in one call so navigation cannot
      // redirect a later insertion.
      e.focus();
      if (!e.isConnected || e.getRootNode().activeElement !== e || privateInput(e)) throw Error('stale');
      e.select();
      if (!e.isConnected || e.getRootNode().activeElement !== e || privateInput(e)) throw Error('stale');
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
