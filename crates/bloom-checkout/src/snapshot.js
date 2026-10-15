(() => {
  const visible = e => e.getClientRects().length && e.checkVisibility({opacityProperty: true, visibilityProperty: true});
  const native = 'a[href],button,input,textarea,select,summary,[role="button"],[role="option"],[role="gridcell"],[role="radio"],[role="checkbox"],[role="tab"],[role="link"],[role="menuitem"],[role="switch"],[onclick],[ng-click],[data-ng-click]';
  // Script frameworks attach click handlers invisibly. A pointer cursor that a
  // page stylesheet assigns to the element itself marks those controls.
  const pointerRules = [];
  const collect = rules => {
    for (const rule of rules) {
      try { if (rule.cssRules) collect(rule.cssRules); } catch {}
      if (rule.selectorText && rule.style?.cursor === 'pointer') pointerRules.push(rule.selectorText);
    }
  };
  for (const sheet of document.styleSheets) { try { collect(sheet.cssRules); } catch {} }
  const valid = pointerRules.filter(s => { try { document.body.matches(s); return true; } catch { return false; } });
  const pointerSelector = valid.join(',');
  const pointer = e => e.style.cursor === 'pointer' || (pointerSelector !== '' && e.matches(pointerSelector));
  const text = e => (e.innerText || '').replace(/\s+/g, ' ').trim();
  const field = e => e.matches('input,select,textarea');
  // Some sites caption a field with text beside it instead of a <label>: use
  // the text of the smallest wrapper holding only this field.
  const caption = e => {
    for (let a = e.parentElement, depth = 0; a && depth < 4; a = a.parentElement, depth++) {
      if (a.querySelectorAll('input,select,textarea').length > 1) return '';
      const around = text(a);
      if (around) return around.length <= 60 ? around : '';
    }
    return '';
  };
  const label = e => (e.getAttribute('aria-label') || e.labels?.[0]?.innerText || (field(e) ? '' : e.innerText) || e.placeholder
    || (field(e) ? caption(e) || e.name : '') || '').replace(/\s+/g, ' ').trim();
  // Card and password values never leave the page; checkout redacts saved
  // traveler values before the agent reads anything else.
  const secret = e => e.type === 'password' || /^cc-/.test((e.autocomplete || '').split(' ').at(-1))
    || /card|tarjeta|cvc|cvv|security|seguridad|password|contrase/i.test(`${e.name} ${e.id} ${label(e)}`);
  // Labels toggle their (often restyled and hidden) radio or checkbox.
  const control = e => e.matches(native) || (e.tagName === 'LABEL' && e.control);
  const candidates = [...document.querySelectorAll('body *')].filter(e =>
    (control(e) || (pointer(e) && label(e))) &&
    visible(e) && !e.disabled && e.getAttribute('aria-disabled') !== 'true' && e.type !== 'hidden');
  // A styled container around other controls is layout, not a control.
  const nodes = candidates.filter(e => control(e) || !candidates.some(o => o !== e && e.contains(o))).slice(0, 300);
  // Repeated controls such as fare buttons or calendar days need their card
  // or month: the largest short block around the control.
  const context = e => {
    let found;
    for (let a = e.parentElement; a && a !== document.body; a = a.parentElement) {
      const around = text(a);
      if (around.length > 240) break;
      if (around !== label(e)) found = around;
    }
    return found;
  };
  globalThis.__bloomRefs = nodes;
  const elements = nodes.map(e => ({
    role: e.tagName.toLowerCase(),
    label: label(e).slice(0, 200),
    context: context(e),
    type: e.type || null,
    value: field(e) && e.type !== 'checkbox' && e.type !== 'radio' && !secret(e) ? String(e.value).slice(0, 200) : undefined,
    checked: e.type === 'checkbox' || e.type === 'radio' ? e.checked : undefined,
    options: e.tagName === 'SELECT' ? [...e.options].map(o => ({value: o.value, label: o.text})) : undefined
  }));
  // Child frames are observed separately; their contents are never merged here.
  return {url: location.href === 'about:blank' ? 'about:blank' : location.origin + location.pathname, elements};
})()
