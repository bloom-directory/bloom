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
  const label = e => (e.getAttribute('aria-label') || e.labels?.[0]?.innerText || e.innerText || e.placeholder || '').replace(/\s+/g, ' ').trim();
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
    options: e.tagName === 'SELECT' ? [...e.options].map(o => ({value: o.value, label: o.text})) : undefined
  }));
  // Values and child frames are deliberately absent from the shopping projection.
  return {url: location.href === 'about:blank' ? 'about:blank' : location.origin + location.pathname, elements};
})()
