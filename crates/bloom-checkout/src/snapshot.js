(() => {
  const visible = e => {
    if (!e.getClientRects().length || !e.checkVisibility({opacityProperty: true, visibilityProperty: true})) return false;
    // Previous steps can remain laid out inside a zero-height clipped panel.
    // They must not consume the control limit ahead of the current form.
    for (let parent = e.parentElement; parent; parent = parent.parentElement) {
      const style = getComputedStyle(parent), clip = parent.getBoundingClientRect();
      if (['hidden', 'clip'].includes(style.overflowX) && clip.width === 0) return false;
      if (['hidden', 'clip'].includes(style.overflowY) && clip.height === 0) return false;
    }
    return true;
  };
  const native = 'a[href],button,input,textarea,select,summary,[role="button"],[role="combobox"],[role="option"],[role="gridcell"],[role="radio"],[role="checkbox"],[role="tab"],[role="link"],[role="menuitem"],[role="switch"],[onclick],[ng-click],[data-ng-click]';
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
  // Cross-origin stylesheets hide their rules, but computed styles remain
  // readable. Ignore children that only inherit their parent's pointer.
  const pointer = e => e.style.cursor === 'pointer' || (pointerSelector !== '' && e.matches(pointerSelector)) ||
    (getComputedStyle(e).cursor === 'pointer' && (!e.parentElement || getComputedStyle(e.parentElement).cursor !== 'pointer'));
  const slotted = e => [...e.querySelectorAll('slot')].flatMap(s => s.assignedNodes({flatten: true}))
    .map(n => n.nodeType === Node.TEXT_NODE ? n.textContent : n.innerText || '').join(' ');
  const text = e => (e.innerText || slotted(e)).replace(/\s+/g, ' ').trim();
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
  // Logo buttons (card brands, banks) name themselves only in image text.
  const pictured = e => [...e.querySelectorAll('img[alt],[title]')].map(i => i.alt || i.title).filter(Boolean).join(' ');
  const namedBy = e => (e.getAttribute('aria-labelledby') || '').split(/\s+/).filter(Boolean)
    .map(id => e.getRootNode().getElementById(id)?.textContent || '').join(' ').trim();
  const label = e => (namedBy(e) || e.getAttribute('aria-label') || (e.labels?.[0] && text(e.labels[0])) || (field(e) ? '' : text(e)) || e.placeholder
    || (field(e) ? caption(e) || e.name : pictured(e)) || '').replace(/\s+/g, ' ').trim();
  // Card and password values never leave the page; checkout redacts saved
  // traveler values before the agent reads anything else.
  const secret = BLOOM_CARD_SECRET;
  // Labels toggle their (often restyled and hidden) radio or checkbox.
  const control = e => e.matches(native) || (e.tagName === 'LABEL' && e.control);
  // Open web components contain ordinary controls outside document selectors.
  const descendants = root => [...root.querySelectorAll('*')].flatMap(e =>
    [e, ...(e.shadowRoot ? descendants(e.shadowRoot) : [])]);
  const candidates = descendants(document.body).filter(e =>
    (control(e) || (pointer(e) && label(e))) &&
    visible(e) && !e.disabled && e.getAttribute('aria-disabled') !== 'true' && e.type !== 'hidden');
  // A styled container around other controls is layout, not a control.
  // Retained earlier steps (for example, a seat map) can sit above the current
  // form. Give current and following controls room before those earlier nodes.
  const order = new Map(candidates.map((e, i) => [e, i]));
  const nodes = candidates.filter(e => control(e) || !candidates.some(o => o !== e && e.contains(o)))
    .sort((a, b) => Number(a.getBoundingClientRect().bottom <= 0) - Number(b.getBoundingClientRect().bottom <= 0))
    .slice(0, 300)
    // Prioritize inclusion, not presentation: repeated passenger fields must
    // retain document order when focusing an input scrolls the page.
    .sort((a, b) => order.get(a) - order.get(b));
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
  const checked = e => {
    const input = e.tagName === 'LABEL' ? e.control : e;
    return ['checkbox', 'radio'].includes(input?.type) ? input.checked : undefined;
  };
  const elements = nodes.map(e => ({
    role: e.tagName.toLowerCase(),
    label: label(e).slice(0, 200),
    context: context(e),
    type: e.type || null,
    value: field(e) && e.type !== 'checkbox' && e.type !== 'radio' && !secret(e, label(e)) ? String(e.value).slice(0, 200) : undefined,
    checked: checked(e),
    options: e.tagName === 'SELECT' ? [...e.options].map(o => ({value: o.value, label: o.text})) : undefined
  }));
  // Child frames are observed separately; their contents are never merged here.
  return {url: location.href === 'about:blank' ? 'about:blank' : location.origin + location.pathname, elements};
})()
