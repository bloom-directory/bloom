(e, label) => {
  if (label === undefined) {
    const namedBy = (e.getAttribute('aria-labelledby') || '').split(/\s+/).filter(Boolean)
      .map(id => e.getRootNode().getElementById(id)?.textContent || '').join(' ');
    label = namedBy || e.getAttribute('aria-label') || e.labels?.[0]?.innerText || e.placeholder || '';
    // The same small, single-field captions used in shopping snapshots.
    if (!label || /^\d[\d\s]*$/.test(label)) for (let parent = e.parentElement, depth = 0; parent && depth < 4; parent = parent.parentElement, depth++) {
      if (parent.querySelectorAll('input,select,textarea').length > 1) break;
      const text = (parent.innerText || '').trim();
      if (text) { label = text.length <= 60 ? text : ''; break; }
    }
  }
  const text = `${e.name || ''} ${e.id || ''} ${label || ''}`.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  return e.type === 'password' || (e.autocomplete || '').split(/\s+/).some(token => token.startsWith('cc-')) || /card|tarjeta|cvc|cvv|security|seguridad|password|contrase|\bso the\b|\bma bao mat\b|\bten chu the\b/i.test(text);
}
