(e, label) => {
  const text = `${e.name || ''} ${e.id || ''} ${label || ''}`.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  return e.type === 'password' || /^cc-/.test((e.autocomplete || '').split(' ').at(-1)) || /card|tarjeta|cvc|cvv|security|seguridad|password|contrase|\bso the\b|\bma bao mat\b|\bten chu the\b/i.test(text);
}
