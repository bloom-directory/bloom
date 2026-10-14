(() => {
  const normalize = s => (s || '').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
  const refs = [];
  const mapped = [];
  for (const e of document.querySelectorAll('input,select,textarea')) {
    if (!e.getClientRects().length || getComputedStyle(e).visibility !== 'visible' || e.disabled
        || e.readOnly || e.type === 'hidden' || e.type === 'password') continue;
    const ac = (e.autocomplete || '').split(' ').at(-1);
    // Some sites caption a field with plain text beside it rather than a
    // <label>: use the text of the smallest wrapper holding only this field.
    let caption = '';
    for (let a = e.parentElement, depth = 0; a && depth < 4; a = a.parentElement, depth++) {
      if (a.querySelectorAll('input,select,textarea').length > 1) break;
      const text = (a.innerText || '').trim();
      if (text) { if (text.length <= 60) caption = text; break; }
    }
    const label = normalize([e.getAttribute('aria-label'),e.labels?.[0]?.innerText,e.placeholder,e.name,e.id,caption].filter(Boolean).join(' '));
    if (ac?.startsWith('cc-') || /card|tarjeta|cvc|security code|password|contrasena/.test(label)) continue;
    if (/full.?name|nombre completo|nombre.*apellido/.test(label)) continue;
    let field, part;
    if (ac === 'given-name' || /first.?name|given.?name|primer nombre|(?:^|\W)nombre(?:s|\(s\))?(?:\W|$)/.test(label)) field = 'given_name';
    else if (ac === 'family-name' || /last.?name|family.?name|surname|apellido/.test(label)) field = 'family_name';
    else if (ac?.startsWith('bday') || /birth|nacimiento/.test(label)) {
      field='born_on';part=ac?.split('-')[1];
      if (!part) part = /year|ano/.test(label) ? 'year' : /month|mes/.test(label) ? 'month' : /day|dia/.test(label) ? 'day' : undefined;
      if (!part && e.type !== 'date') continue;
    } else if (/nationality|nacionalidad/.test(label)) field='nationality';
    else if (/issuing.?country|pais emisor|document.?country/.test(label)) field='document_country';
    else if (/document.?type|tipo de documento|document.?kind/.test(label)) field='document_kind';
    else if (/passport.?number|document.?number|numero.*documento|numero.*pasaporte/.test(label)) field='document_number';
    else if (/document.*expiry|passport.*expiry|vencimiento/.test(label) && e.type === 'date') field='document_expiry';
    else if (ac === 'sex' || /gender|genero|sexo/.test(label)) field='gender';
    else if (ac === 'email' || e.type === 'email' || /email|e-mail|correo/.test(label)) field='email';
    else if (ac === 'tel' || e.type === 'tel' || /phone|telefono/.test(label)) {
      if (/country|area|prefijo|codigo|extension/.test(label) || e.tagName === 'SELECT') continue;
      field='phone';
    }
    if (!field) continue;
    mapped.push({field,part,index:refs.length});refs.push(e);
  }
  if (mapped.length > 40) throw Error('Ambiguous traveler form');
  for (const field of ['given_name','family_name','gender','nationality','document_kind','document_number','document_country','document_expiry','phone']) {
    if (mapped.filter(m=>m.field===field).length > 1) throw Error('Multiple traveler forms require private selection');
  }
  const birth = mapped.filter(m=>m.field==='born_on');
  if (new Set(birth.map(m=>m.part || 'date')).size !== birth.length) throw Error('Ambiguous birth fields');
  globalThis.__bloomTravelerRefs = {document,refs,nonce:globalThis.__bloomTravelerNonce};
  return {origin:location.origin,mapped};
})()
