(() => {
  const normalize = s => (s || '').normalize('NFD').replace(/[̀-ͯ]/g,'').toLowerCase();
  const refs = [];
  const mapped = [];
  const radioGroups = new Set();
  const choices = ['gender','nationality','document_kind','document_country'];
  for (const e of document.querySelectorAll('input,select,textarea')) {
    if (!e.getClientRects().length || getComputedStyle(e).visibility !== 'visible' || e.disabled
        || e.type === 'hidden' || e.type === 'password') continue;
    // Fill only what is still empty: earlier steps of a one-page booking stay
    // in the document, and nothing already entered is overwritten.
    if (e.type !== 'radio' && e.type !== 'checkbox' && e.value) continue;
    // Card-holder name, document and email belong to the payer, not the traveler.
    let payer = false;
    for (let a = e.parentElement; a && !payer; a = a.parentElement) {
      const text = normalize(a.innerText);
      // Stop at the payment block: a few fields and a short text.
      const fields = [...a.querySelectorAll('input,select')].filter(f => f.type !== 'hidden' && f.getClientRects().length);
      if (text.length > 600 || fields.length > 5) break;
      payer = /titular|cardholder|card holder/.test(text);
    }
    if (payer) continue;
    const ac = (e.autocomplete || '').split(' ').at(-1);
    // Some sites caption a field with plain text beside it rather than a
    // <label>: use the text of the smallest wrapper holding only this field.
    let caption = '';
    for (let a = e.parentElement, depth = 0; a && depth < 4; a = a.parentElement, depth++) {
      if (a.querySelectorAll('input,select,textarea').length > 1) break;
      const text = (a.innerText || '').trim();
      if (text) { if (text.length <= 60) caption = text; break; }
    }
    // A short caption shared by several fields: "Fecha de Nacimiento Día Mes Año"
    // or "Género Femenino Masculino".
    let group, groupText = '';
    for (let a = e.parentElement, depth = 0; a && depth < 8; a = a.parentElement, depth++) {
      const text = normalize(a.innerText);
      if (text.length > 80) break;
      if (/nacimiento|birth|genero|gender|sexo/.test(text)) { group = a; groupText = text; break; }
    }
    const combobox = e.getAttribute('role') === 'combobox' || e.hasAttribute('aria-autocomplete') || /^react-select-/.test(e.id);
    const label = normalize([e.getAttribute('aria-label'),e.labels?.[0]?.innerText,e.placeholder,e.name,e.id,caption].filter(Boolean).join(' '));
    if (ac?.startsWith('cc-') || /card|tarjeta|cvc|security code|password|contrasena/.test(label)) continue;
    if (/full.?name|nombre completo|nombre.*apellido/.test(label)) continue;
    let field, part;
    if (e.type === 'radio') {
      // One mapping per radio group; the fill picks the option naming the value.
      if (!group || !/genero|gender|sexo/.test(groupText) || radioGroups.has(group)
          || group.querySelector('input[type=radio]:checked')) continue;
      radioGroups.add(group);
      mapped.push({field:'gender',radio:true,index:refs.length});refs.push(group);
      continue;
    }
    const datePart = /^(day|dia)\b/.test(label) ? 'day' : /^(month|mes)\b/.test(label) ? 'month' : /^(year|ano)\b/.test(label) ? 'year' : undefined;
    if (ac === 'given-name' || /first.?name|given.?name|primer nombre|(?:^|\W)nombre(?:s|\(s\))?(?:\W|$)/.test(label)) field = 'given_name';
    else if (ac === 'family-name' || /last.?name|family.?name|surname|apellido/.test(label)) field = 'family_name';
    else if (ac?.startsWith('bday') || /birth|nacimiento/.test(label) || (datePart && /nacimiento|birth/.test(groupText))) {
      field='born_on';part=ac?.split('-')[1] || datePart;
      if (!part) part = /year|ano/.test(label) ? 'year' : /month|mes/.test(label) ? 'month' : /day|dia/.test(label) ? 'day' : undefined;
      if (!part && e.type !== 'date') continue;
    } else if (/nationality|nacionalidad/.test(label)) field='nationality';
    else if (/issuing.?country|pais emisor|pais de emision|document.?country/.test(label)) field='document_country';
    else if (/document.?type|tipo de documento|document.?kind/.test(label)) field='document_kind';
    else if (/passport.?number|document.?number|(numero|nro)\.?.*documento|(numero|nro)\.?.*pasaporte/.test(label)) field='document_number';
    else if (/document.*expiry|passport.*expiry|vencimiento/.test(label) && e.type === 'date') field='document_expiry';
    else if (ac === 'sex' || /gender|genero|sexo/.test(label)) field='gender';
    else if (ac === 'email' || e.type === 'email' || /email|e-mail|correo/.test(label)) field='email';
    else if (/area.?code|cod\.? ?area|areacode/.test(label)) { field='phone'; part='area'; }
    else if (ac === 'tel' || e.type === 'tel' || /phone|telefono/.test(label)) {
      if (/country|prefijo|codigo|extension/.test(label) || e.tagName === 'SELECT') continue;
      field='phone';
    }
    if (!field) continue;
    // Sites draw these lists themselves: a read-only input opens on click, an
    // editable one filters as the name is typed. Either way an option is clicked.
    const choice = e.tagName === 'INPUT' && (choices.includes(field) || combobox);
    if (e.readOnly && !choice) continue;
    mapped.push({field,part,choice,index:refs.length});refs.push(e);
  }
  if (mapped.length > 40) throw Error('Ambiguous traveler form');
  for (const field of ['given_name','family_name','gender','nationality','document_kind','document_number','document_country','document_expiry','phone']) {
    if (new Set(mapped.filter(m=>m.field===field).map(m=>m.part)).size !== mapped.filter(m=>m.field===field).length) throw Error('Multiple traveler forms require private selection');
  }
  // A separate area-code field means the phone field takes the local number.
  if (mapped.some(m=>m.field==='phone' && m.part==='area')) for (const m of mapped) if (m.field==='phone' && !m.part) m.part='local';
  const birth = mapped.filter(m=>m.field==='born_on');
  if (new Set(birth.map(m=>m.part || 'date')).size !== birth.length) throw Error('Ambiguous birth fields');
  globalThis.__bloomTravelerRefs = {document,refs,nonce:globalThis.__bloomTravelerNonce};
  return {origin:location.origin,mapped};
})()
