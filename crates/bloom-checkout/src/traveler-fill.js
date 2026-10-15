(async () => {
  const binding = globalThis.__bloomTravelerRefs;
  if (!binding || binding.document !== document || binding.nonce !== nonce || location.origin !== origin) throw Error('Traveler document changed');
  const normalize = s => String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase().trim();
  const filled = [];
  for (const mapping of mapped) {
    const e=binding.refs[mapping.index];
    if (!e?.isConnected || e.ownerDocument !== document || e.disabled || (e.readOnly && !mapping.choice) || !e.getClientRects().length
        || (e.autocomplete || '').split(' ').some(s=>s.startsWith('cc-')) || e.type === 'password') throw Error('Traveler field changed');
    let value=values[mapping.field];
    if (typeof value !== 'string') throw Error('Traveler field unavailable');
    let aliases = [value];
    if (mapping.field === 'born_on' && mapping.part) {
      value = String(Number(value.slice(mapping.part === 'year' ? 0 : mapping.part === 'month' ? 5 : 8,
        mapping.part === 'year' ? 4 : mapping.part === 'month' ? 7 : 10)));
      aliases=[value,value.padStart(2,'0')];
      if (mapping.part === 'month') aliases.push(new Intl.DateTimeFormat(document.documentElement.lang || 'en',{month:'long'}).format(new Date(2020,Number(value)-1,1)));
    }
    if (['nationality','document_country'].includes(mapping.field)) {
      aliases.push(new Intl.DisplayNames([document.documentElement.lang || 'en'],{type:'region'}).of(value));
    }
    if (mapping.field === 'gender') aliases.push(...(value === 'female' ? ['F','Femenino','Mujer'] : value === 'male' ? ['M','Masculino','Hombre'] : ['Unspecified','No especificado']));
    if (mapping.field === 'document_kind') aliases.push(...(value === 'passport' ? ['Passport','Pasaporte'] : ['National ID','DNI','Documento nacional']));
    const spanish = /^es/i.test(document.documentElement.lang || navigator.language);
    if (mapping.radio) {
      // `e` is the group: click the one radio naming this value.
      const radios = [...e.querySelectorAll('input[type=radio]')].filter(r => r.getClientRects().length && !r.disabled
        && aliases.some(a => [r.value, r.labels?.[0]?.innerText, r.getAttribute('aria-label')].some(t => t != null && normalize(a) === normalize(t))));
      if (radios.length !== 1) throw Error('Traveler choice needs private input');
      radios[0].click();
      if (!radios[0].checked) throw Error('Traveler choice needs private input');
      filled.push(mapping.field);
      continue;
    }
    if (mapping.choice) {
      // The site draws its own list. Open it (read-only input) or filter it by
      // typing the name (editable input), then click the one new option naming
      // this value; options already on the page, like a country menu, never count.
      const typed = ['nationality','document_country'].includes(mapping.field) ? aliases.at(-1)
        : mapping.field === 'document_kind' ? (value === 'passport' ? (spanish ? 'Pasaporte' : 'Passport') : (spanish ? 'DNI' : 'National ID'))
        : value === 'female' ? (spanish ? 'Femenino' : 'Female') : value === 'male' ? (spanish ? 'Masculino' : 'Male') : value;
      const names = o => [o.dataset.testValue, o.dataset.value, o.getAttribute('value'), o.innerText].filter(t => t != null).map(normalize);
      const matches = o => names(o).some(t => aliases.some(a => normalize(a) === t)
        || (!e.readOnly && t.startsWith(normalize(typed)) && /^\W/.test(t.slice(normalize(typed).length))));
      const candidates = () => [...document.querySelectorAll('[role=option],li,div,span,button')]
        .filter(o => o !== e && !o.contains(e) && o.getClientRects().length && matches(o));
      // A read-only list may already sit in the page, hidden or clipped.
      const before = new Set(e.readOnly ? [] : candidates());
      if (e.readOnly) e.click();
      else {
        e.focus();e.select();
        if (document.activeElement !== e || !document.execCommand('insertText',false,typed)) throw Error('Traveler input unsupported');
      }
      let option;
      for (let i = 0; i < 30 && !option; i++) {
        await new Promise(r => setTimeout(r, 100));
        const found = candidates().filter(o => !before.has(o));
        const deepest = found.filter(o => !found.some(x => x !== o && o.contains(x)));
        if (deepest.length > 1) throw Error('Traveler choice needs private input');
        option = deepest[0];
      }
      if (!option || !e.isConnected || location.origin !== origin) throw Error('Traveler choice needs private input');
      option.click();
      await new Promise(r => setTimeout(r, 200));
      const taken = normalize(e.value);
      if (!aliases.some(a => normalize(a) === taken) && taken !== normalize(option.innerText)) throw Error('Traveler choice needs private input');
    } else if (e.tagName === 'SELECT') {
      const matches = [...e.options].filter(o=>!o.disabled && aliases.some(a=>normalize(a)===normalize(o.value) || normalize(a)===normalize(o.text)));
      if (matches.length !== 1) throw Error('Traveler choice needs private input');
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set.call(e,matches[0].value);
      e.dispatchEvent(new Event('input',{bubbles:true}));
    } else if (e.type === 'date') {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,value);
      e.dispatchEvent(new Event('input',{bubbles:true}));
    } else {
      e.focus();e.select();
      if (document.activeElement !== e || !e.isConnected || !document.execCommand('insertText',false,value)) throw Error('Traveler input unsupported');
    }
    e.dispatchEvent(new Event('change',{bubbles:true}));filled.push(mapping.field);
  }
  return {filled:[...new Set(filled)]};
})()
