(async () => {
  const binding = globalThis.__bloomTravelerRefs;
  if (!binding || binding.document !== document || binding.nonce !== nonce || location.origin !== origin) throw Error('Traveler document changed');
  const normalize = s => String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase().trim();
  const filled = [], skipped = [];
  // A site list that does not take the value is left for the agent's type_traveler.
  class Skip extends Error {}
  // Date widgets may clear the day when the month or year changes: day last.
  const order = [...mapped.filter(m => !(m.field === 'born_on' && m.part === 'day')), ...mapped.filter(m => m.field === 'born_on' && m.part === 'day')];
  for (const mapping of order) {
  try {
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
    if (mapping.field === 'phone' && mapping.part) {
      // Split by how the number was saved: "+54 9 11 2345-6789" is country,
      // mobile prefix, area and local number.
      const groups = value.trim().split(/[\s.-]+/).map(g=>g.replace(/\D/g,'')).filter(Boolean);
      if (value.trim().startsWith('+')) groups.shift();
      if (groups[0] === '9' && groups.length > 2) groups.shift();
      if (groups.length < 2) throw new Skip('phone saved without an area code group');
      value = mapping.part === 'area' ? groups[0] : groups.slice(1).join('');
    } else if (mapping.field === 'phone' && value.startsWith('+')) {
      // A country prefix shown by a neighbouring field ("Argentina (+54)")
      // means the number goes in without it.
      for (let a = e.parentElement, depth = 0; a && depth < 4; a = a.parentElement, depth++) {
        const shown = [...a.querySelectorAll('input,select')].filter(o => o !== e)
          .map(o => o.tagName === 'SELECT' ? o.selectedOptions[0]?.text : o.value).join(' ') + ' ' + a.innerText;
        const code = shown.match(/\(\+?(\d{1,3})\)|(?:^|\s)\+(\d{1,3})\b/);
        if (!code) continue;
        const digits = code[1] || code[2];
        if (value.replace(/[^\d+]/g,'').startsWith('+' + digits)) value = value.replace(/[^\d+]/g,'').slice(digits.length + 1);
        break;
      }
    }
    const spanish = /^es/i.test(document.documentElement.lang || navigator.language);
    if (mapping.radio) {
      // `e` is the group: click the one radio naming this value.
      const radios = [...e.querySelectorAll('input[type=radio]')].filter(r => r.getClientRects().length && !r.disabled
        && aliases.some(a => [r.value, r.labels?.[0]?.innerText, r.getAttribute('aria-label')].some(t => t != null && normalize(a) === normalize(t))));
      if (radios.length !== 1) throw new Skip(`radio ambiguous: ${radios.length} options`);
      radios[0].click();
      if (!radios[0].checked) throw new Skip('radio not checked');
      filled.push(mapping.field);
      continue;
    }
    if (mapping.choice) {
      // The site draws its own list. Open it (read-only input) or filter it by
      // typing the name (editable input), then click the one new option naming
      // this value; options already on the page, like a country menu, never count.
      let typed = mapping.field === 'born_on' ? value : ['nationality','document_country'].includes(mapping.field) ? aliases.at(-1)
        : mapping.field === 'document_kind' ? (value === 'passport' ? (spanish ? 'Pasaporte' : 'Passport') : (spanish ? 'DNI' : 'National ID'))
        : value === 'female' ? (spanish ? 'Femenino' : 'Female') : value === 'male' ? (spanish ? 'Masculino' : 'Male') : value;
      const names = o => [o.dataset.testValue, o.dataset.value, o.getAttribute('value'), o.innerText].filter(t => t != null).map(normalize);
      // One-letter codes ("F") also label seat-map columns and the like; a
      // date list's "7" is the day.
      const word = (t, a) => a.length >= 3 && t.length <= 60
        && new RegExp(`(^|\\W)${a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(\\W|$)`).test(t);
      const matches = o => names(o).some(t => aliases.some(a => (normalize(a).length > 1 || mapping.part) && (normalize(a) === t || word(t, normalize(a))))
        || (!e.readOnly && typed && t.startsWith(normalize(typed)) && /^\W/.test(t.slice(normalize(typed).length))));
      // Real list options, when the site marks them, beat any other matching text.
      const optionLike = o => o.matches('[role=option]') || /option/i.test(`${o.id} ${o.className}`);
      const candidates = () => {
        const found = [...document.querySelectorAll('[role=option],li,div,span,button')]
          .filter(o => o !== e && !o.contains(e) && o.getClientRects().length && matches(o));
        return found.some(optionLike) ? found.filter(optionLike) : found;
      };
      // A read-only list may already sit in the page, hidden or clipped.
      const before = new Set(e.readOnly || mapping.listOpen ? [] : candidates());
      // A month list may use numbers or names: try the number, then the name.
      // listOpen: checkout already opened the list with a real click.
      const attempts = mapping.listOpen ? [null] : e.readOnly ? [typed] : mapping.part === 'month' ? [typed, aliases.at(-1)]
        : mapping.part === 'day' ? [typed, typed.padStart(2,'0')] : [typed];
      // A list that searches from the start of each option ("PAS - Pasaporte")
      // finds nothing for the name: last, clear the box and open the whole list.
      if (!e.readOnly) attempts.push(null);
      let option;
      for (const attempt of attempts) {
        typed = attempt ?? '';
        if (e.readOnly && !mapping.listOpen) e.click();
        else if (attempt === null) {
          if (!mapping.listOpen) { e.focus(); e.select(); document.execCommand('delete'); }
          // Open the list one way at a time: some toggle on each event, so
          // stop as soon as options show.
          let toggle;
          for (let a = e.parentElement, depth = 0; a && depth < 4 && !toggle; a = a.parentElement, depth++)
            toggle = [...a.querySelectorAll('button,[role=button]')].find(b => !b.contains(e) && b.getClientRects().length);
          // Clearing a search box may already list every option.
          for (const open of [() => {}, () => e.click(),
                              () => e.dispatchEvent(new KeyboardEvent('keydown', {key: 'ArrowDown', code: 'ArrowDown', keyCode: 40, bubbles: true})),
                              () => toggle?.click(),
                              () => toggle?.dispatchEvent(new MouseEvent('mousedown', {bubbles: true}))]) {
            open();
            await new Promise(r => setTimeout(r, 300));
            if (candidates().some(o => !before.has(o))) break;
          }
        } else {
          e.focus();e.select();
          if (document.activeElement !== e || !document.execCommand('insertText',false,typed)) throw Error('Traveler input unsupported');
        }
        // Lists re-render while they filter: take an option only once it
        // is the same element on two checks in a row.
        let seen;
        for (let i = 0; i < 25 && !option; i++) {
          await new Promise(r => setTimeout(r, 100));
          const found = candidates().filter(o => !before.has(o));
          const deepest = found.filter(o => !found.some(x => x !== o && o.contains(x)));
          if (deepest.length > 1) { seen = undefined; continue; }
          if (deepest[0] && deepest[0] === seen) option = seen;
          seen = deepest[0];
        }
        if (!option && seen === undefined && candidates().filter(o => !before.has(o)).length > 1) throw new Skip('ambiguous options');
        if (option) break;
      }
      if (!option || !e.isConnected || location.origin !== origin) throw new Skip('option not found');
      option.click();
      await new Promise(r => setTimeout(r, 200));
      // Some lists show the choice in an element beside an emptied input.
      const chosen = normalize(option.innerText);
      let shownBeside = false;
      for (let a = e.parentElement, depth = 0; a && depth < 4 && !shownBeside; a = a.parentElement, depth++) {
        const shown = normalize(a.innerText);
        shownBeside = shown === chosen || aliases.some(x => normalize(x).length > 1 && normalize(x) === shown);
      }
      const taken = normalize(e.value);
      // Typed text alone proves nothing: an editable list must also have closed.
      const closed = !option.isConnected || !option.getClientRects().length;
      // A field may show the option's code ("PAS" for "PAS - Pasaporte").
      const abbreviated = taken.length > 1 && chosen.startsWith(taken) && /^\W/.test(chosen.slice(taken.length));
      if ((!e.readOnly && !closed) || (!aliases.some(a => normalize(a) === taken) && taken !== chosen && !abbreviated && !shownBeside)) throw new Skip('not taken by the field');
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
      // Some forms only accept a value after a key release and leaving the field.
      e.dispatchEvent(new KeyboardEvent('keyup',{key:value.slice(-1),bubbles:true}));
    }
    e.dispatchEvent(new Event('change',{bubbles:true}));
    // Booking sites commonly validate only after a field has been touched and
    // left. Do that before claiming the saved value was accepted.
    if (document.activeElement === e) e.blur();
    await new Promise(r => setTimeout(r, 25));
    if (!e.checkValidity() || e.getAttribute('aria-invalid') === 'true') throw new Skip('field rejected by page');
    filled.push(mapping.field);
  } catch (error) {
    if (!(error instanceof Skip)) throw error;
    const e = binding.refs[mapping.index];
    if (e?.tagName === 'INPUT' && !e.readOnly && e.value && document.activeElement === e) { e.select(); document.execCommand('delete'); }
    skipped.push(`${mapping.field}${mapping.part ? ' ' + mapping.part : ''}: ${error.message}`);
  }
  }
  return {filled:[...new Set(filled)],skipped};
})()
