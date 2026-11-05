(async () => {
  const binding = globalThis.__bloomTravelerRefs;
  if (!binding || binding.document !== document || binding.nonce !== nonce || location.origin !== origin) throw Error('Traveler document changed');
  const normalize = s => String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase().trim();
  const filled = [], skipped = [];
  // A site list that does not take the value is left for the agent's type_traveler.
  class Skip extends Error {}
  const shownValue = e => e.tagName === 'SELECT' ? e.selectedOptions[0]?.text || ''
    : e.value || e.getAttribute('placeholder') || e.getAttribute('aria-label') || '';
  const callingCode = e => {
    const text = shownValue(e).trim();
    return text.match(/^\+?(\d{1,3})\s+\p{L}/u)?.[1]
      || text.match(/\(\+?(\d{1,3})\)/)?.[1]
      || text.match(/^\+(\d{1,3})$/)?.[1];
  };
  const phonePrefix = e => {
    for (let a = e.parentElement, depth = 0; a && depth < 4; a = a.parentElement, depth++) {
      const fields = [...a.querySelectorAll('input,select')].filter(o => o !== e && !o.disabled
        && o.getClientRects().length && callingCode(o));
      if (fields.length) return fields;
    }
    return [];
  };
  const fixedPhoneCode = e => {
    for (let a = e.parentElement, depth = 0; a && depth < 4; a = a.parentElement, depth++) {
      const codes = [...new Set([...a.innerText.matchAll(/\(\+?(\d{1,3})\)|\+(\d{1,3})\b/g)]
        .map(m => m[1] || m[2]))];
      if (codes.length) return codes.length === 1 ? codes[0] : 'ambiguous';
    }
  };
  // Date widgets may clear the day when the month or year changes: day last.
  const dateDay = m => ['born_on','document_expiry'].includes(m.field) && m.part === 'day';
  const order = [...mapped.filter(m => !dateDay(m)), ...mapped.filter(dateDay)].flatMap(m => {
    if (m.field !== 'phone' || !values.phone_country || !values.phone_calling_code) return [m];
    const prefixes = phonePrefix(binding.refs[m.index]);
    if (prefixes.length !== 1) return [m];
    const prefix = prefixes[0];
    if (callingCode(prefix) === values.phone_calling_code) return [m];
    const index = binding.refs.push(prefix) - 1;
    return [{field:'phone',part:'country',index,
      choice:prefix.tagName === 'INPUT' && (prefix.readOnly || prefix.getAttribute('role') === 'combobox')}, m];
  });
  for (const mapping of order) {
  try {
    const e=binding.refs[mapping.index];
    // choose is decided from the element before the readonly guard: a site
    // list is often a read-only input that checkout already opened.
    if (mapping.choose && e) {
      mapping.choice = e.tagName === 'INPUT';
      mapping.listOpen = mapping.choice;
    }
    if (!e?.isConnected || e.ownerDocument !== document || e.disabled || (e.readOnly && !mapping.choice) || !e.getClientRects().length
        || (e.autocomplete || '').split(' ').some(s=>s.startsWith('cc-')) || e.type === 'password') throw Error('Traveler field changed');
    let value=values[mapping.field];
    if (typeof value !== 'string') throw Error('Traveler field unavailable');
    (globalThis.__bloomPrivateFields ||= new WeakMap()).set(e, mapping.field + (mapping.part ? '_' + mapping.part : ''));
    let aliases = [value];
    if (mapping.field === 'phone' && mapping.part !== 'country' && values.phone_calling_code) {
      const prefixes = phonePrefix(e);
      if (prefixes.length > 1) throw new Skip('phone calling code is ambiguous');
      if (prefixes.length && callingCode(prefixes[0]) !== values.phone_calling_code)
        throw new Skip('phone calling code does not match');
      if (!prefixes.length && fixedPhoneCode(e) && fixedPhoneCode(e) !== values.phone_calling_code)
        throw new Skip('phone calling code does not match');
    }
    if (['born_on','document_expiry'].includes(mapping.field) && mapping.part) {
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
    if (mapping.field === 'phone' && mapping.part === 'country') {
      if (e.tagName !== 'SELECT' && !mapping.choice) throw new Skip('phone calling code needs private input');
      value = values.phone_country;
      aliases = [value, new Intl.DisplayNames([document.documentElement.lang || 'en'],{type:'region'}).of(value)];
    } else if (mapping.field === 'phone' && mapping.part) {
      value = mapping.part === 'area' ? values.phone_area : values.phone_local;
      if (typeof value !== 'string' || value === '') throw new Skip('phone saved without an area code group');
      aliases = [value];
    } else if (mapping.field === 'phone' && typeof values.phone_national === 'string') {
      const [prefix] = phonePrefix(e);
      if (prefix || fixedPhoneCode(e)) {
        if (prefix && values.phone_calling_code && callingCode(prefix) !== values.phone_calling_code)
          throw new Skip('phone calling code does not match');
        value = values.phone_national;
        aliases = [value];
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
      (globalThis.__bloomPrivateDisplays ||= new Set()).add(e);
      filled.push(mapping.field);
      continue;
    }
    if (mapping.choice) {
      // The site draws its own list. Open it (read-only input) or filter it by
      // typing the name (editable input), then click the one new option naming
      // this value; options already on the page, like a country menu, never count.
      let typed = ['born_on','document_expiry'].includes(mapping.field) ? value : ['nationality','document_country'].includes(mapping.field) || mapping.part === 'country' ? aliases.at(-1)
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
      const before = new Set(mapping.part !== 'country' && (e.readOnly || mapping.listOpen) ? [] : candidates());
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
        if (shownBeside) {
          globalThis.__bloomPrivateFields.set(a, mapping.field + (mapping.part ? '_' + mapping.part : ''));
          (globalThis.__bloomPrivateDisplays ||= new Set()).add(a);
        }
      }
      const taken = normalize(e.value);
      // Typed text alone proves nothing: an editable list must also have closed.
      const closed = !option.isConnected || !option.getClientRects().length;
      // A field may show the option's code ("PAS" for "PAS - Pasaporte").
      const abbreviated = taken.length > 1 && chosen.startsWith(taken) && /^\W/.test(chosen.slice(taken.length));
      const phoneCountryTaken = mapping.part === 'country' && callingCode(e) === values.phone_calling_code;
      if ((!e.readOnly && !closed) || (!phoneCountryTaken && !aliases.some(a => normalize(a) === taken) && taken !== chosen && !abbreviated && !shownBeside)) throw new Skip('not taken by the field');
    } else if (e.tagName === 'SELECT') {
      const matches = [...e.options].filter(o=>!o.disabled && aliases.some(a=>normalize(a)===normalize(o.value) || normalize(a)===normalize(o.text)
        || (mapping.part === 'country' && normalize(a).length > 2
          && normalize(o.text).replace(/^\+?\d{1,3}\s+|\s*\(\+?\d{1,3}\)$/g,'') === normalize(a))));
      if (matches.length !== 1) throw Error('Traveler choice needs private input');
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set.call(e,matches[0].value);
      e.dispatchEvent(new Event('input',{bubbles:true}));
    } else if (e.type === 'date') {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,value);
      e.dispatchEvent(new Event('input',{bubbles:true}));
    } else {
      e.focus();
      if (!e.isConnected || e.disabled || e.readOnly || e.type === 'password'
          || (e.autocomplete || '').split(' ').some(s=>s.startsWith('cc-'))) throw Error('Traveler field changed');
      // Bind the write to this approved field, not the page's current text
      // selection. Controlled forms can move focus while handling another field.
      const prototype = e.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(prototype,'value').set.call(e,value);
      e.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText',data:value}));
      // Some forms only accept a value after a key release and leaving the field.
      e.dispatchEvent(new KeyboardEvent('keyup',{key:value.slice(-1),bubbles:true}));
    }
    e.dispatchEvent(new Event('change',{bubbles:true}));
    // Booking sites commonly validate only after a field has been touched and
    // left. Do that before claiming the saved value was accepted.
    if (document.activeElement === e) e.blur();
    await new Promise(r => setTimeout(r, 25));
    if (!e.checkValidity() || e.getAttribute('aria-invalid') === 'true') throw new Skip('field rejected by page');
    if (mapping.part !== 'country') filled.push(mapping.field);
  } catch (error) {
    if (!(error instanceof Skip)) throw error;
    const e = binding.refs[mapping.index];
    if (e?.tagName === 'INPUT' && !e.readOnly && e.value && document.activeElement === e) { e.select(); document.execCommand('delete'); }
    skipped.push(`${mapping.field}${mapping.part ? ' ' + mapping.part : ''}: ${error.message}`);
  }
  }
  // Later input handlers can rewrite an earlier passenger name. Check the
  // completed form before reporting acceptance; never return its actual value.
  const accepted = [...new Set(filled)].filter(field => {
    if (!['given_name','family_name'].includes(field)) return true;
    const matches = mapped.filter(m => m.field === field).every(m => {
      const e = binding.refs[m.index];
      return e?.isConnected && normalize(e.value) === normalize(values[field]);
    });
    if (!matches) skipped.push(`${field}: field changed after filling`);
    return matches;
  });
  return {filled:accepted,skipped};
})()
