'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  const form = $('setup-form');
  let state = null;
  let busy = false;
  let hydrated = false;
  let dirty = false;
  const presets = {trader: ['100', '1000', '86400'], degen: ['1000', '10000', '604800']};
  const selected = () => form.elements.persona.value;
  const display = (value) => typeof value === 'string' ? value : JSON.stringify(value ?? null, null, 2);
  function notice(message, error = false) {
    $('notice').textContent = message;
    $('notice').classList.toggle('error', error);
  }
  function activity(message) {
    $('activity').textContent = `${new Date().toLocaleTimeString()}  ${message}\n\n${$('activity').textContent}`;
  }
  function controls() {
    for (const button of document.querySelectorAll('button')) button.disabled = busy;
    $('activate').disabled = busy || dirty || selected() === 'custodian' || !state?.machine?.available;
    $('limits').hidden = selected() === 'custodian';
    for (const input of $('limits').querySelectorAll('input, select')) input.disabled = busy || selected() === 'custodian';
  }
  const petals = [
    ['polymarket', 'Polymarket', 'Prediction markets'], ['hyperliquid', 'Hyperliquid', 'Perpetuals'],
    ['near-intents', 'NEAR Intents', 'Cross-chain swaps'], ['feedback', 'Feedback', 'Send product feedback'],
    ['enso', 'Enso', 'DeFi routes']
  ];
  for (const [id, label, description] of petals) {
    const choice = document.createElement('label');
    choice.className = 'petal-choice';
    const input = document.createElement('input');
    input.type = 'checkbox'; input.name = 'petals'; input.value = id;
    input.checked = ['polymarket', 'hyperliquid'].includes(id);
    const content = document.createElement('span');
    const title = document.createElement('strong'); title.textContent = label;
    const detail = document.createElement('small'); detail.textContent = description;
    content.append(title, detail); choice.append(input, content); $('petal-choices').append(choice);
  }
  function statusText(result, empty) {
    if (!result) return empty;
    if (result.error) return `Needs attention: ${display(result.error)}`;
    if (result.available === false) return 'Unavailable. Reconnect the local service and refresh.';
    const value = result.data;
    if (typeof value === 'string') return value;
    if (Array.isArray(value)) {
      if (!value.length) return empty;
      return value.map((item) => typeof item === 'string' ? item : [item.wallet ?? item.name ?? item.persona, item.locally_disabled ? 'Stopped' : item.preparation_pending ? 'Awaiting preparation' : item.authority?.state ?? item.status ?? item.state].filter(Boolean).join(' · ') || 'Record available; see recovery details.').join('\n');
    }
    if (value?.status || value?.state) return display(value.status ?? value.state);
    if (value?.signed_policy || value?.policy) return 'Wallet policy found. Review or resume to check your selected Petals.';
    if (result.stdout?.trim() && !result.stdout.trim().startsWith('{') && !result.stdout.trim().startsWith('[')) return result.stdout.trim().split('\n').map(line => line.split('\t').slice(0, 2).join(' · ')).join('\n');
    return empty;
  }
  function render(data) {
    state = data;
    const config = data.config ?? {};
    $('raw-state').textContent = display(data);
    $('setup-status').textContent = config.setup_complete ? 'Preferences saved' : 'Setup not yet complete';
    $('wallet-summary').textContent = statusText(data.wallets, 'No wallet found. Create or import main to continue.');
    $('policy-summary').textContent = statusText(data.policy, 'Policy not yet applied. Review or resume the policy once main exists.');
    $('session-status').textContent = statusText(data.sessions, 'No persona sessions reported.');
    if (!hydrated && !dirty) {
      if (config.persona) {
        const persona = typeof config.persona === 'string' ? {preset: config.persona} : config.persona;
        const preset = persona.preset ?? persona.persona;
        const radio = [...form.querySelectorAll('[name="persona"]')].find((input) => input.value === preset);
        if (radio) radio.checked = true;
        if (config.persona_limits?.per_action_usd != null) $('per-action').value = config.persona_limits.per_action_usd;
        if (config.persona_limits?.daily_usd != null) $('daily').value = config.persona_limits.daily_usd;
        if (persona.session_duration_secs != null) {
          const duration = config.persona_limits?.session_duration_secs ?? String(persona.session_duration_secs);
          if (![...$('duration').options].some((option) => option.value === duration)) $('duration').add(new Option(`${duration} seconds (saved)`, duration));
          $('duration').value = duration;
        }
      }
      if (Array.isArray(config.petals) && (config.setup_complete || config.petals.length)) {
        for (const input of form.querySelectorAll('[name="petals"]')) input.checked = config.petals.includes(input.value);
      }
      hydrated = true;
    }
    if (data.machine?.error) notice(display(data.machine.error), true);
    else if (!data.machine?.available) notice('The local Machine service is unavailable. Start or reconnect it, then refresh. Saved setup can be resumed.', true);
    else notice('Connected to your local Bloom. Continue setup or resume an unfinished review.');
    controls();
  }
  async function api(path, payload) {
    const response = await fetch(`api/${path}`, {
      method: payload === undefined ? 'GET' : 'POST',
      headers: payload === undefined ? {'Accept': 'application/json'} : {'Content-Type': 'application/json', 'Accept': 'application/json'},
      ...(payload === undefined ? {} : {body: JSON.stringify(payload)}),
      cache: 'no-store', credentials: 'same-origin'
    });
    const text = await response.text();
    let data;
    try { data = JSON.parse(text); } catch { throw new Error(text || `Local service returned HTTP ${response.status}`); }
    if (!response.ok || data.error || (data.exit_code != null && data.exit_code !== 0)) throw new Error(display(data.error ?? data.stderr ?? data.stdout ?? data));
    return data;
  }
  function review(result) {
    const url = result.ceremony_url;
    if (!url) { $('review').hidden = true; return; }
    let parsed;
    try { parsed = new URL(url, location.href); } catch { throw new Error('The service returned an invalid ceremony URL. See activity details.'); }
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('The service returned an unsupported ceremony URL.');
    $('ceremony-link').href = parsed.href;
    $('review').hidden = false;
    $('review').scrollIntoView({behavior: 'smooth', block: 'center'});
  }
  async function perform(task) {
    if (busy) return;
    busy = true;
    controls();
    try { await task(); }
    catch (error) { notice(error.message, true); activity(`Error: ${error.message}`); }
    finally { busy = false; controls(); }
  }
  async function refresh() { render(await api('state')); }
  form.addEventListener('input', () => { dirty = true; });
  form.addEventListener('change', (event) => {
    dirty = true;
    if (event.target.name === 'persona' && presets[selected()]) {
      const [action, daily, duration] = presets[selected()];
      $('per-action').value = action;
      $('daily').value = daily;
      $('duration').value = duration;
    }
    controls();
  });
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    perform(async () => {
      notice('Saving preferences and provisioning the selected venues…');
      const result = await api('setup', {
        persona: selected(),
        ...(selected() === 'custodian' ? {} : {per_action_usd: $('per-action').value.trim(), daily_usd: $('daily').value.trim(), ...(Number.isSafeInteger(Number($('duration').value)) ? {session_duration_secs: Number($('duration').value)} : {})}),
        petals: [...form.querySelectorAll('[name="petals"]:checked')].map((input) => input.value)
      });
      activity(display(result));
      review(result);
      dirty = false;
      hydrated = false;
      await refresh();
    });
  });
  for (const button of document.querySelectorAll('[data-action]')) button.addEventListener('click', () => {
    perform(async () => {
      const action = button.dataset.action;
      notice(action === 'refresh' ? 'Refreshing local status…' : 'Working with your local Bloom…');
      const result = await api('action', {action});
      activity(result.stdout || display(result.data ?? result));
      review(result);
      $('resume-review').dataset.action = action;
      await refresh();
      if (result.ceremony_url) notice('A secure ceremony is ready. Open the review below to continue.');
    });
  });
  perform(refresh);
})();
