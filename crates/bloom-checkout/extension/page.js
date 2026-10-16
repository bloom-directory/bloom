// Runs Bloom's page scripts (the same files checkout's own browser uses) when
// background.js relays a command. Each call is instant: waiting happens in
// checkout, because Chrome slows timers in background tabs.
async function handle(command) {
  switch (command.action) {
    case 'snapshot': {
      const snapshot = BLOOM_SCRIPTS.snapshot();
      snapshot.text = (document.body?.innerText || '').slice(0, 30000);
      return snapshot;
    }
    case 'click': case 'type': case 'select':
      return BLOOM_SCRIPTS.act(command.index, command.action, command.value ?? '');
    // Saved traveler values arrive only after the person's approval, for
    // this site; they go into the page and never back out.
    case 'traveler_discover':
      return BLOOM_SCRIPTS.travelerDiscover(command.nonce);
    case 'traveler_fill':
      return await BLOOM_SCRIPTS.travelerFill(command.nonce, command.origin, command.mapped, command.values);
    case 'open_list': {
      const e = globalThis.__bloomRefs?.[command.index];
      if (!e?.isConnected) throw Error('stale');
      e.focus(); e.click();
      return {state: 'opened'};
    }
    case 'type_traveler': {
      const e = globalThis.__bloomRefs?.[command.index];
      if (!e?.isConnected) throw Error('stale');
      globalThis.__bloomTravelerRefs = {document, refs: [e], nonce: 'choose'};
      const list = e.tagName === 'INPUT';
      return await BLOOM_SCRIPTS.travelerFill('choose', command.origin,
        [{field: command.field, choice: list, listOpen: list, index: 0}], {[command.field]: command.value});
    }
  }
  throw Error('Unknown page command');
}
chrome.runtime.onMessage.addListener((command, _sender, reply) => {
  handle(command).then(value => reply({value}), error => reply({error: String(error.message || error)}));
  return true;
});
