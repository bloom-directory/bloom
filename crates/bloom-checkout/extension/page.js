// Runs Bloom's page scripts (the same files checkout's own browser uses) when
// background.js relays a command. Each call is instant: waiting happens in
// checkout, because Chrome slows timers in background tabs.
chrome.runtime.onMessage.addListener((command, _sender, reply) => {
  try {
    if (command.action === 'snapshot') {
      const snapshot = BLOOM_SCRIPTS.snapshot();
      snapshot.text = (document.body?.innerText || '').slice(0, 30000);
      reply({value: snapshot});
    } else if (['click', 'type', 'select'].includes(command.action)) {
      reply({value: BLOOM_SCRIPTS.act(command.index, command.action, command.value ?? '')});
    } else {
      reply({error: 'Unknown page command'});
    }
  } catch (error) {
    reply({error: String(error.message || error)});
  }
});
