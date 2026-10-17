// Bloom checkout's hands in the person's own browser: one tab it opened, on
// approved booking sites only. Commands arrive from checkout over native
// messaging; the page work happens in page.js.
const HOST = 'directory.bloom.checkout';
const SITES = /^https:\/\/([a-z0-9-]+\.)*(aerolineas\.com\.ar|jetsmart\.com)(\/|$)/;
let port = null;

function connect() {
  if (port) return;
  port = chrome.runtime.connectNative(HOST);
  port.onMessage.addListener(command => {
    run(command)
      .then(value => ({ok: true, value}), error => ({ok: false, error: String(error.message || error)}))
      .then(result => port?.postMessage({id: command.id, ...result}));
  });
  // Checkout restarted or stopped; the alarm reconnects. Reading lastError marks it handled.
  port.onDisconnect.addListener(() => { void chrome.runtime.lastError; port = null; });
}

async function bloomTab() {
  const {tabId} = await chrome.storage.session.get('tabId');
  const tab = tabId && await chrome.tabs.get(tabId).catch(() => null);
  return tab || null;
}

async function run(command) {
  // Checkout updated the extension's files: load them (unpacked installs).
  if (command.action === 'version') return BLOOM_VERSION;
  if (command.action === 'reload') { setTimeout(() => chrome.runtime.reload(), 100); return {state: 'reloading'}; }
  if (command.action === 'open') {
    if (!SITES.test(command.url)) throw Error('Bloom only opens approved booking sites in this browser');
    let tab = await bloomTab();
    tab = tab ? await chrome.tabs.update(tab.id, {url: command.url}) : await chrome.tabs.create({url: command.url, active: false});
    await chrome.storage.session.set({tabId: tab.id});
    return {state: 'opened'};
  }
  const tab = await bloomTab();
  if (!tab) throw Error('Open a booking page first');
  // The person may have navigated this tab elsewhere; never act there.
  if (!SITES.test(tab.url || '')) throw Error('The Bloom tab is not on an approved booking site');
  if (command.action === 'back') { await chrome.tabs.goBack(tab.id); return {state: 'navigated'}; }
  if (command.action === 'location') return {url: tab.url};
  // Filling waits inside the page, and Chrome slows timers in background tabs.
  const limit = command.action.startsWith('traveler_') || command.action === 'type_traveler' ? 300000 : 60000;
  const reply = await Promise.race([
    chrome.tabs.sendMessage(tab.id, command, {frameId: 0}),
    new Promise((_, fail) => setTimeout(() => fail(Error('The page did not answer')), limit)),
  ]);
  if (!reply || reply.error) throw Error(reply?.error || 'The page did not answer');
  return reply.value;
}

// Chrome stops idle extension workers; reconnect when it wakes us.
chrome.alarms.create('connect', {periodInMinutes: 0.5});
chrome.alarms.onAlarm.addListener(connect);
chrome.runtime.onStartup.addListener(connect);
chrome.runtime.onInstalled.addListener(connect);
connect();
