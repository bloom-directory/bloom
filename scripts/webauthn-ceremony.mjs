#!/usr/bin/env node

// Drive Bloom's real Broker-hosted WebAuthn page with Chromium's standard CDP
// virtual-authenticator support. Secret input and ceremony output move through
// mode-0600 files only; neither is printed to stdout or included in errors.

import { readFile, writeFile, chmod } from "node:fs/promises";
import { existsSync } from "node:fs";
import { spawn } from "node:child_process";

function fail(message) {
  throw new Error(message);
}

function parseArgs(argv) {
  const options = {
    cdp: "http://127.0.0.1:9222",
    chromium: "chromium",
    timeoutMs: 120_000,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    if (name === "--url") options.url = argv[++index];
    else if (name === "--state") options.state = argv[++index];
    else if (name === "--input") options.input = argv[++index];
    else if (name === "--output") options.output = argv[++index];
    else if (name === "--cdp") options.cdp = argv[++index];
    else if (name === "--chromium") options.chromium = argv[++index];
    else if (name === "--timeout-ms") options.timeoutMs = Number(argv[++index]);
    else fail(`unknown argument: ${name}`);
  }
  for (const required of ["url", "state", "output"]) {
    if (!options[required]) fail(`--${required} is required`);
  }
  if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs <= 0) {
    fail("--timeout-ms must be a positive integer");
  }
  return options;
}

async function fetchJson(url, init) {
  const response = await fetch(url, init);
  if (!response.ok) fail(`CDP HTTP request failed (${response.status})`);
  return response.json();
}

async function waitForCdp(base, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      return await fetchJson(`${base}/json/version`);
    } catch (_) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  fail("Chromium CDP endpoint did not become ready");
}

async function ensureChromium(options, state) {
  try {
    const version = await fetchJson(`${options.cdp}/json/version`);
    return { version, state };
  } catch (_) {
    const userDataDir = `${options.state}.chromium`;
    const port = new URL(options.cdp).port || "9222";
    const child = spawn(
      options.chromium,
      [
        "--headless=new",
        `--remote-debugging-port=${port}`,
        `--user-data-dir=${userDataDir}`,
        "--no-first-run",
        "--no-default-browser-check",
        "about:blank",
      ],
      { detached: true, stdio: "ignore" },
    );
    child.unref();
    delete state.targetId;
    delete state.authenticatorId;
    state.chromiumPid = child.pid;
    state.chromiumUserDataDir = userDataDir;
    return { version: await waitForCdp(options.cdp, options.timeoutMs), state };
  }
}

class CdpClient {
  constructor(url) {
    this.socket = new WebSocket(url);
    this.nextId = 1;
    this.pending = new Map();
    this.socket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      if (!message.id) return;
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(message.error.message));
      else pending.resolve(message.result || {});
    });
  }

  async ready() {
    if (this.socket.readyState === WebSocket.OPEN) return;
    await new Promise((resolve, reject) => {
      this.socket.addEventListener("open", resolve, { once: true });
      this.socket.addEventListener("error", reject, { once: true });
    });
  }

  send(method, params = {}, sessionId) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.socket.send(JSON.stringify({ id, method, params, sessionId }));
    });
  }

  close() {
    this.socket.close();
  }
}

async function loadState(path) {
  if (!existsSync(path)) return {};
  return JSON.parse(await readFile(path, "utf8"));
}

async function savePrivateJson(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
}

async function evaluate(client, sessionId, expression, awaitPromise = true) {
  const result = await client.send(
    "Runtime.evaluate",
    { expression, awaitPromise, returnByValue: true },
    sessionId,
  );
  if (result.exceptionDetails) fail("ceremony page evaluation failed");
  return result.result?.value;
}

async function waitForPage(client, sessionId, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ready = await evaluate(
      client,
      sessionId,
      "document.readyState === 'complete' && Boolean(document.querySelector('#approve'))",
    );
    if (ready) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  fail("ceremony page did not become ready");
}

async function waitForCompletion(client, sessionId, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const state = await evaluate(
      client,
      sessionId,
      `(() => ({
        status: document.querySelector('#status')?.textContent || '',
        review: document.querySelector('#review')?.textContent || ''
      }))()`,
    );
    if (state.status.includes("Completed")) return state.review;
    if (/failed|error/i.test(state.status)) fail("ceremony page reported failure");
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  fail("ceremony did not complete before the timeout");
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  let state = await loadState(options.state);
  const chromium = await ensureChromium(options, state);
  state = chromium.state;
  const client = new CdpClient(chromium.version.webSocketDebuggerUrl);
  await client.ready();

  try {
    if (!state.targetId) {
      state.targetId = (await client.send("Target.createTarget", { url: "about:blank" })).targetId;
    }
    const attached = await client.send("Target.attachToTarget", {
      targetId: state.targetId,
      flatten: true,
    });
    const sessionId = attached.sessionId;
    await client.send("Page.enable", {}, sessionId);
    await client.send("Runtime.enable", {}, sessionId);
    await client.send("WebAuthn.enable", {}, sessionId);
    if (!state.authenticatorId) {
      state.authenticatorId = (
        await client.send(
          "WebAuthn.addVirtualAuthenticator",
          {
            options: {
              protocol: "ctap2",
              transport: "internal",
              hasResidentKey: true,
              hasUserVerification: true,
              isUserVerified: true,
              automaticPresenceSimulation: true,
              hasPrf: true,
            },
          },
          sessionId,
        )
      ).authenticatorId;
    }
    await savePrivateJson(options.state, state);

    await client.send("Page.navigate", { url: options.url }, sessionId);
    await waitForPage(client, sessionId, options.timeoutMs);
    const input = options.input ? JSON.parse(await readFile(options.input, "utf8")) : {};
    const encodedInput = JSON.stringify(input);
    await evaluate(
      client,
      sessionId,
      `(() => {
        const input = ${JSON.stringify(encodedInput)};
        const parsed = JSON.parse(input);
        const generic = document.querySelector('#generic-input');
        if (generic && parsed.generic !== undefined) {
          generic.value = typeof parsed.generic === 'string'
            ? parsed.generic : JSON.stringify(parsed.generic);
        }
        const recoveryId = document.querySelector('#recovery-id');
        const recoverySecret = document.querySelector('#recovery-secret');
        if (recoveryId && parsed.recovery_id) recoveryId.value = parsed.recovery_id;
        if (recoverySecret && parsed.recovery_secret) recoverySecret.value = parsed.recovery_secret;
        document.querySelector('#approve').click();
      })()`,
    );
    const output = await waitForCompletion(client, sessionId, options.timeoutMs);
    await writeFile(options.output, output, { mode: 0o600 });
    await chmod(options.output, 0o600);
  } finally {
    client.close();
  }
}

main().catch((error) => {
  process.stderr.write(`webauthn ceremony driver: ${error.message}\n`);
  process.exitCode = 1;
});
