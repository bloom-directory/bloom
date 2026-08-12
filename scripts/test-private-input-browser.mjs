#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";

const html = await readFile(new URL("../crates/bloom-daemon/src/ceremony_server/private_input_ceremony.html", import.meta.url), "utf8");
const recipient = "0x1111111111111111111111111111111111111111";
let preparedValue;
let completion;

async function body(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url, "http://127.0.0.1");
  response.setHeader("Content-Type", url.pathname.endsWith(".json") ? "application/json" : "text/html");
  if (request.method === "GET" && url.pathname === "/private-input/test") {
    response.end(html);
  } else if (request.method === "GET" && url.pathname.endsWith("/request.json")) {
    response.end(JSON.stringify({
      title: "Private Privacy Pools withdrawal",
      prompt: "Enter the destination privately.",
      note_wallet: "dev",
      approval_wallet: "owner-passkey",
    }));
  } else if (request.method === "POST" && url.pathname.endsWith("/prepare")) {
    preparedValue = (await body(request)).value;
    response.end(JSON.stringify({
      publicKey: {
        challenge: "AQIDBA",
        allowCredentials: [{ type: "public-key", id: "BQYHCA" }],
        timeout: 60_000,
      },
    }));
  } else if (request.method === "POST" && url.pathname.endsWith("/complete")) {
    completion = await body(request);
    response.end(JSON.stringify({ ok: true }));
  } else {
    response.statusCode = 404;
    response.end(JSON.stringify({ error: "not found" }));
  }
});

await new Promise((resolvePromise) => server.listen(0, "127.0.0.1", resolvePromise));
const driverPort = 19_515 + Math.floor(Math.random() * 1_000);
const driver = spawn("chromedriver", [`--port=${driverPort}`, "--log-level=SEVERE"], { stdio: "ignore" });
const driverUrl = `http://127.0.0.1:${driverPort}`;

async function command(path, payload, method = "POST") {
  const response = await fetch(`${driverUrl}${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
  assert(response.ok, `WebDriver ${path} failed: HTTP ${response.status}`);
  const result = await response.json();
  if (result.value?.error) throw new Error(result.value.message ?? result.value.error);
  return result.value;
}

async function waitForDriver() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      await command("/status", undefined, "GET");
      return;
    } catch {
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
    }
  }
  throw new Error("chromedriver did not start");
}

let sessionId;
try {
  await waitForDriver();
  const session = await command("/session", {
    capabilities: {
      alwaysMatch: {
        browserName: "chrome",
        "goog:chromeOptions": {
          binary: "/usr/bin/chromium",
          args: ["--headless=new", "--no-sandbox", "--disable-dev-shm-usage"],
        },
      },
    },
  });
  sessionId = session.sessionId;
  await command(`/session/${sessionId}/goog/cdp/execute`, {
    cmd: "Page.addScriptToEvaluateOnNewDocument",
    params: {
      source: `Object.defineProperty(navigator,'credentials',{configurable:true,value:{get:async()=>({id:'credential-id',response:{authenticatorData:new Uint8Array([1,2]).buffer,clientDataJSON:new Uint8Array([3,4]).buffer,signature:new Uint8Array([5,6]).buffer,userHandle:null}})}});`,
    },
  });
  await command(`/session/${sessionId}/url`, { url: `http://127.0.0.1:${server.address().port}/private-input/test` });
  await command(`/session/${sessionId}/execute/sync`, {
    script: `document.getElementById('destination').value=arguments[0];document.getElementById('form').requestSubmit();`,
    args: [recipient],
  });
  let view;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    view = await command(`/session/${sessionId}/execute/sync`, {
      script: `return {wallet:document.getElementById('wallet').textContent,status:document.getElementById('status').textContent,value:document.getElementById('destination').value};`,
      args: [],
    });
    if (view.status.includes("held privately")) break;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
  }
  assert.equal(view.wallet, "Passkey wallet · owner-passkey · Note wallet · dev");
  assert.match(view.status, /held privately/);
  assert.equal(view.value, "");
  assert.equal(preparedValue, recipient);
  assert.equal(completion.credential.id, "credential-id");
  assert.equal(completion.credential.response.authenticatorData, "AQI");
  assert.equal(completion.credential.response.clientDataJSON, "AwQ");
  assert.equal(completion.credential.response.signature, "BQY");
  assert.equal(completion.credential.response.userHandle, null);
  console.log(JSON.stringify({ browserCeremony: "complete", approvalIdentityCorrect: true, addressCleared: true }));
} finally {
  if (sessionId) await command(`/session/${sessionId}`, undefined, "DELETE").catch(() => {});
  driver.kill("SIGTERM");
  await new Promise((resolvePromise) => server.close(resolvePromise));
}
