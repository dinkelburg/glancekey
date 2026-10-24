import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { after, test } from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import ts from "typescript";

const source = await readFile(new URL("../src/index.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
});
const relay = new Miniflare(convertV4MiniflareOptions({
  modules: true,
  script: outputText,
  compatibilityDate: "2026-10-01",
  durableObjects: { MACHINES: { className: "Machine", useSQLite: true } },
}));
after(() => relay.dispose());

async function connect(machineId, secret = "a".repeat(32)) {
  const response = await relay.dispatchFetch(`http://localhost/v1/agent/${machineId}`, {
    headers: { Upgrade: "websocket", Authorization: `Bearer ${secret}` },
  });
  assert.equal(response.status, 101);
  const socket = response.webSocket;
  socket.accept();
  return socket;
}

async function pendingRequest(machineId, socket) {
  const received = new Promise((resolve) => {
    socket.addEventListener("message", (event) => resolve(JSON.parse(event.data)), { once: true });
  });
  const response = relay.dispatchFetch(`http://localhost/v1/m/${machineId}/hello`, {
    method: "POST",
    body: JSON.stringify({ deviceId: "test-phone" }),
  });
  return { response, request: await received };
}

async function promptly(response) {
  let timer;
  try {
    return await Promise.race([
      response,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("Pending request did not finish within 1 second")), 1000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

test("an agent reply preserves its HTTP status and JSON body", { timeout: 5000 }, async () => {
  const machineId = crypto.randomUUID();
  const socket = await connect(machineId);
  try {
    const { response, request } = await pendingRequest(machineId, socket);
    assert.equal(request.path, "/v1/hello");
    assert.deepEqual(JSON.parse(request.body), { deviceId: "test-phone" });
    socket.send(JSON.stringify({ id: request.id, status: 403, body: '{"error":"Not paired"}' }));
    const answer = await promptly(response);
    assert.equal(answer.status, 403);
    assert.deepEqual(await answer.json(), { error: "Not paired" });
  } finally {
    socket.close(1000);
  }
});

test("disconnecting an agent promptly fails its pending request", { timeout: 5000 }, async () => {
  const machineId = crypto.randomUUID();
  const socket = await connect(machineId);
  const { response } = await pendingRequest(machineId, socket);
  socket.close(1000);
  const answer = await promptly(response);
  assert.equal(answer.status, 503);
  assert.match((await answer.json()).error, /disconnected/);
});

test("replacing an agent fails old pending requests and routes new ones", { timeout: 5000 }, async () => {
  const machineId = crypto.randomUUID();
  const old = await connect(machineId);
  const { response: oldResponse } = await pendingRequest(machineId, old);
  const current = await connect(machineId);
  try {
    assert.equal((await promptly(oldResponse)).status, 503);
    const { response, request } = await pendingRequest(machineId, current);
    current.send(JSON.stringify({ id: request.id, status: 200, body: '{"nonce":"new-connection"}' }));
    const answer = await promptly(response);
    assert.equal(answer.status, 200);
    assert.deepEqual(await answer.json(), { nonce: "new-connection" });
  } finally {
    current.close(1000);
  }
});
