import assert from "node:assert/strict";
import { generateKeyPairSync, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { after, test } from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import ts from "typescript";

const source = await readFile(new URL("../src/index.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
});
// Requests to Apple's push service land here. Tokens starting with "dd" only exist in the sandbox, like those of
// an app installed from Xcode.
const apnsKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const pushes = [];
async function apns(request) {
  const url = new URL(request.url);
  pushes.push({ url, headers: request.headers, body: await request.json() });
  const token = url.pathname.split("/").pop();
  if (token.startsWith("dd") && url.host === "api.push.apple.com") {
    return Response.json({ reason: "BadDeviceToken" }, { status: 400 });
  }
  return new Response(null, { status: 200 });
}

const relay = new Miniflare(convertV4MiniflareOptions({
  modules: true,
  script: outputText,
  compatibilityDate: "2026-10-01",
  durableObjects: { MACHINES: { className: "Machine", useSQLite: true } },
  bindings: {
    APNS_KEY: apnsKey.privateKey.export({ type: "pkcs8", format: "pem" }),
    APNS_KEY_ID: "KEYID12345",
    APNS_TEAM_ID: "TEAMID1234",
    APNS_TOPIC: "com.example.app",
  },
  outboundService: apns,
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

async function pushesFor(token, count) {
  const deadline = Date.now() + 2000;
  let found;
  while ((found = pushes.filter((push) => push.url.pathname === `/3/device/${token}`)).length < count) {
    if (Date.now() > deadline) throw new Error(`Expected ${count} push(es) to ${token}, got ${found.length}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return found;
}

test("a computer's notification is pushed through APNs, to the sandbox for Xcode installs", { timeout: 5000 }, async () => {
  const machineId = crypto.randomUUID();
  const socket = await connect(machineId);
  const production = "ab".repeat(32), sandbox = "dd".repeat(32);
  try {
    socket.send(JSON.stringify({ notify: { machineName: "Ruben’s Mac", pushTokens: [production, sandbox, "not-a-token"] } }));
    const [push] = await pushesFor(production, 1);
    assert.equal(push.url.host, "api.push.apple.com");
    assert.equal(push.body.aps.alert.title, "Ruben’s Mac is waiting for you");
    assert.match(push.body.aps.alert.body, /^Tap to approve or deny with /);
    assert.equal(push.headers.get("apns-topic"), "com.example.app");
    assert.equal(push.headers.get("apns-push-type"), "alert");
    assert.equal(push.headers.get("apns-collapse-id").length, 64);

    const [header, claims, signature] = push.headers.get("authorization").replace(/^bearer /, "").split(".");
    const decode = (part) => JSON.parse(Buffer.from(part, "base64url"));
    assert.deepEqual(decode(header), { alg: "ES256", kid: "KEYID12345" });
    assert.equal(decode(claims).iss, "TEAMID1234");
    assert.ok(verify("sha256", Buffer.from(`${header}.${claims}`), { key: apnsKey.publicKey, dsaEncoding: "ieee-p1363" },
      Buffer.from(signature, "base64url")));

    const tries = await pushesFor(sandbox, 2);
    assert.deepEqual(tries.map((push) => push.url.host), ["api.push.apple.com", "api.sandbox.push.apple.com"]);
    assert.equal(pushes.filter((push) => push.url.pathname.includes("not-a-token")).length, 0);
  } finally {
    socket.close(1000);
  }
});

test("a computer can only send a few notifications a minute", { timeout: 5000 }, async () => {
  const machineId = crypto.randomUUID();
  const socket = await connect(machineId);
  const token = "ac".repeat(32);
  try {
    for (let i = 0; i < 10; i++) socket.send(JSON.stringify({ notify: { machineName: "Mac", pushTokens: [token] } }));
    await pushesFor(token, 6);
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal((await pushesFor(token, 6)).length, 6);
  } finally {
    socket.close(1000);
  }
});
