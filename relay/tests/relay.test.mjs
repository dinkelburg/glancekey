import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, verify } from "node:crypto";
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
  durableObjects: {
    MACHINES: { className: "Machine", useSQLite: true },
    CARDS: { className: "Card", useSQLite: true },
    RECIPIENTS: { className: "Recipient", useSQLite: true },
  },
  bindings: {
    APNS_KEY: apnsKey.privateKey.export({ type: "pkcs8", format: "pem" }),
    APNS_KEY_ID: "KEYID12345",
    APNS_TEAM_ID: "TEAMID1234",
    APNS_TOPIC: "com.example.app",
    FREE_LIMITS: { computers: 2, perDay: 15 },
  },
  outboundService: apns,
}));
after(() => relay.dispose());

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

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

// The iPhone app reads this as FreeLimits (Core/Tests, FreeTierTests.limitsJSON).
test("the relay tells the app the free limits", { timeout: 5000 }, async () => {
  const response = await relay.dispatchFetch("http://localhost/v1/limits");
  assert.equal(response.status, 200);
  assert.equal(await response.text(), '{"computers":2,"perDay":15}');
});

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

test("oversized requests and too many waiting requests are refused", { timeout: 5000 }, async () => {
  const machineId = crypto.randomUUID();
  const socket = await connect(machineId);
  const waiting = [];
  try {
    const big = await relay.dispatchFetch(`http://localhost/v1/m/${machineId}/hello`, { method: "POST", body: "x".repeat(16 * 1024 + 1) });
    assert.equal(big.status, 413);

    for (let i = 0; i < 32; i++) waiting.push((await pendingRequest(machineId, socket)).response);
    const extra = await relay.dispatchFetch(`http://localhost/v1/m/${machineId}/hello`, { method: "POST", body: "{}" });
    assert.equal(extra.status, 429);
  } finally {
    socket.close(1000);
  }
  await Promise.all(waiting); // they fail once the computer disconnects
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

async function pushesFor(token, count, wait = 2000) {
  const deadline = Date.now() + wait;
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

test("a notification lasts as long as the request waits", { timeout: 5000 }, async () => {
  const socket = await connect(crypto.randomUUID());
  const token = "b1".repeat(32), older = "b2".repeat(32);
  try {
    socket.send(JSON.stringify({ notify: { machineName: "Mac", pushTokens: [token], expiresIn: 900 } }));
    const [push] = await pushesFor(token, 1);
    assert.ok(Math.abs(Number(push.headers.get("apns-expiration")) - (Date.now() / 1000 + 900)) < 5);
    // A computer from before expiresIn: two minutes.
    socket.send(JSON.stringify({ notify: { machineName: "Mac", pushTokens: [older] } }));
    const [old] = await pushesFor(older, 1);
    assert.ok(Math.abs(Number(old.headers.get("apns-expiration")) - (Date.now() / 1000 + 120)) < 5);
  } finally {
    socket.close(1000);
  }
});

test("new machine ids can't send one iPhone more than a few notifications a minute", { timeout: 8000 }, async () => {
  const token = "a0".repeat(32);
  const sockets = await Promise.all([1, 2, 3].map(() => connect(crypto.randomUUID())));
  try {
    for (const socket of sockets) {
      for (let i = 0; i < 6; i++) socket.send(JSON.stringify({ notify: { machineName: "Mac", pushTokens: [token] } }));
    }
    await pushesFor(token, 10);
    await sleep(500);
    assert.equal((await pushesFor(token, 10)).length, 10);
  } finally {
    for (const socket of sockets) socket.close(1000);
  }
});

// MARK: - Lock screen cards

function newCard() {
  const secret = crypto.randomUUID() + crypto.randomUUID();
  return { secret, id: createHash("sha256").update(secret).digest("hex") };
}

async function register(card, body) {
  return relay.dispatchFetch(`http://localhost/v1/card/${card.id}`, {
    method: "POST",
    body: JSON.stringify({ secret: card.secret, on: true, key: "card-key-0123456789", ...body }),
  });
}

const liveToken = () => [...crypto.getRandomValues(new Uint8Array(40))].map((byte) => byte.toString(16).padStart(2, "0")).join("");

test("only the iPhone with the card's secret can register it", { timeout: 5000 }, async () => {
  const card = newCard();
  assert.equal((await relay.dispatchFetch("http://localhost/v1/card/not-a-card", { method: "POST", body: "{}" })).status, 400);
  assert.equal((await register({ ...card, secret: "x".repeat(40) }, { computers: [] })).status, 403);
  assert.equal((await register(card, { computers: [], key: "short" })).status, 400);
  assert.equal((await register(card, { computers: [] })).status, 200);
});

test("a computer's changes update the iPhone's card", { timeout: 10000 }, async () => {
  const card = newCard();
  const machineId = crypto.randomUUID(), otherId = crypto.randomUUID();
  const token = liveToken();
  const registered = await register(card, {
    computers: [{ id: machineId, name: "Mac", state: "unknown" }, { id: otherId, name: "Omarchy", state: "locked" }, { id: "bad id", name: "x" }],
    updateToken: token,
    startedAt: Date.now() / 1000,
  });
  assert.equal(registered.status, 200);

  const socket = await connect(machineId);
  const waiting = { id: "a1", title: "sudo true", detail: "ruben on pts/1", expiresIn: 60 };
  socket.send(JSON.stringify({ card: { cards: [card.id, "not-a-card"], locked: true, approvals: [waiting] } }));
  const [push] = await pushesFor(token, 1);
  assert.equal(push.headers.get("apns-push-type"), "liveactivity");
  assert.equal(push.headers.get("apns-topic"), "com.example.app.push-type.liveactivity");
  assert.equal(push.body.aps.event, "update");
  const state = push.body.aps["content-state"];
  assert.deepEqual(state.computers, [
    { id: machineId, name: "Mac", state: "locked" },
    // Hasn't sent its part: what the iPhone last saw.
    { id: otherId, name: "Omarchy", state: "locked" },
  ]);
  assert.equal(state.requests.length, 1);
  const { until, ...request } = state.requests[0];
  assert.deepEqual(request, { computer: machineId, id: "a1", title: "sudo true", detail: "ruben on pts/1" });
  assert.ok(Math.abs(until - (Date.now() / 1000 + 60)) < 5);
  assert.equal(state.key, "card-key-0123456789");

  // The same again changes nothing.
  socket.send(JSON.stringify({ card: { cards: [card.id], locked: true, approvals: [{ ...waiting, expiresIn: 59 }] } }));
  await sleep(1500);
  assert.equal((await pushesFor(token, 1)).length, 1);

  // Disconnecting shows it offline, without its requests.
  socket.close(1000);
  const [, offline] = await pushesFor(token, 2, 4000);
  assert.deepEqual(offline.body.aps["content-state"].computers[0], { id: machineId, name: "Mac", state: "offline" });
  assert.deepEqual(offline.body.aps["content-state"].requests, []);
});

test("an ended card starts again when a computer locks or asks for something", { timeout: 10000 }, async () => {
  const card = newCard();
  const machineId = crypto.randomUUID();
  const startToken = liveToken();
  assert.equal((await register(card, { computers: [{ id: machineId, name: "Mac", state: "unknown" }], startToken })).status, 200);
  const socket = await connect(machineId);
  try {
    // Unlocked is no reason to light up the iPhone.
    socket.send(JSON.stringify({ card: { cards: [card.id], locked: false, approvals: [] } }));
    await sleep(800);
    assert.equal(pushes.filter((push) => push.url.pathname === `/3/device/${startToken}`).length, 0);

    socket.send(JSON.stringify({ card: { cards: [card.id], locked: true, approvals: [] } }));
    const [start] = await pushesFor(startToken, 1, 3000);
    assert.equal(start.body.aps.event, "start");
    assert.equal(start.body.aps["attributes-type"], "LiveCardAttributes");
    assert.deepEqual(start.body.aps.attributes, {});
    assert.equal(start.body.aps.alert.title, "Mac is locked");
    assert.equal(start.body.aps["content-state"].computers[0].state, "locked");

    // A change before the iPhone says where the new card is waits for it.
    socket.send(JSON.stringify({ card: { cards: [card.id], locked: false, approvals: [] } }));
    await sleep(1500);
    const updateToken = liveToken();
    assert.equal((await register(card, { computers: [{ id: machineId, name: "Mac", state: "locked" }], startToken, updateToken })).status, 200);
    const [update] = await pushesFor(updateToken, 1, 3000);
    assert.equal(update.body.aps.event, "update");
    assert.equal(update.body.aps["content-state"].computers[0].state, "unlocked");
    assert.equal(pushes.filter((push) => push.url.pathname === `/3/device/${startToken}`).length, 1);
  } finally {
    socket.close(1000);
  }
});

test("turning the card off ends it and drops the computer from it", { timeout: 10000 }, async () => {
  const card = newCard();
  const machineId = crypto.randomUUID();
  const token = liveToken();
  await register(card, { computers: [{ id: machineId, name: "Mac", state: "unknown" }], updateToken: token, startedAt: Date.now() / 1000 });
  const off = await relay.dispatchFetch(`http://localhost/v1/card/${card.id}`, { method: "POST", body: JSON.stringify({ secret: card.secret, on: false }) });
  assert.equal(off.status, 200);
  const [end] = await pushesFor(token, 1);
  assert.equal(end.body.aps.event, "end");
  assert.ok(end.body.aps["dismissal-date"] > 0);

  // A computer still sending to it pushes nothing: the card has nowhere to go.
  const socket = await connect(machineId);
  try {
    socket.send(JSON.stringify({ card: { cards: [card.id], locked: true, approvals: [] } }));
    await sleep(1000);
    assert.equal((await pushesFor(token, 1)).length, 1);
  } finally {
    socket.close(1000);
  }
});

test("after the card is turned off, a computer's part isn't kept", { timeout: 10000 }, async () => {
  const card = newCard();
  const machineId = crypto.randomUUID(), otherId = crypto.randomUUID();
  await register(card, { computers: [{ id: machineId, name: "Mac", state: "unknown" }] });
  await relay.dispatchFetch(`http://localhost/v1/card/${card.id}`, { method: "POST", body: JSON.stringify({ secret: card.secret, on: false }) });
  const mac = await connect(machineId), other = await connect(otherId);
  try {
    // Sent before the computer heard the card is off.
    mac.send(JSON.stringify({ card: { cards: [card.id], locked: true, approvals: [{ id: "a1", title: "sudo secret", detail: "", expiresIn: 600 }] } }));
    await sleep(500);
    const token = liveToken();
    await register(card, {
      computers: [{ id: machineId, name: "Mac", state: "unknown" }, { id: otherId, name: "Omarchy", state: "unknown" }],
      updateToken: token, startedAt: Date.now() / 1000,
    });
    other.send(JSON.stringify({ card: { cards: [card.id], locked: false, approvals: [] } }));
    const [push] = await pushesFor(token, 1, 3000);
    assert.equal(push.body.aps["content-state"].computers[0].state, "unknown");
    assert.deepEqual(push.body.aps["content-state"].requests, []);
  } finally {
    mac.close(1000);
    other.close(1000);
  }
});

test("a computer the card doesn't list can't push it", { timeout: 10000 }, async () => {
  const card = newCard();
  const token = liveToken();
  await register(card, { computers: [{ id: crypto.randomUUID(), name: "Mac", state: "unknown" }], updateToken: token, startedAt: Date.now() / 1000 });
  const stranger = await connect(crypto.randomUUID());
  try {
    stranger.send(JSON.stringify({ card: { cards: [card.id], locked: true, approvals: [{ id: "a1", title: "sudo x", detail: "", expiresIn: 60 }] } }));
    await sleep(1500);
    assert.equal(pushes.filter((push) => push.url.pathname === `/3/device/${token}`).length, 0);
  } finally {
    stranger.close(1000);
  }
});

test("an expired request leaves the card, and the relay, by itself", { timeout: 10000 }, async () => {
  const card = newCard();
  const machineId = crypto.randomUUID();
  const token = liveToken();
  await register(card, { computers: [{ id: machineId, name: "Mac", state: "unknown" }], updateToken: token, startedAt: Date.now() / 1000 });
  const socket = await connect(machineId);
  try {
    socket.send(JSON.stringify({ card: { cards: [card.id], locked: false, approvals: [{ id: "a1", title: "sudo true", detail: "", expiresIn: 2 }] } }));
    const [first] = await pushesFor(token, 1);
    assert.equal(first.body.aps["content-state"].requests.length, 1);
    const [, second] = await pushesFor(token, 2, 5000);
    assert.deepEqual(second.body.aps["content-state"].requests, []);
  } finally {
    socket.close(1000);
  }
});

test("a new request lights up the iPhone through its card, or as a notification when there's no card", { timeout: 10000 }, async () => {
  const waiting = { id: "a1", title: "sudo true", detail: "", expiresIn: 60 };

  // A running card alerts with a sound, once notifications are on.
  const card = newCard();
  const machineId = crypto.randomUUID();
  const token = liveToken(), pushToken = "ae".repeat(32);
  await register(card, { computers: [{ id: machineId, name: "Mac", state: "unknown" }], updateToken: token,
    startedAt: Date.now() / 1000, alerts: true, pushToken });
  const socket = await connect(machineId);
  try {
    socket.send(JSON.stringify({ card: { cards: [card.id], locked: false, approvals: [waiting] } }));
    const [update] = await pushesFor(token, 1);
    assert.deepEqual(update.body.aps.alert, { title: "Mac is waiting for you", body: "Approve it on the card." });
    assert.equal(update.body.aps.sound, "default");
    await sleep(300);
    assert.equal(pushes.filter((push) => push.url.pathname === `/3/device/${pushToken}`).length, 0);
  } finally {
    socket.close(1000);
  }

  // Without a card to show it, it comes as the regular notification.
  const bare = newCard();
  const otherId = crypto.randomUUID();
  const otherPushToken = "af".repeat(32);
  await register(bare, { computers: [{ id: otherId, name: "Omarchy", state: "unknown" }], alerts: true, pushToken: otherPushToken });
  const other = await connect(otherId);
  try {
    other.send(JSON.stringify({ card: { cards: [bare.id], locked: false, approvals: [waiting] } }));
    const [notification] = await pushesFor(otherPushToken, 1);
    assert.equal(notification.headers.get("apns-push-type"), "alert");
    assert.equal(notification.body.aps.alert.title, "Omarchy is waiting for you");
  } finally {
    other.close(1000);
  }
});

test("with notifications off, the card updates without lighting up the iPhone", { timeout: 10000 }, async () => {
  const card = newCard();
  const machineId = crypto.randomUUID();
  const token = liveToken();
  await register(card, { computers: [{ id: machineId, name: "Mac", state: "unknown" }], updateToken: token, startedAt: Date.now() / 1000 });
  const socket = await connect(machineId);
  try {
    socket.send(JSON.stringify({ card: { cards: [card.id], locked: false, approvals: [{ id: "a1", title: "sudo true", detail: "", expiresIn: 60 }] } }));
    const [update] = await pushesFor(token, 1);
    assert.equal(update.body.aps.alert, undefined);
    assert.equal(update.body.aps.sound, undefined);
  } finally {
    socket.close(1000);
  }
});
