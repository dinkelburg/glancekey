import { DurableObject } from "cloudflare:workers";

// The relay. Computers (the Mac app, the Linux agent) keep a WebSocket open to
// /v1/agent/<machineId>; the iPhone POSTs to /v1/m/<machineId>/{pair,hello,command}. One Durable Object per
// machine passes each request down that WebSocket and returns the answer.
//
// The relay is not trusted: every command is signed by the iPhone's Secure Enclave key and checked on the
// computer, and pairing proves knowledge of the QR code without sending it. The relay only routes.
//
// It also sends the iPhone's notifications: when a computer waits for an approval, it sends
// {"notify": {"machineName", "pushTokens"}} over its WebSocket and the relay pushes "<machineName> is waiting for
// you" through Apple's push service (APNs), signed with the app's APNs key. Neither is stored.

// The app's name, as in Core/Sources/AppCore/Brand.swift, which explains how to rename the app. The relay's
// own name and address are in wrangler.jsonc.
const APP_NAME = "GlanceKey";

export interface Env {
  MACHINES: DurableObjectNamespace<Machine>;
  /// The APNs key (the .p8 file's contents), a secret: `npx wrangler secret put APNS_KEY < AuthKey_<id>.p8`.
  /// Without it the relay sends no notifications.
  APNS_KEY?: string;
  /// The rest is in wrangler.jsonc: the key's ID, the Apple team that owns it and the iPhone app's bundle ID.
  APNS_KEY_ID?: string;
  APNS_TEAM_ID?: string;
  APNS_TOPIC?: string;
}

interface Pending {
  socket: WebSocket;
  resolve: (answer: { status: number; body: string }) => void;
  timer: ReturnType<typeof setTimeout>;
}

const MACHINE_ID = /^[A-Za-z0-9-]{8,64}$/;
const MAX_BODY = 16 * 1024;
/// Requests a machine may have waiting for its computer at once. An iPhone has one or two; this keeps anyone who
/// knows a machine id from piling up more.
const MAX_PENDING = 32;
const ANSWER_TIMEOUT_MS = 25_000;
const PUSH_TOKEN = /^[0-9A-Fa-f]{64,200}$/;
const MAX_PUSH_TOKENS = 10;
/// Notifications a computer may send per minute. Each one is a password prompt, so a few are plenty.
const MAX_NOTIFICATIONS_PER_MINUTE = 6;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/") return new Response(`${APP_NAME} relay\n`);

    const agent = url.pathname.match(/^\/v1\/agent\/([^/]+)$/);
    const phone = url.pathname.match(/^\/v1\/m\/([^/]+)\/(pair|hello|command)$/);
    const machineId = agent?.[1] ?? phone?.[1];
    if (!machineId) return json(404, { error: "Not found." });
    if (!MACHINE_ID.test(machineId)) return json(400, { error: "Invalid machine id." });

    const machine = env.MACHINES.get(env.MACHINES.idFromName(machineId));
    return machine.fetch(request);
  },
} satisfies ExportedHandler<Env>;

export class Machine extends DurableObject<Env> {
  private pending = new Map<string, Pending>();
  private notifiedAt: number[] = [];

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // Agents ping every 20 s to keep NAT mappings alive; answering here doesn't wake the object.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    return url.pathname.startsWith("/v1/agent/") ? this.connectAgent(request) : this.forward(request, url);
  }

  /// The first agent to connect for a machine id claims it with its secret; later connections must match.
  private async connectAgent(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return json(426, { error: "Expected a WebSocket upgrade." });
    }
    const secret = request.headers.get("Authorization")?.match(/^Bearer (.{32,256})$/)?.[1];
    if (!secret) return json(401, { error: "Missing agent secret." });

    const hash = await sha256(secret);
    const claimed = await this.ctx.storage.get<string>("agentSecretHash");
    if (claimed === undefined) {
      await this.ctx.storage.put("agentSecretHash", hash);
    } else if (!timingSafeEqual(claimed, hash)) {
      return json(403, { error: "This machine id belongs to another agent." });
    }

    // A reconnect replaces the previous connection, which is usually already dead.
    for (const socket of this.ctx.getWebSockets()) {
      this.rejectPending(socket);
      try {
        socket.close(4000, "Replaced by a newer connection");
      } catch {}
    }
    const { 0: client, 1: server } = new WebSocketPair();
    this.ctx.acceptWebSocket(server, [String(Date.now())]);
    return new Response(null, { status: 101, webSocket: client });
  }

  private async forward(request: Request, url: URL): Promise<Response> {
    if (request.method !== "POST") return json(405, { error: "Use POST." });
    const body = await readText(request, MAX_BODY);
    if (body === undefined) return json(413, { error: "Request too large." });
    if (this.pending.size >= MAX_PENDING) return json(429, { error: "Too many requests are waiting for your computer. Try again." });

    const agent = this.currentAgent();
    if (!agent) {
      return json(503, { error: `Your computer isn't connected to ${APP_NAME} right now. It may be asleep, offline or not running the app.` });
    }

    const id = crypto.randomUUID();
    const path = "/v1/" + url.pathname.split("/").pop();
    const answer = await new Promise<{ status: number; body: string }>((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        resolve({ status: 504, body: JSON.stringify({ error: "Your computer didn't answer in time." }) });
      }, ANSWER_TIMEOUT_MS);
      this.pending.set(id, { socket: agent, resolve, timer });
      try {
        agent.send(JSON.stringify({ id, path, body }));
      } catch {
        clearTimeout(timer);
        this.pending.delete(id);
        resolve({ status: 503, body: JSON.stringify({ error: "Your computer just disconnected. Try again." }) });
      }
    });
    return new Response(answer.body, {
      status: answer.status,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    });
  }

  async webSocketMessage(_socket: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== "string") return;
    let answer: { id?: unknown; status?: unknown; body?: unknown; notify?: unknown };
    try {
      answer = JSON.parse(message);
    } catch {
      return;
    }
    if (answer.notify !== undefined) return this.notify(answer.notify);
    if (typeof answer.id !== "string") return;
    const pending = this.pending.get(answer.id);
    if (!pending) return;
    this.pending.delete(answer.id);
    clearTimeout(pending.timer);
    const status = typeof answer.status === "number" && answer.status >= 200 && answer.status < 600 ? answer.status : 502;
    pending.resolve({ status, body: typeof answer.body === "string" ? answer.body : "" });
  }

  async webSocketClose(socket: WebSocket, code: number, reason: string): Promise<void> {
    this.rejectPending(socket);
    try {
      socket.close(code, reason);
    } catch {}
  }

  async webSocketError(socket: WebSocket): Promise<void> {
    await this.webSocketClose(socket, 1011, "WebSocket error");
  }

  private rejectPending(socket: WebSocket): void {
    for (const [id, pending] of this.pending) {
      if (pending.socket !== socket) continue;
      this.pending.delete(id);
      clearTimeout(pending.timer);
      pending.resolve({ status: 503, body: JSON.stringify({ error: "Your computer just disconnected. Try again." }) });
    }
  }

  /// Pushes "<machineName> is waiting for you" to the iPhones the computer named. Only the computer's own
  /// connection gets here, and the text is fixed apart from its name, so it can't push anything else.
  private async notify(request: unknown): Promise<void> {
    const { machineName, pushTokens } = (request ?? {}) as { machineName?: unknown; pushTokens?: unknown };
    if (typeof machineName !== "string" || !machineName.trim() || !Array.isArray(pushTokens)) return;
    const tokens = [...new Set(pushTokens.filter((token): token is string => typeof token === "string" && PUSH_TOKEN.test(token)))];
    if (tokens.length === 0) return;
    if (tokens.length > MAX_PUSH_TOKENS) {
      console.log(`A computer named ${tokens.length} iPhones; notifying the first ${MAX_PUSH_TOKENS}.`);
      tokens.length = MAX_PUSH_TOKENS;
    }

    const now = Date.now();
    this.notifiedAt = this.notifiedAt.filter((time) => now - time < 60_000);
    if (this.notifiedAt.length >= MAX_NOTIFICATIONS_PER_MINUTE) return;
    this.notifiedAt.push(now);

    const { APNS_KEY, APNS_KEY_ID, APNS_TEAM_ID, APNS_TOPIC } = this.env;
    if (!APNS_KEY || !APNS_KEY_ID || !APNS_TEAM_ID || !APNS_TOPIC) {
      console.log("Not sending a notification: the APNs key isn't set up.");
      return;
    }
    const name = Array.from(machineName.trim()).slice(0, 100).join("");
    const payload = JSON.stringify({
      aps: {
        alert: { title: `${name} is waiting for you`, body: `Tap to approve or deny with ${APP_NAME}.` },
        sound: "default",
        "interruption-level": "time-sensitive",
      },
    });
    try {
      const authorization = `bearer ${await providerToken(APNS_KEY, APNS_KEY_ID, APNS_TEAM_ID)}`;
      await Promise.all(tokens.map((token) => push(token, payload, {
        authorization,
        "apns-topic": APNS_TOPIC,
        "apns-push-type": "alert",
        "apns-priority": "10",
        // Requests stop waiting within two minutes; a later notification would point at nothing.
        "apns-expiration": String(Math.floor(now / 1000) + 120),
        // A newer notification for this computer replaces the previous one (the id is 64 hex digits, APNs' limit).
        "apns-collapse-id": this.ctx.id.toString(),
      })));
    } catch (error) {
      console.log(`Couldn't send a notification: ${error}`);
    }
  }

  /// The newest open connection (tagged with its connect time).
  private currentAgent(): WebSocket | undefined {
    let newest: WebSocket | undefined;
    let newestTime = -1;
    for (const socket of this.ctx.getWebSockets()) {
      if (socket.readyState !== WebSocket.OPEN) continue;
      const time = Number(this.ctx.getTags(socket)[0] ?? 0);
      if (time > newestTime) {
        newest = socket;
        newestTime = time;
      }
    }
    return newest;
  }
}

const APNS_HOSTS = ["https://api.push.apple.com", "https://api.sandbox.push.apple.com"];

/// Sends to production APNs, or to the sandbox for an app installed from Xcode, whose tokens only work there.
async function push(token: string, payload: string, headers: Record<string, string>): Promise<void> {
  for (const host of APNS_HOSTS) {
    const response = await fetch(`${host}/3/device/${token}`, { method: "POST", headers, body: payload });
    if (response.ok) return;
    const reason = await response.json<{ reason?: string }>().then((body) => body.reason, () => undefined);
    if (reason === "BadDeviceToken" && host !== APNS_HOSTS[APNS_HOSTS.length - 1]) continue;
    console.log(`APNs refused a notification: ${response.status} ${reason ?? ""}`);
    return;
  }
}

/// APNs takes a JWT signed with the APNs key, renewed between 20 and 60 minutes after it was made.
let cachedProviderToken: { value: string; madeAt: number } | undefined;

async function providerToken(pem: string, keyId: string, teamId: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  if (cachedProviderToken && now - cachedProviderToken.madeAt < 45 * 60) return cachedProviderToken.value;
  const der = Uint8Array.from(atob(pem.replace(/-----[^-]+-----|\s/g, "")), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const encode = (value: object) => base64URL(new TextEncoder().encode(JSON.stringify(value)));
  const unsigned = `${encode({ alg: "ES256", kid: keyId })}.${encode({ iss: teamId, iat: now })}`;
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(unsigned));
  cachedProviderToken = { value: `${unsigned}.${base64URL(new Uint8Array(signature))}`, madeAt: now };
  return cachedProviderToken.value;
}

function base64URL(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/// The body as text, reading no more than `limit` bytes; undefined if it's larger.
async function readText(request: Request, limit: number): Promise<string | undefined> {
  if (Number(request.headers.get("Content-Length") ?? 0) > limit) return undefined;
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      return undefined;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

function json(status: number, value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

async function sha256(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}
