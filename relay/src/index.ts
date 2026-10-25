import { DurableObject } from "cloudflare:workers";

// The relay. Computers (the Mac app, the Linux agent) keep a WebSocket open to
// /v1/agent/<machineId>; the iPhone POSTs to /v1/m/<machineId>/{pair,hello,command}. One Durable Object per
// machine passes each request down that WebSocket and returns the answer.
//
// The relay is not trusted: every command is signed by the iPhone's Secure Enclave key and checked on the
// computer, and pairing proves knowledge of the QR code without sending it. The relay only routes.

// The app's name, as in Core/Sources/AppCore/Brand.swift, which explains how to rename the app. The relay's
// own name and address are in wrangler.jsonc.
const APP_NAME = "GlanceKey";

export interface Env {
  MACHINES: DurableObjectNamespace<Machine>;
}

interface Pending {
  socket: WebSocket;
  resolve: (answer: { status: number; body: string }) => void;
  timer: ReturnType<typeof setTimeout>;
}

const MACHINE_ID = /^[A-Za-z0-9-]{8,64}$/;
const MAX_BODY = 16 * 1024;
const ANSWER_TIMEOUT_MS = 25_000;

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
    const body = await request.text();
    if (body.length > MAX_BODY) return json(413, { error: "Request too large." });

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
    let answer: { id?: unknown; status?: unknown; body?: unknown };
    try {
      answer = JSON.parse(message);
    } catch {
      return;
    }
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
