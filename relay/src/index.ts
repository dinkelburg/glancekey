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
//
// And it keeps the iPhones' lock screen cards (Live Activities) up to date. Each card has its own Durable Object
// (`Card`): the iPhone POSTs /v1/card/<cardId> with where to push it and which computers it lists, and each computer
// sends {"card": {"cards", "locked", "approvals"}} over its WebSocket whenever that changes. The card stores the
// latest of each computer and pushes the whole card. What the card shows is what the relay already carries; its
// buttons open the app. For an iPhone with a card, the card also does the notifying: a new request lights up the
// iPhone through the card, and only comes as a notification when there's no card to do that.

// The app's name, as in Core/Sources/AppCore/Brand.swift, which explains how to rename the app. The relay's
// own name and address are in wrangler.jsonc.
const APP_NAME = "GlanceKey";

export interface Env {
  MACHINES: DurableObjectNamespace<Machine>;
  CARDS: DurableObjectNamespace<Card>;
  /// The APNs key (the .p8 file's contents), a secret: `npx wrangler secret put APNS_KEY < AuthKey_<id>.p8`.
  /// Without it the relay sends no notifications.
  APNS_KEY?: string;
  /// The rest is in wrangler.jsonc: the key's ID, the Apple team that owns it and the iPhone app's bundle ID.
  APNS_KEY_ID?: string;
  APNS_TEAM_ID?: string;
  APNS_TOPIC?: string;
  /// What the App Store app allows without the subscription, on this relay (FreeLimits in
  /// Core/Sources/AppCore/FreeTier.swift): computers, and unlocks and approvals a day. In wrangler.jsonc, so the
  /// limits change with a deploy instead of an app update; null or left out is no limit. The iPhone counts its own use
  /// and asks Apple about the subscription, so the relay never sees either.
  FREE_LIMITS?: { computers?: number | null; perDay?: number | null };
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
/// A card's id: the SHA-256 (hex) of a secret only the iPhone knows (Core/Sources/AppCore/Protocol.swift, CardId).
const CARD_ID = /^[0-9a-f]{64}$/;
/// Card updates a computer may send per minute. They come when it locks, unlocks or a request comes or goes.
const MAX_CARD_UPDATES_PER_MINUTE = 30;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/") return new Response(`${APP_NAME} relay\n`);
    if (url.pathname === "/v1/limits") return json(200, freeLimits(env.FREE_LIMITS));

    const card = url.pathname.match(/^\/v1\/card\/([^/]+)$/);
    if (card) {
      if (!CARD_ID.test(card[1])) return json(400, { error: "Invalid card id." });
      return env.CARDS.get(env.CARDS.idFromName(card[1])).fetch(request);
    }

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
  private cardUpdatedAt: number[] = [];

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // Agents ping every 20 s to keep NAT mappings alive; answering here doesn't wake the object.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    // The cards need the machine id, which the Durable Object only knows hashed. Every path has it (this object is
    // idFromName of it), so a connection made while an older version ran still gets it with the iPhone's next request.
    const machineId = url.pathname.split("/")[3];
    if (await this.ctx.storage.get<string>("machineId") !== machineId) await this.ctx.storage.put("machineId", machineId);
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
    let answer: { id?: unknown; status?: unknown; body?: unknown; notify?: unknown; card?: unknown };
    try {
      answer = JSON.parse(message);
    } catch {
      return;
    }
    if (answer.notify !== undefined) return this.notify(answer.notify);
    if (answer.card !== undefined) return this.updateCards(answer.card);
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
    // Gone for good, not replaced by a newer connection: its cards show it as offline.
    if (!this.ctx.getWebSockets().some((other) => other !== socket && other.readyState === WebSocket.OPEN)) {
      await this.sendToCards(await this.ctx.storage.get<string[]>("cards") ?? [], null);
    }
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

    // A newer notification for this computer replaces the previous one.
    await sendNotification(this.env, tokens, machineName, this.ctx.id.toString());
  }

  /// The computer's part of its iPhones' lock screen cards: passed on to each card, and to cards it no longer lists
  /// (that iPhone turned its card off or was removed) as gone. Only the computer's own connection gets here.
  private async updateCards(request: unknown): Promise<void> {
    const update = cardUpdate(request);
    if (!update) return;
    const now = Date.now();
    this.cardUpdatedAt = this.cardUpdatedAt.filter((time) => now - time < 60_000);
    if (this.cardUpdatedAt.length >= MAX_CARD_UPDATES_PER_MINUTE) return;
    this.cardUpdatedAt.push(now);

    const previous = await this.ctx.storage.get<string[]>("cards") ?? [];
    await this.ctx.storage.put("cards", update.cards);
    await Promise.all([
      this.sendToCards(update.cards, update.entry),
      this.sendToCards(previous.filter((card) => !update.cards.includes(card)), undefined),
    ]);
  }

  /// `entry` null: the computer is offline; undefined: it left the card.
  private async sendToCards(cards: string[], entry: CardEntry | null | undefined): Promise<void> {
    const machineId = await this.ctx.storage.get<string>("machineId");
    if (!machineId || cards.length === 0) return;
    await Promise.all(cards.map(async (card) => {
      try {
        await this.env.CARDS.get(this.env.CARDS.idFromName(card)).update(machineId, entry);
      } catch (error) {
        console.log(`Couldn't update a card: ${error}`);
      }
    }));
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

// MARK: - Lock screen cards

/// What the iPhone's card shows for each computer. Keep in sync with iOS/Shared/LiveCard.swift.
type ComputerState = "locked" | "unlocked" | "offline" | "unknown";
const COMPUTER_STATES: ComputerState[] = ["locked", "unlocked", "offline", "unknown"];

interface CardComputer {
  id: string;
  name: string;
  /// What the iPhone saw when it last asked, for a computer that hasn't sent its part yet (or runs an older version).
  state: ComputerState;
}

/// A request waiting for approval; `until` in seconds since 1970.
interface CardWaiting {
  id: string;
  title: string;
  detail: string;
  until: number;
}

/// A computer's part of a card, from its last {"card": …} message.
export interface CardEntry {
  locked: boolean | null;
  approvals: CardWaiting[];
}

interface StoredEntry extends CardEntry {
  online: boolean;
  at: number;
}

/// What the iPhone registered: where to push and what to list.
interface CardSettings {
  computers: CardComputer[];
  /// Notifications are on: a new request makes the card light up the iPhone with a sound, or, when there's no card
  /// to do that, comes as a notification to `pushToken`. The computers leave this iPhone out of their own `notify`.
  alerts: boolean;
  pushToken?: string;
  /// Goes into the card's links, so the app can tell they came from its own card and not from a web page.
  key: string;
  /// Starts a new card (push-to-start).
  startToken?: string;
  /// Updates the running card.
  updateToken?: string;
  /// When the running card started, in seconds since 1970.
  startedAt?: number;
}

/// iOS ends a Live Activity after eight hours; after that only a new one shows.
const CARD_LIFETIME_SECONDS = 8 * 3600 - 300;
/// Starting a card lights up the iPhone, and Apple limits how often apps may, so not more often than this.
const MIN_START_INTERVAL_MS = 10 * 60_000;
const MAX_CARD_COMPUTERS = 8;
/// The longest a request waits: "until answered" (ApprovalWait in Core/Sources/AppCore/Protocol.swift).
const MAX_APPROVAL_WAIT_SECONDS = 24 * 60 * 60;
const MAX_CARD_REQUESTS = 3;
const MAX_CARD_ENTRIES = 16;
const MAX_REGISTRATIONS_PER_MINUTE = 20;
const LIVE_ACTIVITY_TOKEN = /^[0-9A-Fa-f]{32,1024}$/;
const CARD_KEY = /^[A-Za-z0-9_-]{16,64}$/;

/// One iPhone's lock screen card. The iPhone registers where to push it; the computers on it send their part.
export class Card extends DurableObject<Env> {
  private registeredAt: number[] = [];

  /// POST /v1/card/<cardId> {secret, on, computers, key, alerts, pushToken?, startToken?, updateToken?, startedAt?}.
  /// The id is the SHA-256 of the secret, so only the iPhone can register; the computers only know the id.
  async fetch(request: Request): Promise<Response> {
    if (request.method !== "POST") return json(405, { error: "Use POST." });
    const now = Date.now();
    this.registeredAt = this.registeredAt.filter((time) => now - time < 60_000);
    if (this.registeredAt.length >= MAX_REGISTRATIONS_PER_MINUTE) return json(429, { error: "Too many requests. Try again." });
    this.registeredAt.push(now);

    const text = await readText(request, MAX_BODY);
    if (text === undefined) return json(413, { error: "Request too large." });
    let body: Record<string, unknown>;
    try {
      body = JSON.parse(text) ?? {};
    } catch {
      return json(400, { error: "Bad request." });
    }
    const cardId = new URL(request.url).pathname.split("/").pop() ?? "";
    if (typeof body.secret !== "string" || body.secret.length < 16 || body.secret.length > 256 ||
        !timingSafeEqual(await sha256(body.secret), cardId)) {
      return json(403, { error: "Wrong card secret." });
    }

    const previous = await this.ctx.storage.get<CardSettings>("settings");
    if (body.on === false) {
      if (previous?.updateToken) await this.pushCard(previous.updateToken, previous, "end");
      await this.ctx.storage.deleteAlarm();
      await this.ctx.storage.deleteAll();
      return json(200, { ok: true });
    }
    if (typeof body.key !== "string" || !CARD_KEY.test(body.key) || !Array.isArray(body.computers)) {
      return json(400, { error: "Bad request." });
    }
    const computers = body.computers.flatMap((value): CardComputer[] => {
      const { id, name, state } = (value ?? {}) as { id?: unknown; name?: unknown; state?: unknown };
      if (typeof id !== "string" || !MACHINE_ID.test(id) || typeof name !== "string" || !name.trim()) return [];
      return [{ id, name: clip(name.trim(), 60), state: COMPUTER_STATES.includes(state as ComputerState) ? state as ComputerState : "unknown" }];
    }).slice(0, MAX_CARD_COMPUTERS);
    // Left out: keep the one registered before. Anything other than a token removes it.
    function token(value: unknown, current: string | undefined): string | undefined {
      if (value === undefined) return current;
      return typeof value === "string" && LIVE_ACTIVITY_TOKEN.test(value) ? value : undefined;
    }
    const settings: CardSettings = {
      computers,
      alerts: body.alerts === true,
      pushToken: typeof body.pushToken === "string" && PUSH_TOKEN.test(body.pushToken) ? body.pushToken : undefined,
      key: body.key,
      startToken: token(body.startToken, previous?.startToken),
      updateToken: token(body.updateToken, previous?.updateToken),
      startedAt: previous?.startedAt,
    };
    if (settings.updateToken !== previous?.updateToken) {
      // A new card: the iPhone says when it started, which can't be later than now.
      const startedAt = typeof body.startedAt === "number" && Number.isFinite(body.startedAt) ? body.startedAt : now / 1000;
      settings.startedAt = settings.updateToken ? Math.floor(Math.min(startedAt, now / 1000)) : undefined;
    }
    await this.ctx.storage.put("settings", settings);

    // Computers the iPhone no longer lists leave the card.
    const entries = await this.entries();
    const listed = new Set(computers.map((computer) => computer.id));
    for (const id of Object.keys(entries)) if (!listed.has(id)) delete entries[id];
    await this.ctx.storage.put("entries", entries);
    // Something changed while the card had nowhere to go (it was just starting): push it now.
    if (settings.updateToken && settings.updateToken !== previous?.updateToken && await this.ctx.storage.get<boolean>("dirty")) {
      await this.schedulePush();
    }
    return json(200, { ok: true });
  }

  /// A computer's part, from its Machine. null: it went offline; undefined: it left the card.
  async update(machineId: string, entry: CardEntry | null | undefined): Promise<void> {
    const entries = await this.entries();
    const before = entries[machineId];
    const now = Math.floor(Date.now() / 1000);
    if (entry === undefined) {
      delete entries[machineId];
    } else if (entry === null) {
      if (!before) return;
      entries[machineId] = { ...before, online: false, approvals: [], at: now };
    } else {
      entries[machineId] = { ...entry, online: true, at: now };
    }
    if (sameEntry(before, entries[machineId])) return;
    // Keep the newest few, so computers that aren't on the card can't fill it up.
    const ids = Object.keys(entries).sort((a, b) => entries[b].at - entries[a].at);
    for (const id of ids.slice(MAX_CARD_ENTRIES)) delete entries[id];
    await this.ctx.storage.put("entries", entries);

    // Worth lighting up the iPhone for (and starting a new card): a computer that's now locked, or a new request.
    const settings = await this.ctx.storage.get<CardSettings>("settings");
    const listed = settings?.computers.some((computer) => computer.id === machineId) ?? false;
    const newlyLocked = entry?.locked === true && (!before || !before.online || before.locked !== true);
    const newRequest = entry?.approvals.some((waiting) => !before?.approvals.some((old) => old.id === waiting.id)) ?? false;
    if (listed && (newlyLocked || newRequest)) {
      await this.ctx.storage.put("news", newRequest ? { machineId, reason: "request" } : { machineId, reason: "locked" });
    }
    await this.schedulePush();
  }

  /// Pushes after a short wait, so changes that come together go out as one, at most one push a second.
  private async schedulePush(): Promise<void> {
    await this.ctx.storage.put("pushWanted", true);
    const last = await this.ctx.storage.get<number>("pushedAt") ?? 0;
    await this.alarmBy(Math.max(Date.now() + 300, last + 1000));
  }

  private async alarmBy(time: number): Promise<void> {
    const current = await this.ctx.storage.getAlarm();
    if (current === null || current > time) await this.ctx.storage.setAlarm(time);
  }

  /// Pushes what's wanted, and drops requests once they expire, so their commands aren't kept any longer.
  async alarm(): Promise<void> {
    const entries = await this.entries();
    const now = Math.floor(Date.now() / 1000);
    let expired = false;
    for (const entry of Object.values(entries)) {
      const left = entry.approvals.filter((waiting) => waiting.until > now);
      expired ||= left.length !== entry.approvals.length;
      entry.approvals = left;
    }
    if (expired) await this.ctx.storage.put("entries", entries);
    const wanted = expired || (await this.ctx.storage.get<boolean>("pushWanted") ?? false);
    await this.ctx.storage.delete("pushWanted");
    const settings = await this.ctx.storage.get<CardSettings>("settings");
    if (wanted && settings && settings.computers.length > 0) await this.push(settings);
    const next = Math.min(...Object.values(entries).flatMap((entry) => entry.approvals.map((waiting) => waiting.until)));
    if (Number.isFinite(next)) await this.alarmBy(next * 1000 + 500);
  }

  private async push(settings: CardSettings): Promise<void> {
    const now = Date.now();
    await this.ctx.storage.put("pushedAt", now);
    const news = await this.ctx.storage.get<{ machineId: string; reason: "locked" | "request" }>("news");
    await this.ctx.storage.delete("news");
    const name = settings.computers.find((computer) => computer.id === news?.machineId)?.name ?? "Your computer";
    // A new request alerts you, with notifications on: through the card when there is one, else as a notification.
    const alerts = news?.reason === "request" && settings.alerts;
    const waiting = { title: `${name} is waiting for you`, body: "Approve it on the card.", sound: alerts };

    const running = settings.updateToken && settings.startedAt && now / 1000 - settings.startedAt < CARD_LIFETIME_SECONDS;
    if (running) {
      const result = await this.pushCard(settings.updateToken!, settings, "update", alerts ? waiting : undefined);
      if (result.gone) {
        // The card ended (swiped away, or iOS ended it): start a new one with the next change worth it.
        await this.ctx.storage.put("settings", { ...settings, updateToken: undefined, startedAt: undefined });
      }
      if (alerts && !result.ok) await this.notifyInstead(settings, name);
      await this.ctx.storage.put("dirty", !result.ok);
      return;
    }
    const startedAt = await this.ctx.storage.get<number>("startedCardAt") ?? 0;
    if (news && settings.startToken && now - startedAt >= MIN_START_INTERVAL_MS) {
      const alert = news.reason === "request" ? waiting : { title: `${name} is locked`, body: "Unlock it from the card.", sound: false };
      const result = await this.pushCard(settings.startToken, settings, "start", alert);
      if (result.ok) {
        await this.ctx.storage.put("startedCardAt", now);
        // The iPhone sends the new card's update token; until then changes wait (see fetch).
        await this.ctx.storage.put("settings", { ...settings, updateToken: undefined, startedAt: Math.floor(now / 1000) });
        await this.ctx.storage.put("dirty", false);
        return;
      }
    }
    if (alerts) await this.notifyInstead(settings, name);
    await this.ctx.storage.put("dirty", true);
  }

  /// The notification a computer would have sent, for a new request when the card can't alert you itself.
  private async notifyInstead(settings: CardSettings, machineName: string): Promise<void> {
    if (settings.pushToken) await sendNotification(this.env, [settings.pushToken], machineName, this.ctx.id.toString());
  }

  private async entries(): Promise<Record<string, StoredEntry>> {
    return await this.ctx.storage.get<Record<string, StoredEntry>>("entries") ?? {};
  }

  /// The card as the iPhone's LiveCardAttributes.ContentState decodes it.
  private async contentState(settings: CardSettings): Promise<object> {
    const entries = await this.entries();
    const now = Math.floor(Date.now() / 1000);
    const computers = settings.computers.map(({ id, name, state }) => ({ id, name, state: entries[id] ? entryState(entries[id]) : state }));
    const requests = settings.computers.flatMap(({ id }) => (entries[id]?.online ? entries[id].approvals : [])
      .filter((waiting) => waiting.until > now)
      .map((waiting) => ({ computer: id, id: waiting.id, title: clip(waiting.title, 120), detail: clip(waiting.detail, 80), until: waiting.until })))
      .slice(0, MAX_CARD_REQUESTS);
    return { computers, requests, key: settings.key };
  }

  /// `alert` lights up the iPhone and shows the card (with a sound if it says so); a start always needs one.
  private async pushCard(token: string, settings: CardSettings, event: "start" | "update" | "end",
                         alert?: { title: string; body: string; sound: boolean }): Promise<{ ok: boolean; gone?: boolean }> {
    const { APNS_KEY, APNS_KEY_ID, APNS_TEAM_ID, APNS_TOPIC } = this.env;
    if (!APNS_KEY || !APNS_KEY_ID || !APNS_TEAM_ID || !APNS_TOPIC) {
      console.log("Not updating a card: the APNs key isn't set up.");
      return { ok: false };
    }
    const now = Math.floor(Date.now() / 1000);
    const aps: Record<string, unknown> = { timestamp: now, event, "content-state": await this.contentState(settings) };
    if (event === "start") {
      aps["attributes-type"] = "LiveCardAttributes";
      aps.attributes = {};
    }
    if (alert) {
      aps.alert = { title: alert.title, body: alert.body };
      if (alert.sound) aps.sound = "default";
    }
    if (event === "end") aps["dismissal-date"] = now;
    try {
      return await push(token, JSON.stringify({ aps }), {
        authorization: `bearer ${await providerToken(APNS_KEY, APNS_KEY_ID, APNS_TEAM_ID)}`,
        "apns-topic": `${APNS_TOPIC}.push-type.liveactivity`,
        "apns-push-type": "liveactivity",
        "apns-priority": "10",
        "apns-expiration": String(now + 3600),
      });
    } catch (error) {
      console.log(`Couldn't update a card: ${error}`);
      return { ok: false };
    }
  }
}

function entryState(entry: StoredEntry): ComputerState {
  if (!entry.online) return "offline";
  if (entry.locked === null) return "unknown";
  return entry.locked ? "locked" : "unlocked";
}

/// Whether two parts of a card show the same, allowing a deadline to move a little: the computer counts seconds left.
function sameEntry(a: StoredEntry | undefined, b: StoredEntry | undefined): boolean {
  if (!a || !b) return a === b;
  return a.online === b.online && a.locked === b.locked && a.approvals.length === b.approvals.length &&
    a.approvals.every((waiting, i) => {
      const other = b.approvals[i];
      return waiting.id === other.id && waiting.title === other.title && waiting.detail === other.detail &&
        Math.abs(waiting.until - other.until) <= 2;
    });
}

/// Checks a computer's {"card": …} message.
function cardUpdate(request: unknown): { cards: string[]; entry: CardEntry } | undefined {
  const { cards, locked, approvals } = (request ?? {}) as { cards?: unknown; locked?: unknown; approvals?: unknown };
  if (!Array.isArray(cards)) return undefined;
  const ids = [...new Set(cards.filter((card): card is string => typeof card === "string" && CARD_ID.test(card)))].slice(0, MAX_PUSH_TOKENS);
  const now = Math.floor(Date.now() / 1000);
  const waiting = (Array.isArray(approvals) ? approvals : []).flatMap((value): CardWaiting[] => {
    const { id, title, detail, expiresIn } = (value ?? {}) as { id?: unknown; title?: unknown; detail?: unknown; expiresIn?: unknown };
    if (typeof id !== "string" || !id || id.length > 100 || typeof title !== "string" || typeof detail !== "string" ||
        typeof expiresIn !== "number" || !Number.isFinite(expiresIn)) return [];
    return [{ id, title: clip(title, 300), detail: clip(detail, 300), until: now + Math.min(Math.max(Math.round(expiresIn), 0), MAX_APPROVAL_WAIT_SECONDS) }];
  }).slice(0, 5);
  return { cards: ids, entry: { locked: typeof locked === "boolean" ? locked : null, approvals: waiting } };
}

/// The free limits as the app reads them: a whole number of at least 0 each, or null for no limit.
function freeLimits(limits: Env["FREE_LIMITS"]): { computers: number | null; perDay: number | null } {
  const count = (value: unknown) => typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : null;
  return { computers: count(limits?.computers), perDay: count(limits?.perDay) };
}

/// At most `limit` characters, counting emoji and other non-BMP characters as one.
function clip(text: string, limit: number): string {
  const characters = Array.from(text);
  return characters.length <= limit ? text : characters.slice(0, limit - 1).join("") + "…";
}

/// Pushes "<machineName> is waiting for you" to `tokens`. A newer one with the same `collapseId` (64 hex digits, APNs'
/// limit) replaces the previous one.
async function sendNotification(env: Env, tokens: string[], machineName: string, collapseId: string): Promise<void> {
  const { APNS_KEY, APNS_KEY_ID, APNS_TEAM_ID, APNS_TOPIC } = env;
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
  const now = Math.floor(Date.now() / 1000);
  try {
    const authorization = `bearer ${await providerToken(APNS_KEY, APNS_KEY_ID, APNS_TEAM_ID)}`;
    await Promise.all(tokens.map((token) => push(token, payload, {
      authorization,
      "apns-topic": APNS_TOPIC,
      "apns-push-type": "alert",
      "apns-priority": "10",
      // Requests stop waiting within two minutes; a later notification would point at nothing.
      "apns-expiration": String(now + 120),
      "apns-collapse-id": collapseId,
    })));
  } catch (error) {
    console.log(`Couldn't send a notification: ${error}`);
  }
}

const APNS_HOSTS = ["https://api.push.apple.com", "https://api.sandbox.push.apple.com"];

/// Sends to production APNs, or to the sandbox for an app installed from Xcode, whose tokens only work there.
/// Returns false if APNs refused it; `gone` says the token no longer works.
async function push(token: string, payload: string, headers: Record<string, string>): Promise<{ ok: boolean; gone?: boolean }> {
  for (const host of APNS_HOSTS) {
    const response = await fetch(`${host}/3/device/${token}`, { method: "POST", headers, body: payload });
    if (response.ok) return { ok: true };
    const reason = await response.json<{ reason?: string }>().then((body) => body.reason, () => undefined);
    if (reason === "BadDeviceToken" && host !== APNS_HOSTS[APNS_HOSTS.length - 1]) continue;
    console.log(`APNs refused a push: ${response.status} ${reason ?? ""}`);
    return { ok: false, gone: response.status === 410 || reason === "BadDeviceToken" || reason === "Unregistered" || reason === "ExpiredToken" };
  }
  return { ok: false };
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
