// The Cloudflare Worker for a commonwire host. cw-host (WASM) does all the work; this file connects it to
// Durable Object SQL, hibernatable WebSockets, alarms and fetch. Junk requests are refused here, before
// any Durable Object is called.
import { initSync, Gate, HostHandle, TenantHandle } from "./cw_host.js";
import wasm from "./cw_host_bg.wasm";

initSync({ module: wasm });

interface Env {
  HOST_SECRET: string;
  CLAIM_DIGEST: string;
  VAPID: string;
  ORIGIN: string;
  HOST: DurableObjectNamespace;
  TENANT: DurableObjectNamespace;
}

const ROLLBACK = Symbol("rollback");
const INTERNAL = "cw-internal";
const TENANT = "cw-tenant";
/** How long a push socket may go without a ping (the app sends one every 25 s, hidden tabs about once a minute). */
const SOCKET_SILENCE_MS = 75_000;

function headerList(headers: Headers): [string, string][] {
  const out: [string, string][] = [];
  headers.forEach((value, key) => {
    if (key !== INTERNAL && key !== TENANT) out.push([key, value]);
  });
  return out;
}

function respond(o: Outcome): Response {
  const empty = o.status === 204 || o.status === 304 || o.body.length === 0;
  return new Response(empty ? null : (o.body as unknown as ArrayBuffer), { status: o.status, headers: o.headers });
}

function bridge(sql: SqlStorage): SqlBridge {
  return { exec: (query, params) => Array.from(sql.exec(query, ...params).raw()) };
}

/** Runs `f` in one storage transaction, rolling back when the outcome says not to commit. */
function transact(ctx: DurableObjectState, f: () => Outcome): Outcome {
  let outcome: Outcome | undefined;
  try {
    ctx.storage.transactionSync(() => {
      outcome = f();
      if (!outcome.commit) throw ROLLBACK;
    });
  } catch (e) {
    if (e !== ROLLBACK) throw e;
  }
  return outcome!;
}

function secrets(env: Env): [string, string, string, string] {
  return [env.HOST_SECRET, env.CLAIM_DIGEST, env.VAPID, env.ORIGIN];
}

let gate: Gate | undefined;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    gate ??= new Gate(...secrets(env));
    const url = new URL(request.url);
    const ip = request.headers.get("cf-connecting-ip") ?? "";
    const verdict = gate.check(request.method, url.pathname + url.search, headerList(request.headers), ip, Date.now());
    if (!verdict.ok) return respond(verdict);
    const headers = new Headers(request.headers);
    headers.delete(INTERNAL);
    headers.delete(TENANT);
    const ns = verdict.target === "host" ? env.HOST : env.TENANT;
    if (verdict.target !== "host") headers.set(TENANT, verdict.target);
    return ns.get(ns.idFromName(verdict.target)).fetch(new Request(request, { headers }));
  },
};

function tenantStub(env: Env, tenant: string): DurableObjectStub {
  return env.TENANT.get(env.TENANT.idFromName(tenant));
}

function internal(env: Env, tenant: string, op: string): Promise<Response> {
  return tenantStub(env, tenant).fetch("https://internal/", {
    method: "POST",
    headers: { [INTERNAL]: "1", [TENANT]: tenant },
    body: op,
  });
}

/** An operation a tenant starts on the host's store, such as a guest offer. */
function hostInternal(env: Env, op: string): Promise<Response> {
  return env.HOST.get(env.HOST.idFromName("host")).fetch("https://internal/", {
    method: "POST",
    headers: { [INTERNAL]: "1" },
    body: op,
  });
}

export class Host {
  private handle: HostHandle;
  private sql: SqlBridge;

  constructor(private ctx: DurableObjectState, private env: Env) {
    this.handle = new HostHandle(...secrets(env));
    this.sql = bridge(ctx.storage.sql);
    this.handle.ensure(this.sql);
  }

  async fetch(request: Request): Promise<Response> {
    if (request.headers.get(INTERNAL)) {
      const op = await request.text();
      return respond(transact(this.ctx, () => this.handle.internal(this.sql, op, Date.now())));
    }
    const url = new URL(request.url), received = Date.now();
    const body = new Uint8Array(await request.arrayBuffer());
    const o = transact(this.ctx, () =>
      this.handle.handle(this.sql, request.method, url.host, url.pathname + url.search, headerList(request.headers), body, received, Date.now()),
    );
    if (o.kind === "tenant") return internal(this.env, o.tenant, o.op);
    if (o.kind === "each") {
      const results: [string, number, string][] = [];
      for (const [tenant, op] of o.ops) {
        const r = await internal(this.env, tenant, op);
        results.push([tenant, r.status, await r.text()]);
      }
      return respond(transact(this.ctx, () => this.handle.finish(this.sql, o.finish, JSON.stringify(results))));
    }
    return respond(o);
  }
}

export class Tenant {
  private handle?: TenantHandle;
  private sql: SqlBridge;

  constructor(private ctx: DurableObjectState, private env: Env) {
    this.sql = bridge(ctx.storage.sql);
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
    console.log("tenant object started");
  }

  private open(tenant: string | null): TenantHandle {
    if (!this.handle) {
      if (!tenant) throw new Error("tenant unknown");
      this.handle = new TenantHandle(...secrets(this.env), tenant);
    }
    return this.handle;
  }

  /**
   * The devices with a live push socket. A socket silent for SOCKET_SILENCE_MS belongs to a suspended or vanished
   * device, so it closes here and the device gets Web Push again.
   */
  private sockets(): string[] {
    const now = Date.now();
    const devices: string[] = [];
    for (const ws of this.ctx.getWebSockets()) {
      const a = ws.deserializeAttachment() as { device?: string; opened?: number } | null;
      const heard = Math.max(this.ctx.getWebSocketAutoResponseTimestamp(ws)?.getTime() ?? 0, a?.opened ?? 0);
      if (now - heard > SOCKET_SILENCE_MS) {
        try {
          ws.close(1001, "silent");
        } catch {}
      } else if (typeof a?.device === "string") devices.push(a.device);
    }
    return devices;
  }

  /** Deletes everything this object stores, and the state it holds in memory, so it answers as a tenant never made. */
  private async erase() {
    await this.ctx.storage.deleteAll();
    this.handle = undefined;
  }

  private run(f: (h: TenantHandle) => Outcome): Outcome {
    const handle = this.handle!;
    const o = transact(this.ctx, () => f(handle));
    if (!o.commit) handle.forget();
    for (const e of o.effects ?? []) this.effect(e);
    return o;
  }

  private effect(e: Effect): void {
    switch (e.t) {
      case "event":
        for (const ws of this.ctx.getWebSockets()) {
          try {
            ws.send(e.text);
          } catch {}
        }
        break;
      case "close":
        for (const ws of this.ctx.getWebSockets()) {
          try {
            ws.close(1000, "removed");
          } catch {}
        }
        break;
      case "alarm":
        this.ctx.waitUntil(this.ctx.storage.setAlarm(e.at));
        break;
      case "push":
        this.ctx.waitUntil(this.push(e));
        break;
    }
  }

  private async push(e: { device: string; endpoint: string; authorization: string }): Promise<void> {
    const r = await fetch(e.endpoint, {
      method: "POST",
      headers: { authorization: e.authorization, ttl: "86400", urgency: "high" },
    });
    if (r.status === 404 || r.status === 410) {
      const op = JSON.stringify({ op: "drop-subscription", device: e.device });
      this.run((h) => h.internal(this.sql, op, this.sockets(), Date.now()));
    }
  }

  async fetch(request: Request): Promise<Response> {
    const handle = this.open(request.headers.get(TENANT));
    if (request.headers.get(INTERNAL)) {
      const op = await request.text();
      const o = this.run((h) => h.internal(this.sql, op, this.sockets(), Date.now()));
      if (op === '{"op":"usage"}' && o.status === 200) {
        const usage = JSON.parse(new TextDecoder().decode(o.body));
        if (usage.state === "gone") await this.erase();
      }
      // The host is being destroyed: everything this object stores goes, alarms included.
      if (op === '{"op":"destroy"}') await this.erase();
      return respond(o);
    }
    const url = new URL(request.url), received = Date.now();
    const body = new Uint8Array(await request.arrayBuffer());
    const o = this.run((h) =>
      h.handle(this.sql, request.method, url.host, url.pathname + url.search, headerList(request.headers), body, this.sockets(), received, Date.now()),
    );
    if (o.kind === "accept") {
      const pair = new WebSocketPair();
      const [client, server] = [pair[0], pair[1]];
      this.ctx.acceptWebSocket(server, [o.device]);
      server.serializeAttachment({ device: o.device, opened: Date.now() });
      server.send(o.state);
      return new Response(null, { status: 101, webSocket: client, headers: { "sec-websocket-protocol": "cw1" } });
    }
    if (o.kind === "import") return this.transfer(handle, o.from, o.grant);
    if (o.kind === "host") return hostInternal(this.env, o.op);
    return respond(o);
  }

  private async transfer(handle: TenantHandle, from: string, grant: string): Promise<Response> {
    const failed = (what: string) =>
      new Response(JSON.stringify({ error: `transfer: ${what}` }), { status: 502, headers: { "content-type": "application/json" } });
    const exported = await fetch(`${from}/export`, { headers: { "cw-grant": grant } });
    if (exported.status !== 200) return failed(`export answered ${exported.status}`);
    const bytes = new Uint8Array(await exported.arrayBuffer());
    const m = this.run((h) => h.import_export(this.sql, bytes, Date.now()));
    if (m.kind !== "missing") return respond(m);
    let total = 0;
    for (const name of m.missing) {
      const r = await fetch(`${from}/objects/${name}`, { headers: { "cw-grant": grant } });
      if (r.status !== 200) return failed(`${name} answered ${r.status}`);
      const object = new Uint8Array(await r.arrayBuffer());
      const s = this.run((h) => h.import_object(this.sql, name, object, Date.now()));
      if (s.kind !== "stored") return respond(s);
      total += object.length;
    }
    return respond(handle.import_done(m.missing.length, total));
  }

  async alarm(): Promise<void> {
    const rows = Array.from(this.ctx.storage.sql.exec("SELECT lower(hex(tenant)) FROM tenant WHERE id = 1").raw());
    if (!rows.length) return;
    this.open(String(rows[0][0]));
    this.run((h) => h.internal(this.sql, '{"op":"alarm"}', this.sockets(), Date.now()));
  }

  async webSocketMessage(ws: WebSocket): Promise<void> {
    ws.close(1008, "clients send only ping");
  }

  async webSocketClose(ws: WebSocket, code: number): Promise<void> {
    try {
      ws.close(code === 1005 ? 1000 : code, "closed");
    } catch {}
  }
}
