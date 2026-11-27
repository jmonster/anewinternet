// The parts of cw-host's wasm-bindgen output that the shim uses.
export function initSync(options: { module: WebAssembly.Module }): void;
export class Gate {
  constructor(secret: string, claim: string, vapid: string, origin: string);
  check(method: string, target: string, headers: [string, string][], ip: string, now: number): Outcome & { ok?: boolean; target: string };
}
export class HostHandle {
  constructor(secret: string, claim: string, vapid: string, origin: string);
  ensure(sql: SqlBridge): void;
  handle(sql: SqlBridge, method: string, authority: string, target: string, headers: [string, string][], body: Uint8Array, received: number, now: number): Outcome;
  finish(sql: SqlBridge, finish: string, results: string): Outcome;
  internal(sql: SqlBridge, op: string, now: number): Outcome;
}
export class TenantHandle {
  constructor(secret: string, claim: string, vapid: string, origin: string, tenant: string);
  forget(): void;
  handle(sql: SqlBridge, method: string, authority: string, target: string, headers: [string, string][], body: Uint8Array, sockets: string[], received: number, now: number): Outcome;
  internal(sql: SqlBridge, op: string, sockets: string[], now: number): Outcome;
  import_export(sql: SqlBridge, bytes: Uint8Array, now: number): Outcome;
  import_object(sql: SqlBridge, name: string, bytes: Uint8Array, now: number): Outcome;
  import_done(objects: number, bytes: number): Outcome;
}
