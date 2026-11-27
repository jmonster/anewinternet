// The parts of the Workers runtime and of cw-host's WASM bindings that the shim uses.

interface SqlCursor {
  raw(): IterableIterator<unknown[]>;
}
interface SqlStorage {
  exec(query: string, ...bindings: unknown[]): SqlCursor;
}
interface DurableObjectStorage {
  sql: SqlStorage;
  transactionSync<T>(fn: () => T): T;
  setAlarm(at: number): Promise<void>;
  deleteAll(): Promise<void>;
}
interface DurableObjectState {
  storage: DurableObjectStorage;
  acceptWebSocket(ws: WebSocket, tags?: string[]): void;
  getWebSockets(tag?: string): WebSocket[];
  setWebSocketAutoResponse(pair: WebSocketRequestResponsePair): void;
  getWebSocketAutoResponseTimestamp(ws: WebSocket): Date | null;
  waitUntil(promise: Promise<unknown>): void;
}
interface DurableObjectId {}
interface DurableObjectStub {
  fetch(input: Request | string, init?: RequestInit): Promise<Response>;
}
interface DurableObjectNamespace {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): DurableObjectStub;
}
declare class WebSocketRequestResponsePair {
  constructor(request: string, response: string);
}
declare class WebSocketPair {
  0: WebSocket;
  1: WebSocket;
}
interface WebSocket {
  serializeAttachment(value: unknown): void;
  deserializeAttachment(): unknown;
}
interface ResponseInit {
  webSocket?: WebSocket;
}

declare module "*.wasm" {
  const module: WebAssembly.Module;
  export default module;
}

interface Outcome {
  kind: "respond" | "tenant" | "each" | "host" | "accept" | "import" | "missing" | "stored";
  commit: boolean;
  status: number;
  headers: [string, string][];
  body: Uint8Array;
  tenant: string;
  op: string;
  /** For `each`: `[tenant, op]` pairs, and how the host answers once they ran. */
  ops: [string, string][];
  finish: string;
  device: string;
  /** A push socket's first frame. */
  state: string;
  from: string;
  grant: string;
  missing: string[];
  effects: Effect[];
}
type Effect =
  | { t: "event"; text: string }
  | { t: "push"; device: string; endpoint: string; authorization: string }
  | { t: "alarm"; at: number }
  | { t: "close" };
interface SqlBridge {
  exec(query: string, params: unknown[]): unknown[][];
}
