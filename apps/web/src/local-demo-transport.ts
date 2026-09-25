import { bytesToHex } from "@p2pcards/crypto";
import { parseIdentityPublicKey, type IdentityPublicKey } from "@p2pcards/protocol";

import type { LobbyTransportLike, LobbyTransportOptions } from "./lobby-transport";

type LocalOptions = Omit<LobbyTransportOptions, "signaling" | "createPeerConnection">;

/** Delivers demo traffic inside this tab. Signed game messages still pass through the normal receivers. */
export class LocalDemoTransportNetwork {
  readonly #rooms = new Map<string, Map<string, LocalDemoTransport>>();

  createTransport(options: LocalOptions): LobbyTransportLike {
    return new LocalDemoTransport(this, options);
  }

  join(transport: LocalDemoTransport): void {
    const room = this.#rooms.get(transport.roomId) ?? new Map<string, LocalDemoTransport>();
    if (room.has(transport.key)) throw new Error("This demo identity is already at the table");
    room.set(transport.key, transport);
    this.#rooms.set(transport.roomId, room);
    for (const other of room.values()) {
      if (other === transport) continue;
      this.connect(transport, other);
      this.connect(other, transport);
    }
  }

  find(roomId: string, identity: IdentityPublicKey): LocalDemoTransport | undefined {
    return this.#rooms.get(roomId)?.get(bytesToHex(identity));
  }

  connect(from: LocalDemoTransport, to: LocalDemoTransport): void {
    if (from.closed || to.closed || from === to || from.has(to.identity) || !from.wants(to.identity) || !to.accepts(from.identity)) return;
    from.attach(to);
    to.attach(from);
    queueMicrotask(() => { from.notifyAuthenticated(to); to.notifyAuthenticated(from); });
  }

  disconnect(from: LocalDemoTransport, to: LocalDemoTransport): void {
    if (!from.has(to.identity)) return;
    from.detach(to.identity);
    to.detach(from.identity);
  }

  leave(transport: LocalDemoTransport): void {
    const room = this.#rooms.get(transport.roomId);
    if (room?.get(transport.key) !== transport) return;
    for (const other of room.values()) if (other !== transport) this.disconnect(transport, other);
    room.delete(transport.key);
    if (room.size === 0) this.#rooms.delete(transport.roomId);
  }
}

class LocalDemoTransport implements LobbyTransportLike {
  readonly identity: IdentityPublicKey;
  readonly key: string;
  readonly roomId: string;
  readonly #network: LocalDemoTransportNetwork;
  readonly #options: LocalOptions;
  readonly #known: Set<string>;
  readonly #peers = new Map<string, { readonly remote: LocalDemoTransport; readonly generation: number }>();
  #nextGeneration = 1;
  #started = false;
  closed = false;

  constructor(network: LocalDemoTransportNetwork, options: LocalOptions) {
    this.#network = network;
    this.#options = options;
    this.identity = parseIdentityPublicKey(options.identity.publicKey);
    this.key = bytesToHex(this.identity);
    this.roomId = options.roomId;
    this.#known = new Set(options.roster.map(bytesToHex));
  }

  get peers() {
    return [...this.#peers.values()].map(({ remote, generation }) => ({ identity: remote.identity, generation, connectionState: "connected" as const }));
  }

  wants(remote: IdentityPublicKey): boolean { return this.#known.has(bytesToHex(remote)); }
  accepts(remote: IdentityPublicKey): boolean {
    if (this.wants(remote)) return true;
    if (!this.#options.onUnknownPeer(remote)) return false;
    this.#known.add(bytesToHex(remote));
    return true;
  }
  has(remote: IdentityPublicKey): boolean { return this.#peers.has(bytesToHex(remote)); }
  authenticated(remote: IdentityPublicKey): boolean { return this.has(remote); }
  generation(remote: IdentityPublicKey): number | undefined { return this.#peers.get(bytesToHex(remote))?.generation; }

  attach(remote: LocalDemoTransport): void {
    this.#peers.set(remote.key, { remote, generation: this.#nextGeneration++ });
  }

  notifyAuthenticated(remote: LocalDemoTransport): void {
    const peer = this.#peers.get(remote.key);
    if (!peer || this.closed) return;
    try { this.#options.onAuthenticated(remote.identity, peer.generation); this.#options.onChange(); }
    catch (cause) { this.#options.onError(asError(cause), remote.identity); this.#network.disconnect(this, remote); }
  }

  detach(remote: IdentityPublicKey): void {
    if (!this.#peers.delete(bytesToHex(remote)) || this.closed) return;
    this.#options.onDisconnected(remote);
    this.#options.onChange();
  }

  async start(): Promise<void> {
    if (this.#started || this.closed) throw new Error("Demo transport cannot start again");
    this.#started = true;
    this.#network.join(this);
  }

  async admit(remote: IdentityPublicKey): Promise<void> {
    if (this.closed) return;
    this.#known.add(bytesToHex(remote));
    const other = this.#network.find(this.roomId, remote);
    if (other) this.#network.connect(this, other);
  }

  remove(remote: IdentityPublicKey): void {
    this.#known.delete(bytesToHex(remote));
    const other = this.#network.find(this.roomId, remote);
    if (other) this.#network.disconnect(this, other);
  }

  async retry(remote: IdentityPublicKey): Promise<void> {
    const other = this.#network.find(this.roomId, remote);
    if (!other) return;
    this.#known.add(bytesToHex(remote));
    this.#network.disconnect(this, other);
    this.#network.connect(this, other);
  }

  async path(remote: IdentityPublicKey): Promise<{ readonly path: "direct" | "unknown" }> {
    return { path: this.has(remote) ? "direct" : "unknown" };
  }

  async send(remote: IdentityPublicKey, generation: number, payload: Uint8Array): Promise<void> {
    const peer = this.#peers.get(bytesToHex(remote));
    if (this.closed || peer?.generation !== generation) throw new Error("Demo connection was replaced");
    if (payload.length > 65536) throw new Error("Envelope exceeds 64 KiB");
    const target = peer.remote;
    const targetGeneration = target.generation(this.identity);
    if (targetGeneration === undefined) throw new Error("Demo connection is not available");
    const copy = payload.slice();
    queueMicrotask(() => {
      if (this.closed || target.closed || this.generation(target.identity) !== generation || target.generation(this.identity) !== targetGeneration) return;
      void target.#options.onMessage(this.identity, copy, targetGeneration).catch(cause => target.#options.onError(asError(cause), this.identity));
    });
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.#network.leave(this);
  }
}

function asError(cause: unknown): Error { return cause instanceof Error ? cause : new Error("Demo connection failed"); }
