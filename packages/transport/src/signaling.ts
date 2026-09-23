import {
  parseIdentityPublicKey,
  type IdentityPublicKey,
} from "@p2pcards/protocol";

import { MAX_SIGNALING_MESSAGE_BYTES } from "./signaling-message";

export type SignalingMessageHandler = (
  from: IdentityPublicKey,
  payload: Uint8Array,
) => void;

export interface SignalingAdapter {
  join(roomId: string, self: Uint8Array): Promise<void>;
  send(to: Uint8Array, payload: Uint8Array): Promise<void>;
  onMessage(callback: SignalingMessageHandler): void;
  leave(): Promise<void>;
}

export class InMemorySignalingNetwork {
  readonly #rooms = new Map<string, Map<string, InMemorySignalingAdapter>>();

  createAdapter(): InMemorySignalingAdapter {
    return new InMemorySignalingAdapter(this);
  }

  join(adapter: InMemorySignalingAdapter, roomId: string, identity: IdentityPublicKey): void {
    const room = this.#rooms.get(roomId) ?? new Map<string, InMemorySignalingAdapter>();
    const key = identityKey(identity);
    if (room.has(key)) {
      throw new Error("Signaling identity is already present in the room");
    }
    room.set(key, adapter);
    this.#rooms.set(roomId, room);
  }

  leave(adapter: InMemorySignalingAdapter, roomId: string, identity: IdentityPublicKey): void {
    const room = this.#rooms.get(roomId);
    if (room === undefined) {
      return;
    }
    const key = identityKey(identity);
    if (room.get(key) === adapter) {
      room.delete(key);
    }
    if (room.size === 0) {
      this.#rooms.delete(roomId);
    }
  }

  async send(
    sender: InMemorySignalingAdapter,
    roomId: string,
    from: IdentityPublicKey,
    to: IdentityPublicKey,
    payload: Uint8Array,
  ): Promise<void> {
    const recipient = this.#rooms.get(roomId)?.get(identityKey(to));
    if (recipient === undefined) {
      throw new Error("Signaling recipient is not present in the room");
    }
    const message = payload.slice();
    await new Promise<void>((resolve, reject) => {
      queueMicrotask(() => {
        if (!sender.isJoinedAs(roomId, from) || !recipient.isJoinedAs(roomId, to)) {
          reject(new Error("Signaling membership changed before delivery"));
          return;
        }
        try {
          recipient.deliver(from, message);
          resolve();
        } catch (cause) {
          reject(cause);
        }
      });
    });
  }
}

export class InMemorySignalingAdapter implements SignalingAdapter {
  readonly #network: InMemorySignalingNetwork;
  #roomId: string | null = null;
  #identity: IdentityPublicKey | null = null;
  #handler: SignalingMessageHandler | null = null;

  constructor(network: InMemorySignalingNetwork) {
    if (!(network instanceof InMemorySignalingNetwork)) {
      throw new TypeError("In-memory signaling adapter requires a network");
    }
    this.#network = network;
  }

  async join(roomId: string, self: Uint8Array): Promise<void> {
    if (this.#roomId !== null) {
      throw new Error("Signaling adapter is already joined");
    }
    const normalizedRoomId = parseSignalingRoomId(roomId);
    const identity = parseIdentityPublicKey(self);
    this.#network.join(this, normalizedRoomId, identity);
    this.#roomId = normalizedRoomId;
    this.#identity = identity;
  }

  async send(to: Uint8Array, payload: Uint8Array): Promise<void> {
    if (this.#roomId === null || this.#identity === null) {
      throw new Error("Signaling adapter is not joined");
    }
    const recipient = parseIdentityPublicKey(to);
    requirePayload(payload);
    if (identityKey(recipient) === identityKey(this.#identity)) {
      throw new Error("Signaling adapter cannot send to itself");
    }
    await this.#network.send(this, this.#roomId, this.#identity, recipient, payload);
  }

  onMessage(callback: SignalingMessageHandler): void {
    if (typeof callback !== "function") {
      throw new TypeError("Signaling message handler must be a function");
    }
    this.#handler = callback;
  }

  async leave(): Promise<void> {
    if (this.#roomId === null || this.#identity === null) {
      return;
    }
    this.#network.leave(this, this.#roomId, this.#identity);
    this.#roomId = null;
    this.#identity = null;
  }

  isJoinedAs(roomId: string, identity: IdentityPublicKey): boolean {
    return this.#roomId === roomId &&
      this.#identity !== null &&
      identityKey(this.#identity) === identityKey(identity);
  }

  deliver(from: IdentityPublicKey, payload: Uint8Array): void {
    if (this.#handler === null) {
      throw new Error("Signaling recipient has no message handler");
    }
    this.#handler(parseIdentityPublicKey(from), payload.slice());
  }
}

export function parseSignalingRoomId(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new TypeError("Signaling room ID must be 64 lowercase hexadecimal characters");
  }
  return value;
}

function requirePayload(value: Uint8Array): void {
  if (!(value instanceof Uint8Array) || value.constructor !== Uint8Array) {
    throw new TypeError("Signaling payload must be a Uint8Array");
  }
  if (value.length > MAX_SIGNALING_MESSAGE_BYTES) {
    throw new RangeError(
      `Signaling payload must not exceed ${MAX_SIGNALING_MESSAGE_BYTES} bytes`,
    );
  }
}

function identityKey(identity: Uint8Array): string {
  return Array.from(identity, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
