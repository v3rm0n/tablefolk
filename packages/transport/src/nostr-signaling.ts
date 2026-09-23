import {
  asciiToBytes,
  bytesEqual,
  bytesToHex,
  randomBytes,
  sha256,
  systemRandomSource,
  type RandomSource,
} from "@p2pcards/crypto";
import { decodeCanonical, encodeCanonical } from "@p2pcards/encoding";
import {
  expectByteString,
  expectExactMap,
  parseIdentityPublicKey,
  type IdentityPublicKey,
} from "@p2pcards/protocol";
import {
  createEvent as createTrysteroNostrEvent,
  defaultRelayUrls,
} from "trystero/nostr";

import {
  decodeDataFrame,
  encodeDataFrame,
  FrameReassembler,
  MAX_FRAME_PAYLOAD_BYTES,
  splitDataFrames,
} from "./frame";
import { parseSignalingRoomId, type SignalingAdapter, type SignalingMessageHandler } from "./signaling";
import { MAX_SIGNALING_MESSAGE_BYTES } from "./signaling-message";

export const DEFAULT_NOSTR_APP_ID = "p2pcards/v1";
export const DEFAULT_NOSTR_RELAY_REDUNDANCY = 5;
export const DEFAULT_NOSTR_CONNECT_TIMEOUT_MS = 10_000;
export const DEFAULT_MAX_PENDING_NOSTR_EVENTS = 256;
export const DEFAULT_MAX_CONCURRENT_NOSTR_SENDS = 16;
export const DEFAULT_MAX_SEEN_NOSTR_EVENTS = 4_096;
export const DEFAULT_MAX_RETAINED_NOSTR_FAILURES = 128;
export const DEFAULT_MAX_NOSTR_REASSEMBLY_SENDERS = 16;
export const DEFAULT_MAX_PENDING_NOSTR_FRAME_BYTES = MAX_SIGNALING_MESSAGE_BYTES * 2;
export const DEFAULT_NOSTR_PUBLICATION_ACK_TIMEOUT_MS = 5_333;
export const DEFAULT_NOSTR_RECONNECT_BASE_DELAY_MS = 1_000;
export const DEFAULT_NOSTR_RECONNECT_MAX_DELAY_MS = 30_000;
export const DEFAULT_NOSTR_SIGNAL_RETENTION_MS = 30_000;
export const DEFAULT_MAX_RETAINED_NOSTR_PUBLICATIONS = 128;
export const NOSTR_SIGNAL_ENVELOPE_VERSION = 1;
export const NOSTR_SIGNAL_NONCE_BYTES = 12;
export const MAX_NOSTR_EVENT_CONTENT_CHARS = 24 * 1024;
export const MAX_NOSTR_RELAY_MESSAGE_CHARS = 32 * 1024;

const TOPIC_DOMAIN = asciiToBytes("p2pcards/v1/nostr-signal/topic");
const KEY_DOMAIN = asciiToBytes("p2pcards/v1/nostr-signal/key");
const AAD_DOMAIN = asciiToBytes("p2pcards/v1/nostr-signal/aad");
const RELAY_SELECTION_DOMAIN = asciiToBytes("p2pcards/v1/nostr-signal/relay");
const SUBSCRIPTION_DOMAIN = asciiToBytes("p2pcards/v1/nostr-signal/subscription");
const SIGNAL_PACKET_KEYS = ["from", "to", "frame"] as const;
const MAX_RELAY_URLS = 64;
const MAX_RELAY_URL_BYTES = 2_048;
const MAX_APP_ID_BYTES = 128;
const WEB_SOCKET_OPEN = 1;

type Lifecycle = "idle" | "joining" | "joined" | "leaving";

export type NostrRelayConnectionState =
  | "connecting"
  | "subscribing"
  | "connected"
  | "disconnected"
  | "failed";

export interface NostrRelaySocketEvent {
  readonly type: string;
  readonly data?: unknown;
}

export interface NostrRelaySocket {
  readonly readyState: number;
  addEventListener(
    type: "open" | "message" | "error" | "close",
    listener: (event: NostrRelaySocketEvent) => void,
  ): void;
  send(data: string): void;
  close(code?: number, reason?: string): void;
}

export type NostrRelaySocketFactory = (url: string) => NostrRelaySocket;
export type NostrEventFactory = (topic: string, content: string) => Promise<string>;
export type NostrSubscriptionFactory = (subscriptionId: string, topic: string) => string;

export interface NostrRelaySnapshot {
  readonly url: string;
  readonly state: NostrRelayConnectionState;
  readonly lastError: Error | null;
}

export interface NostrSignalingFailure {
  readonly error: Error;
  readonly relayUrl: string | null;
}

export interface TrysteroNostrSignalingAdapterOptions {
  readonly appId?: string;
  readonly relayUrls?: readonly string[];
  readonly relayRedundancy?: number;
  readonly connectTimeoutMs?: number;
  readonly maxPendingEvents?: number;
  readonly maxConcurrentSends?: number;
  readonly maxSeenEvents?: number;
  readonly maxRetainedFailures?: number;
  readonly maxReassemblySenders?: number;
  readonly maxPendingFrameBytes?: number;
  readonly publicationAckTimeoutMs?: number;
  readonly reconnectBaseDelayMs?: number;
  readonly reconnectMaxDelayMs?: number;
  readonly signalRetentionMs?: number;
  readonly maxRetainedPublications?: number;
  readonly randomSource?: RandomSource;
  readonly subtleCrypto?: SubtleCrypto;
  readonly createSocket?: NostrRelaySocketFactory;
  readonly createEvent?: NostrEventFactory;
  readonly createSubscription?: NostrSubscriptionFactory;
  readonly onRelayStateChange?: (relay: NostrRelaySnapshot) => void;
  readonly onError?: (error: Error, relayUrl: string | null) => void;
}

interface RelayState {
  readonly url: string;
  readonly socket: NostrRelaySocket;
  state: NostrRelayConnectionState;
  lastError: Error | null;
  ready: boolean;
  readonly rejectReady: (error: Error) => void;
}

interface IncomingQueueState {
  readonly generation: number;
  queue: Promise<void>;
  pending: number;
}

interface PendingPublication {
  readonly relayUrls: Set<string>;
  readonly resolve: () => void;
  readonly reject: (error: Error) => void;
  readonly timer: ReturnType<typeof globalThis.setTimeout>;
}

interface RetainedPublication {
  readonly eventId: string;
  readonly event: string;
  readonly createdAt: number;
  readonly acknowledgedRelayUrls: Set<string>;
}

interface EncryptedSignalContext {
  readonly topic: string;
  readonly keyBytes: Uint8Array<ArrayBuffer>;
  readonly additionalData: Uint8Array<ArrayBuffer>;
}

interface DecodedSignalPacket {
  readonly from: IdentityPublicKey;
  readonly to: IdentityPublicKey;
  readonly frame: ReturnType<typeof decodeDataFrame>;
}

class NostrSignalingCapacityError extends Error {}

/**
 * A signaling-only Nostr adapter. Trystero supplies signed Nostr events, while
 * this class retains ownership of WebRTC in FullMeshTransport instead of
 * creating Trystero-managed peer connections.
 */
export class TrysteroNostrSignalingAdapter implements SignalingAdapter {
  readonly #appId: string;
  readonly #relayUrls: readonly string[];
  readonly #relayRedundancy: number;
  readonly #connectTimeoutMs: number;
  readonly #maxPendingEvents: number;
  readonly #maxConcurrentSends: number;
  readonly #maxSeenEvents: number;
  readonly #maxRetainedFailures: number;
  readonly #maxReassemblySenders: number;
  readonly #maxPendingFrameBytes: number;
  readonly #publicationAckTimeoutMs: number;
  readonly #reconnectBaseDelayMs: number;
  readonly #reconnectMaxDelayMs: number;
  readonly #signalRetentionMs: number;
  readonly #maxRetainedPublications: number;
  readonly #randomSource: RandomSource;
  readonly #subtleCrypto: SubtleCrypto | null;
  readonly #createSocket: NostrRelaySocketFactory;
  readonly #createEvent: NostrEventFactory;
  readonly #createSubscription: NostrSubscriptionFactory;
  readonly #onRelayStateChange: ((relay: NostrRelaySnapshot) => void) | undefined;
  readonly #onError: ((error: Error, relayUrl: string | null) => void) | undefined;
  readonly #relays: RelayState[] = [];
  readonly #seenEventDigests = new Set<string>();
  readonly #reassemblers = new Map<string, FrameReassembler>();
  readonly #failures: NostrSignalingFailure[] = [];
  readonly #pendingPublications = new Map<string, PendingPublication>();
  readonly #retainedPublications: RetainedPublication[] = [];
  readonly #reconnectTimers = new Map<string, ReturnType<typeof globalThis.setTimeout>>();
  readonly #reconnectAttempts = new Map<string, number>();
  #lifecycle: Lifecycle = "idle";
  #generation = 0;
  #self: IdentityPublicKey | null = null;
  #topic: string | null = null;
  #subscriptionId: string | null = null;
  #subscriptionRequest: string | null = null;
  #encryptionKey: CryptoKey | null = null;
  #additionalData: Uint8Array<ArrayBuffer> | null = null;
  #handler: SignalingMessageHandler | null = null;
  #nextFrameId = 0;
  #outboundState = { active: 0 };
  #incomingState: IncomingQueueState = {
    generation: 0,
    queue: Promise.resolve(),
    pending: 0,
  };
  #reassemblyExpiryTimer: ReturnType<typeof globalThis.setTimeout> | null = null;

  constructor(options: TrysteroNostrSignalingAdapterOptions = {}) {
    if (typeof options !== "object" || options === null) {
      throw new TypeError("Nostr signaling options must be an object");
    }
    this.#appId = normalizeAppId(options.appId ?? DEFAULT_NOSTR_APP_ID);
    this.#relayUrls = normalizeRelayUrls(options.relayUrls ?? defaultRelayUrls);
    this.#relayRedundancy = boundedPositiveInteger(
      options.relayRedundancy ??
        Math.min(DEFAULT_NOSTR_RELAY_REDUNDANCY, this.#relayUrls.length),
      "Nostr relay redundancy",
      this.#relayUrls.length,
    );
    this.#connectTimeoutMs = positiveInteger(
      options.connectTimeoutMs ?? DEFAULT_NOSTR_CONNECT_TIMEOUT_MS,
      "Nostr relay connection timeout",
    );
    this.#maxPendingEvents = positiveInteger(
      options.maxPendingEvents ?? DEFAULT_MAX_PENDING_NOSTR_EVENTS,
      "Maximum pending Nostr events",
    );
    this.#maxConcurrentSends = positiveInteger(
      options.maxConcurrentSends ?? DEFAULT_MAX_CONCURRENT_NOSTR_SENDS,
      "Maximum concurrent Nostr sends",
    );
    this.#maxSeenEvents = positiveInteger(
      options.maxSeenEvents ?? DEFAULT_MAX_SEEN_NOSTR_EVENTS,
      "Maximum seen Nostr events",
    );
    this.#maxRetainedFailures = positiveInteger(
      options.maxRetainedFailures ?? DEFAULT_MAX_RETAINED_NOSTR_FAILURES,
      "Maximum retained Nostr failures",
    );
    this.#maxReassemblySenders = positiveInteger(
      options.maxReassemblySenders ?? DEFAULT_MAX_NOSTR_REASSEMBLY_SENDERS,
      "Maximum Nostr reassembly senders",
    );
    this.#maxPendingFrameBytes = positiveInteger(
      options.maxPendingFrameBytes ?? DEFAULT_MAX_PENDING_NOSTR_FRAME_BYTES,
      "Maximum pending Nostr frame bytes",
    );
    this.#publicationAckTimeoutMs = positiveInteger(
      options.publicationAckTimeoutMs ?? DEFAULT_NOSTR_PUBLICATION_ACK_TIMEOUT_MS,
      "Nostr publication acknowledgement timeout",
    );
    this.#reconnectBaseDelayMs = positiveInteger(
      options.reconnectBaseDelayMs ?? DEFAULT_NOSTR_RECONNECT_BASE_DELAY_MS,
      "Nostr relay reconnect base delay",
    );
    this.#reconnectMaxDelayMs = positiveInteger(
      options.reconnectMaxDelayMs ?? DEFAULT_NOSTR_RECONNECT_MAX_DELAY_MS,
      "Nostr relay reconnect maximum delay",
    );
    if (this.#reconnectMaxDelayMs < this.#reconnectBaseDelayMs) {
      throw new RangeError("Nostr relay reconnect maximum delay must not be below its base delay");
    }
    this.#signalRetentionMs = positiveInteger(
      options.signalRetentionMs ?? DEFAULT_NOSTR_SIGNAL_RETENTION_MS,
      "Nostr signaling retention duration",
    );
    this.#maxRetainedPublications = positiveInteger(
      options.maxRetainedPublications ?? DEFAULT_MAX_RETAINED_NOSTR_PUBLICATIONS,
      "Maximum retained Nostr publications",
    );
    this.#randomSource = options.randomSource ?? systemRandomSource;
    this.#subtleCrypto = options.subtleCrypto ?? globalThis.crypto?.subtle ?? null;
    this.#createSocket = options.createSocket ?? defaultSocketFactory;
    this.#createEvent = options.createEvent ?? createTrysteroNostrEvent;
    this.#createSubscription = options.createSubscription ?? createNostrSubscription;
    requireFunction(this.#createSocket, "Nostr relay socket factory");
    requireFunction(this.#createEvent, "Nostr event factory");
    requireFunction(this.#createSubscription, "Nostr subscription factory");
    requireOptionalFunction(options.onRelayStateChange, "Nostr relay state observer");
    requireOptionalFunction(options.onError, "Nostr signaling error observer");
    this.#onRelayStateChange = options.onRelayStateChange;
    this.#onError = options.onError;
  }

  get joined(): boolean {
    return this.#lifecycle === "joined";
  }

  get relayDiagnostics(): readonly NostrRelaySnapshot[] {
    return Object.freeze(
      this.#relays.map((relay) => snapshotRelay(relay)),
    );
  }

  get failures(): readonly NostrSignalingFailure[] {
    return Object.freeze(
      this.#failures.map(({ error, relayUrl }) => Object.freeze({ error, relayUrl })),
    );
  }

  async join(roomId: string, self: Uint8Array): Promise<void> {
    if (this.#lifecycle !== "idle") {
      throw new Error("Nostr signaling adapter is already joined or joining");
    }
    const normalizedRoomId = parseSignalingRoomId(roomId);
    const identity = parseIdentityPublicKey(self);
    if (this.#subtleCrypto === null) {
      throw new Error("Web Crypto AES-GCM is unavailable for Nostr signaling");
    }

    const context = deriveEncryptedSignalContext(this.#appId, normalizedRoomId);
    const nextFrameId = uint32FromBytes(randomBytes(4, this.#randomSource));
    const generation = ++this.#generation;
    this.#lifecycle = "joining";
    this.#self = identity;
    this.#topic = context.topic;
    this.#additionalData = context.additionalData;
    this.#subscriptionId = bytesToHex(
      sha256(
        SUBSCRIPTION_DOMAIN,
        encodeCanonical({ topic: context.topic, self: identity }),
      ),
    ).slice(0, 32);
    this.#nextFrameId = nextFrameId;
    this.#outboundState = { active: 0 };
    this.#incomingState = {
      generation,
      queue: Promise.resolve(),
      pending: 0,
    };

    try {
      const encryptionKey = await this.#subtleCrypto.importKey(
        "raw",
        context.keyBytes,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"],
      );
      this.#requireGeneration(generation, "Nostr signaling startup was cancelled");
      this.#encryptionKey = encryptionKey;
      const subscription = this.#createSubscription(this.#subscriptionId, context.topic);
      if (typeof subscription !== "string") {
        throw new TypeError("Nostr subscription factory must return text");
      }
      this.#subscriptionRequest = subscription;
      const selectedRelays = selectRelayUrls(
        this.#relayUrls,
        this.#relayRedundancy,
        context.topic,
      );
      const attempts = selectedRelays.map((url) =>
        this.#connectRelay(url, subscription, generation),
      );
      const allSettled = Promise.allSettled(attempts);
      if (!(await settlesBeforeTimeout(allSettled, this.#connectTimeoutMs))) {
        this.#requireGeneration(generation, "Nostr signaling startup was cancelled");
        for (const relay of this.#relays) {
          if (!relay.ready) {
            const error = new Error(`Timed out subscribing to Nostr relay ${relay.url}`);
            relay.state = "failed";
            relay.lastError = error;
            this.#notifyRelayState(relay);
            this.#report(error, relay.url);
            relay.rejectReady(error);
            relay.socket.close();
          }
        }
      }
      await allSettled;
      this.#requireGeneration(generation, "Nostr signaling startup was cancelled");
      if (!this.#relays.some((relay) => relay.ready)) {
        throw new AggregateError([], "No Nostr relay subscription became ready");
      }
      this.#lifecycle = "joined";
      for (const relay of this.#relays) {
        if (!relay.ready) {
          this.#scheduleRelayReconnect(relay.url, generation);
        }
      }
    } catch (cause) {
      if (this.#generation === generation) {
        this.#resetMembership();
      }
      if (cause instanceof AggregateError) {
        throw new Error("Failed to connect to any Nostr relay", { cause });
      }
      throw asError(cause, "Failed to join Nostr signaling room");
    }
  }

  async send(to: Uint8Array, payload: Uint8Array): Promise<void> {
    if (
      this.#lifecycle !== "joined" ||
      this.#self === null ||
      this.#topic === null ||
      this.#encryptionKey === null ||
      this.#additionalData === null ||
      this.#subtleCrypto === null
    ) {
      throw new Error("Nostr signaling adapter is not joined");
    }
    const outboundState = this.#outboundState;
    if (outboundState.active >= this.#maxConcurrentSends) {
      throw new NostrSignalingCapacityError("Concurrent Nostr send limit exceeded");
    }
    const recipient = parseIdentityPublicKey(to);
    const message = requireSignalingPayload(payload);
    if (bytesEqual(recipient, this.#self)) {
      throw new Error("Nostr signaling adapter cannot send to itself");
    }

    const generation = this.#generation;
    const sender = parseIdentityPublicKey(this.#self);
    const topic = this.#topic;
    const key = this.#encryptionKey;
    const subtleCrypto = this.#subtleCrypto;
    const additionalData = this.#additionalData.slice();
    const frameId = this.#allocateFrameId();
    outboundState.active += 1;
    try {
      // Publish at most 17 fragments together; serial ACK waits can outlive reassembly.
      const results = await Promise.allSettled(splitDataFrames(message, frameId).map(async (frame) => {
        const plaintext = encodeCanonical({
          from: sender,
          to: recipient,
          frame: encodeDataFrame(frame),
        });
        const content = await encryptSignalPacket(
          plaintext,
          key,
          additionalData,
          subtleCrypto,
          this.#randomSource,
        );
        if (content.length > MAX_NOSTR_EVENT_CONTENT_CHARS) {
          throw new RangeError("Encrypted Nostr signaling event exceeds the profiled limit");
        }
        this.#requireGeneration(generation, "Nostr signaling membership changed during send");
        const event = await this.#createEvent(topic, content);
        if (typeof event !== "string") {
          throw new TypeError("Nostr event factory must return text");
        }
        this.#requireGeneration(generation, "Nostr signaling membership changed during send");
        await this.#broadcast(event);
      }));
      const failed = results.find((result) => result.status === "rejected");
      if (failed?.status === "rejected") {
        throw failed.reason;
      }
    } finally {
      outboundState.active -= 1;
    }
  }

  onMessage(callback: SignalingMessageHandler): void {
    if (typeof callback !== "function") {
      throw new TypeError("Signaling message handler must be a function");
    }
    this.#handler = callback;
  }

  async leave(): Promise<void> {
    if (this.#lifecycle === "idle") {
      return;
    }
    this.#resetMembership();
  }

  async whenIdle(): Promise<void> {
    for (;;) {
      const state = this.#incomingState;
      const snapshot = state.queue;
      await snapshot;
      if (this.#incomingState === state && state.queue === snapshot) {
        return;
      }
    }
  }

  #connectRelay(
    url: string,
    subscription: string,
    generation: number,
  ): Promise<void> {
    if (!this.#isGenerationActive(generation)) {
      return Promise.reject(new Error("Nostr signaling startup was cancelled"));
    }
    return new Promise<void>((resolve, reject) => {
      let socket: NostrRelaySocket;
      try {
        socket = this.#createSocket(url);
      } catch (cause) {
        const error = asError(cause, `Failed to create Nostr relay socket for ${url}`);
        this.#report(error, url);
        reject(error);
        return;
      }
      const relay: RelayState = {
        url,
        socket,
        state: "connecting",
        lastError: null,
        ready: false,
        rejectReady: reject,
      };
      this.#relays.push(relay);
      this.#notifyRelayState(relay);

      socket.addEventListener("open", () => {
        if (!this.#isRelayActive(relay, generation)) {
          socket.close();
          reject(new Error("Nostr signaling startup was cancelled"));
          return;
        }
        try {
          relay.state = "subscribing";
          relay.lastError = null;
          this.#notifyRelayState(relay);
          socket.send(subscription);
        } catch (cause) {
          const error = asError(cause, `Failed to subscribe to Nostr relay ${url}`);
          relay.state = "failed";
          relay.lastError = error;
          this.#notifyRelayState(relay);
          this.#report(error, url);
          reject(error);
          socket.close();
        }
      });
      socket.addEventListener("message", (event) => {
        if (this.#isRelayActive(relay, generation)) {
          this.#acceptRelayMessage(event.data, relay, generation, resolve, reject);
        }
      });
      socket.addEventListener("error", () => {
        if (!this.#isRelayActive(relay, generation)) {
          return;
        }
        const error = new Error(`Nostr relay ${url} reported a WebSocket error`);
        relay.state = "failed";
        relay.lastError = error;
        this.#notifyRelayState(relay);
        this.#report(error, url);
        if (!relay.ready) {
          reject(error);
        }
        socket.close();
      });
      socket.addEventListener("close", () => {
        if (!this.#isRelayActive(relay, generation)) {
          if (!relay.ready) {
            reject(new Error("Nostr signaling startup was cancelled"));
          }
          return;
        }
        const disconnectError = new Error(`Nostr relay ${url} disconnected`);
        this.#rejectRelayPublications(url, disconnectError);
        relay.ready = false;
        relay.state = relay.lastError === null ? "disconnected" : "failed";
        this.#notifyRelayState(relay);
        if (!relay.ready) {
          reject(new Error(`Nostr relay ${url} closed before connecting`));
        }
        this.#scheduleRelayReconnect(url, generation);
      });
    });
  }

  #acceptRelayMessage(
    data: unknown,
    relay: RelayState,
    generation: number,
    markReady: () => void,
    rejectReady: (error: Error) => void,
  ): void {
    try {
      if (typeof data !== "string") {
        throw new TypeError("Nostr relay message must be text");
      }
      if (data.length > MAX_NOSTR_RELAY_MESSAGE_CHARS) {
        throw new RangeError("Nostr relay message exceeds the profiled limit");
      }
      const message: unknown = JSON.parse(data);
      if (!Array.isArray(message) || message.length === 0) {
        throw new TypeError("Nostr relay message must be a non-empty JSON array");
      }
      if (message[0] === "NOTICE") {
        throw new Error(`Nostr relay notice: ${String(message[1] ?? "unknown")}`);
      }
      if (message[0] === "EOSE") {
        if (message.length !== 2 || message[1] !== this.#subscriptionId) {
          throw new TypeError("Malformed Nostr relay EOSE message");
        }
        if (!relay.ready) {
          relay.ready = true;
          relay.state = "connected";
          relay.lastError = null;
          this.#reconnectAttempts.delete(relay.url);
          this.#notifyRelayState(relay);
          markReady();
          this.#replayRetainedPublications(relay, generation);
        }
        return;
      }
      if (message[0] === "CLOSED" && message[1] === this.#subscriptionId) {
        const error = new Error(`Nostr relay closed subscription: ${String(message[2] ?? "unknown")}`);
        relay.state = "failed";
        relay.lastError = error;
        this.#notifyRelayState(relay);
        this.#report(error, relay.url);
        rejectReady(error);
        relay.socket.close();
        return;
      }
      if (message[0] === "OK") {
        this.#acceptPublicationAcknowledgement(message, relay);
        return;
      }
      if (message[0] !== "EVENT") {
        return;
      }
      if (
        message.length !== 3 ||
        message[1] !== this.#subscriptionId ||
        !isRecord(message[2])
      ) {
        throw new TypeError("Malformed Nostr relay EVENT message");
      }
      const event = message[2];
      if (typeof event["id"] !== "string" || !/^[0-9a-f]{64}$/.test(event["id"])) {
        throw new TypeError("Nostr event ID must be 64 lowercase hexadecimal characters");
      }
      if (typeof event["content"] !== "string") {
        throw new TypeError("Nostr event content must be text");
      }
      if (event["content"].length > MAX_NOSTR_EVENT_CONTENT_CHARS) {
        throw new RangeError("Nostr event content exceeds the profiled limit");
      }
      if (!hasTopicTag(event["tags"], this.#topic)) {
        throw new TypeError("Nostr event does not match the signaling topic");
      }
      const eventDigest = bytesToHex(sha256(new TextEncoder().encode(event["content"])));
      if (this.#seenEventDigests.has(eventDigest)) {
        return;
      }
      const incomingState = this.#incomingState;
      if (incomingState.generation !== generation) {
        return;
      }
      if (incomingState.pending >= this.#maxPendingEvents) {
        throw new Error("Pending Nostr event limit exceeded");
      }
      this.#rememberEventDigest(eventDigest);
      incomingState.pending += 1;
      const content = event["content"];
      const queued = incomingState.queue.then(async () => {
        if (this.#isGenerationActive(generation)) {
          await this.#processEvent(content, generation);
        }
      });
      incomingState.queue = queued
        .catch((cause: unknown) => {
          if (this.#isGenerationActive(generation)) {
            if (cause instanceof NostrSignalingCapacityError) {
              this.#seenEventDigests.delete(eventDigest);
            }
            this.#report(cause, relay.url);
          }
        })
        .finally(() => {
          incomingState.pending -= 1;
        });
    } catch (cause) {
      this.#report(cause, relay.url);
    }
  }

  async #processEvent(content: string, generation: number): Promise<void> {
    if (
      this.#encryptionKey === null ||
      this.#additionalData === null ||
      this.#subtleCrypto === null ||
      this.#self === null
    ) {
      throw new Error("Nostr signaling decryption context is unavailable");
    }
    const plaintext = await decryptSignalPacket(
      content,
      this.#encryptionKey,
      this.#additionalData,
      this.#subtleCrypto,
    );
    this.#requireGeneration(generation, "Nostr signaling membership changed during receive");
    const packet = decodeSignalPacket(plaintext);
    if (!bytesEqual(packet.to, this.#self) || bytesEqual(packet.from, this.#self)) {
      return;
    }
    this.#expireReassemblers();
    const senderKey = identityKey(packet.from);
    let reassembler = this.#reassemblers.get(senderKey);
    if (reassembler === undefined) {
      if (this.#reassemblers.size >= this.#maxReassemblySenders) {
        throw new NostrSignalingCapacityError("Nostr reassembly sender limit exceeded");
      }
      reassembler = new FrameReassembler({
        maxMessageBytes: MAX_SIGNALING_MESSAGE_BYTES,
        maxPendingBytes: this.#maxPendingFrameBytes,
        maxPendingGroups: 64,
        maxFramesPerMessage: Math.ceil(
          MAX_SIGNALING_MESSAGE_BYTES / MAX_FRAME_PAYLOAD_BYTES,
        ),
        scheduleExpiry: false,
      });
      this.#reassemblers.set(senderKey, reassembler);
    }
    const result = reassembler.accept(packet.frame);
    if (this.#pendingFrameBytes() > this.#maxPendingFrameBytes) {
      reassembler.clear();
      this.#reassemblers.delete(senderKey);
      this.#clearReassemblyExpiryIfIdle();
      throw new NostrSignalingCapacityError("Pending Nostr frame byte limit exceeded");
    }
    if (reassembler.pendingGroups === 0) {
      reassembler.clear();
      this.#reassemblers.delete(senderKey);
      this.#clearReassemblyExpiryIfIdle();
    } else {
      this.#scheduleReassemblyExpiry();
    }
    if (result.status === "rejected") {
      if (result.reason === "capacity_exceeded") {
        throw new NostrSignalingCapacityError("Nostr reassembly capacity exceeded");
      }
      throw new Error(`Rejected Nostr signaling frame: ${result.reason}`);
    }
    if (result.status !== "complete") {
      return;
    }
    if (this.#handler === null) {
      throw new Error("Nostr signaling recipient has no message handler");
    }
    this.#handler(parseIdentityPublicKey(packet.from), result.payload.slice());
  }

  async #broadcast(event: string): Promise<void> {
    const eventId = publishedEventId(event);
    const eligibleRelays = this.#relays.filter(
      (relay) =>
        relay.ready &&
        relay.state === "connected" &&
        relay.socket.readyState === WEB_SOCKET_OPEN,
    );
    if (eligibleRelays.length === 0) {
      throw new Error("No connected Nostr relay accepted the signaling event");
    }
    if (this.#pendingPublications.has(eventId)) {
      throw new Error("Nostr event factory reused a pending event ID");
    }
    this.#retainPublication(eventId, event);
    let resolvePublication: (() => void) | undefined;
    let rejectPublication: ((error: Error) => void) | undefined;
    const acknowledgement = new Promise<void>((resolve, reject) => {
      resolvePublication = resolve;
      rejectPublication = reject;
    });
    if (resolvePublication === undefined || rejectPublication === undefined) {
      throw new Error("Failed to initialize Nostr publication acknowledgement");
    }
    const timer = globalThis.setTimeout(() => {
      const pending = this.#pendingPublications.get(eventId);
      if (pending === undefined) {
        return;
      }
      this.#pendingPublications.delete(eventId);
      pending.reject(new Error("Timed out waiting for a Nostr publication acknowledgement"));
      this.#report(new Error("Timed out waiting for a Nostr publication acknowledgement"), null);
    }, this.#publicationAckTimeoutMs);
    const pending: PendingPublication = {
      relayUrls: new Set(eligibleRelays.map(({ url }) => url)),
      resolve: resolvePublication,
      reject: rejectPublication,
      timer,
    };
    this.#pendingPublications.set(eventId, pending);
    let sent = 0;
    for (const relay of eligibleRelays) {
      try {
        relay.socket.send(event);
        sent += 1;
      } catch (cause) {
        const error = asError(cause, `Failed to send through Nostr relay ${relay.url}`);
        relay.ready = false;
        relay.state = "failed";
        relay.lastError = error;
        this.#notifyRelayState(relay);
        this.#report(error, relay.url);
        this.#rejectPublicationRelay(eventId, relay.url, error);
        relay.socket.close();
        this.#scheduleRelayReconnect(relay.url, this.#generation);
      }
    }
    if (sent === 0) {
      const current = this.#pendingPublications.get(eventId);
      if (current !== undefined) {
        globalThis.clearTimeout(current.timer);
        this.#pendingPublications.delete(eventId);
        current.reject(new Error("No connected Nostr relay accepted the signaling event"));
      }
    }
    await acknowledgement;
  }

  #acceptPublicationAcknowledgement(
    message: readonly unknown[],
    relay: RelayState,
  ): void {
    if (
      message.length < 4 ||
      typeof message[1] !== "string" ||
      !/^[0-9a-f]{64}$/.test(message[1]) ||
      typeof message[2] !== "boolean"
    ) {
      throw new TypeError("Malformed Nostr relay OK message");
    }
    const reason = typeof message[3] === "string" ? message[3] : "unknown";
    const accepted = message[2] || reason.startsWith("duplicate:");
    if (accepted) {
      this.#acknowledgeRetainedPublication(message[1], relay.url);
    }
    const pending = this.#pendingPublications.get(message[1]);
    if (pending === undefined || !pending.relayUrls.has(relay.url)) {
      return;
    }
    if (accepted) {
      globalThis.clearTimeout(pending.timer);
      this.#pendingPublications.delete(message[1]);
      pending.resolve();
      return;
    }
    const error = new Error(`Nostr relay rejected publication: ${reason}`);
    this.#report(error, relay.url);
    this.#rejectPublicationRelay(message[1], relay.url, error);
  }

  #rejectPublicationRelay(eventId: string, relayUrl: string, error: Error): void {
    const pending = this.#pendingPublications.get(eventId);
    if (pending === undefined) {
      return;
    }
    pending.relayUrls.delete(relayUrl);
    if (pending.relayUrls.size > 0) {
      return;
    }
    globalThis.clearTimeout(pending.timer);
    this.#pendingPublications.delete(eventId);
    pending.reject(error);
  }

  #rejectRelayPublications(relayUrl: string, error: Error): void {
    for (const eventId of [...this.#pendingPublications.keys()]) {
      this.#rejectPublicationRelay(eventId, relayUrl, error);
    }
  }

  #retainPublication(eventId: string, event: string): void {
    this.#expireRetainedPublications();
    if (
      this.#retainedPublications.some(
        (publication) => publication.eventId === eventId,
      )
    ) {
      throw new Error("Nostr event factory reused a retained event ID");
    }
    if (this.#retainedPublications.length >= this.#maxRetainedPublications) {
      this.#retainedPublications.shift();
    }
    this.#retainedPublications.push({
      eventId,
      event,
      createdAt: Date.now(),
      acknowledgedRelayUrls: new Set(),
    });
  }

  #acknowledgeRetainedPublication(eventId: string, relayUrl: string): void {
    this.#retainedPublications
      .find((publication) => publication.eventId === eventId)
      ?.acknowledgedRelayUrls.add(relayUrl);
  }

  #replayRetainedPublications(relay: RelayState, generation: number): void {
    this.#expireRetainedPublications();
    for (const publication of this.#retainedPublications) {
      if (
        publication.acknowledgedRelayUrls.has(relay.url) ||
        !this.#isGenerationActive(generation) ||
        !relay.ready ||
        relay.socket.readyState !== WEB_SOCKET_OPEN
      ) {
        continue;
      }
      try {
        this.#pendingPublications.get(publication.eventId)?.relayUrls.add(relay.url);
        relay.socket.send(publication.event);
      } catch (cause) {
        const error = asError(
          cause,
          `Failed to replay signaling through Nostr relay ${relay.url}`,
        );
        relay.ready = false;
        relay.state = "failed";
        relay.lastError = error;
        this.#notifyRelayState(relay);
        this.#report(error, relay.url);
        this.#rejectPublicationRelay(publication.eventId, relay.url, error);
        relay.socket.close();
        this.#scheduleRelayReconnect(relay.url, generation);
        return;
      }
    }
  }

  #expireRetainedPublications(now = Date.now()): void {
    while (
      this.#retainedPublications[0] !== undefined &&
      now - this.#retainedPublications[0].createdAt >= this.#signalRetentionMs
    ) {
      this.#retainedPublications.shift();
    }
  }

  #scheduleRelayReconnect(url: string, generation: number): void {
    if (
      this.#lifecycle !== "joined" ||
      this.#generation !== generation ||
      this.#reconnectTimers.has(url) ||
      this.#subscriptionRequest === null
    ) {
      return;
    }
    const attempt = (this.#reconnectAttempts.get(url) ?? 0) + 1;
    this.#reconnectAttempts.set(url, attempt);
    const delay = Math.min(
      this.#reconnectBaseDelayMs * 2 ** Math.min(attempt - 1, 30),
      this.#reconnectMaxDelayMs,
    );
    const timer = globalThis.setTimeout(() => {
      if (
        this.#lifecycle !== "joined" ||
        this.#generation !== generation ||
        this.#subscriptionRequest === null
      ) {
        this.#reconnectTimers.delete(url);
        return;
      }
      for (let index = this.#relays.length - 1; index >= 0; index -= 1) {
        const previous = this.#relays[index];
        if (previous?.url === url) {
          this.#relays.splice(index, 1);
          previous.socket.close();
        }
      }
      const reconnecting = this.#connectRelay(url, this.#subscriptionRequest, generation);
      const relay = this.#relays.find((candidate) => candidate.url === url);
      const timeout = globalThis.setTimeout(() => {
        if (relay !== undefined && this.#isRelayActive(relay, generation) && !relay.ready) {
          relay.rejectReady(new Error(`Timed out subscribing to Nostr relay ${url}`));
          relay.socket.close();
        }
      }, this.#connectTimeoutMs);
      void reconnecting.then(
        () => {
          globalThis.clearTimeout(timeout);
          if (this.#reconnectTimers.get(url) === timer) {
            this.#reconnectTimers.delete(url);
            if (relay !== undefined && !relay.ready) {
              this.#scheduleRelayReconnect(url, generation);
            }
          }
        },
        (cause: unknown) => {
          globalThis.clearTimeout(timeout);
          if (this.#reconnectTimers.get(url) !== timer) {
            return;
          }
          this.#reconnectTimers.delete(url);
          this.#report(cause, url);
          this.#scheduleRelayReconnect(url, generation);
        },
      );
    }, delay);
    this.#reconnectTimers.set(url, timer);
  }

  #allocateFrameId(): number {
    const id = this.#nextFrameId;
    this.#nextFrameId = (this.#nextFrameId + 1) >>> 0;
    return id;
  }

  #rememberEventDigest(eventDigest: string): void {
    this.#seenEventDigests.add(eventDigest);
    if (this.#seenEventDigests.size <= this.#maxSeenEvents) {
      return;
    }
    const oldest = this.#seenEventDigests.values().next().value as string | undefined;
    if (oldest !== undefined) {
      this.#seenEventDigests.delete(oldest);
    }
  }

  #pendingFrameBytes(): number {
    let total = 0;
    for (const reassembler of this.#reassemblers.values()) {
      total += reassembler.pendingBytes;
    }
    return total;
  }

  #scheduleReassemblyExpiry(): void {
    if (this.#reassemblyExpiryTimer !== null) {
      return;
    }
    let nextExpiryAt: number | null = null;
    for (const reassembler of this.#reassemblers.values()) {
      const candidate = reassembler.nextExpiryAt;
      if (candidate !== null && (nextExpiryAt === null || candidate < nextExpiryAt)) {
        nextExpiryAt = candidate;
      }
    }
    if (nextExpiryAt === null) {
      return;
    }
    this.#reassemblyExpiryTimer = globalThis.setTimeout(() => {
      this.#reassemblyExpiryTimer = null;
      this.#expireReassemblers();
      if (this.#reassemblers.size > 0 && this.#lifecycle !== "idle") {
        this.#scheduleReassemblyExpiry();
      }
    }, Math.max(0, nextExpiryAt - Date.now()));
  }

  #expireReassemblers(now = Date.now()): void {
    for (const [sender, reassembler] of this.#reassemblers) {
      reassembler.expire(now);
      if (reassembler.pendingGroups === 0) {
        reassembler.clear();
        this.#reassemblers.delete(sender);
      }
    }
    this.#clearReassemblyExpiryIfIdle();
  }

  #clearReassemblyExpiryIfIdle(): void {
    if (this.#reassemblers.size === 0 && this.#reassemblyExpiryTimer !== null) {
      globalThis.clearTimeout(this.#reassemblyExpiryTimer);
      this.#reassemblyExpiryTimer = null;
    }
  }

  #isGenerationActive(generation: number): boolean {
    return this.#generation === generation &&
      (this.#lifecycle === "joining" || this.#lifecycle === "joined");
  }

  #isRelayActive(relay: RelayState, generation: number): boolean {
    return this.#isGenerationActive(generation) && this.#relays.includes(relay);
  }

  #requireGeneration(generation: number, message: string): void {
    if (!this.#isGenerationActive(generation)) {
      throw new Error(message);
    }
  }

  #notifyRelayState(relay: RelayState): void {
    try {
      this.#onRelayStateChange?.(snapshotRelay(relay));
    } catch (cause) {
      this.#retainFailure(
        asError(cause, "Nostr relay state observer failed"),
        relay.url,
      );
    }
  }

  #report(cause: unknown, relayUrl: string | null): void {
    const error = asError(cause, "Nostr signaling operation failed");
    this.#retainFailure(error, relayUrl);
    try {
      this.#onError?.(error, relayUrl);
    } catch (observerCause) {
      this.#retainFailure(
        asError(observerCause, "Nostr signaling error observer failed"),
        relayUrl,
      );
    }
  }

  #retainFailure(error: Error, relayUrl: string | null): void {
    if (this.#failures.length >= this.#maxRetainedFailures) {
      this.#failures.shift();
    }
    this.#failures.push(Object.freeze({ error, relayUrl }));
  }

  #resetMembership(): void {
    this.#lifecycle = "leaving";
    this.#generation += 1;
    for (const relay of this.#relays.splice(0)) {
      try {
        relay.rejectReady(new Error("Nostr signaling startup was cancelled"));
        relay.socket.close(1000, "leaving signaling room");
      } catch (cause) {
        this.#report(cause, relay.url);
      }
    }
    for (const [eventId, publication] of this.#pendingPublications) {
      globalThis.clearTimeout(publication.timer);
      publication.reject(new Error("Nostr signaling membership changed during publication"));
      this.#pendingPublications.delete(eventId);
    }
    for (const timer of this.#reconnectTimers.values()) {
      globalThis.clearTimeout(timer);
    }
    this.#reconnectTimers.clear();
    this.#reconnectAttempts.clear();
    this.#retainedPublications.length = 0;
    for (const reassembler of this.#reassemblers.values()) {
      reassembler.clear();
    }
    this.#reassemblers.clear();
    this.#seenEventDigests.clear();
    if (this.#reassemblyExpiryTimer !== null) {
      globalThis.clearTimeout(this.#reassemblyExpiryTimer);
      this.#reassemblyExpiryTimer = null;
    }
    this.#self = null;
    this.#topic = null;
    this.#subscriptionId = null;
    this.#subscriptionRequest = null;
    this.#encryptionKey = null;
    this.#additionalData = null;
    this.#lifecycle = "idle";
  }
}

export function deriveNostrSignalingTopic(appId: string, roomId: string): string {
  return deriveEncryptedSignalContext(
    normalizeAppId(appId),
    parseSignalingRoomId(roomId),
  ).topic;
}

export function deriveTrysteroNostrKind(topic: string): number {
  if (!/^[0-9a-f]{64}$/.test(topic)) {
    throw new TypeError("Trystero Nostr topic must be 64 lowercase hexadecimal characters");
  }
  let sum = 0;
  for (const character of topic) {
    sum += character.charCodeAt(0);
  }
  return (sum % 10_000) + 20_000;
}

function createNostrSubscription(subscriptionId: string, topic: string): string {
  return JSON.stringify([
    "REQ",
    subscriptionId,
    {
      kinds: [deriveTrysteroNostrKind(topic)],
      since: Math.floor(Date.now() / 1_000),
      "#x": [topic],
    },
  ]);
}

function deriveEncryptedSignalContext(
  appId: string,
  roomId: string,
): EncryptedSignalContext {
  const context = encodeCanonical({ app_id: appId, room_id: roomId });
  const topic = bytesToHex(sha256(TOPIC_DOMAIN, context));
  return Object.freeze({
    topic,
    keyBytes: ownedBytes(sha256(KEY_DOMAIN, context)),
    additionalData: ownedBytes(
      sha256(AAD_DOMAIN, encodeCanonical({ app_id: appId, room_id: roomId, topic })),
    ),
  });
}

async function encryptSignalPacket(
  plaintext: Uint8Array,
  key: CryptoKey,
  additionalData: Uint8Array<ArrayBuffer>,
  subtleCrypto: SubtleCrypto,
  randomSource: RandomSource,
): Promise<string> {
  const nonce = ownedBytes(randomBytes(NOSTR_SIGNAL_NONCE_BYTES, randomSource));
  const ciphertext = new Uint8Array(
    await subtleCrypto.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData, tagLength: 128 },
      key,
      ownedBytes(plaintext),
    ),
  );
  const envelope = new Uint8Array(1 + nonce.length + ciphertext.length);
  envelope[0] = NOSTR_SIGNAL_ENVELOPE_VERSION;
  envelope.set(nonce, 1);
  envelope.set(ciphertext, 1 + nonce.length);
  return encodeBase64Url(envelope);
}

async function decryptSignalPacket(
  content: string,
  key: CryptoKey,
  additionalData: Uint8Array<ArrayBuffer>,
  subtleCrypto: SubtleCrypto,
): Promise<Uint8Array> {
  const envelope = decodeBase64Url(content);
  if (envelope.length < 1 + NOSTR_SIGNAL_NONCE_BYTES + 16) {
    throw new TypeError("Encrypted Nostr signaling envelope is too short");
  }
  if (envelope[0] !== NOSTR_SIGNAL_ENVELOPE_VERSION) {
    throw new TypeError("Unsupported Nostr signaling envelope version");
  }
  const nonce = ownedBytes(envelope.subarray(1, 1 + NOSTR_SIGNAL_NONCE_BYTES));
  const ciphertext = ownedBytes(envelope.subarray(1 + NOSTR_SIGNAL_NONCE_BYTES));
  return new Uint8Array(
    await subtleCrypto.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData, tagLength: 128 },
      key,
      ciphertext,
    ),
  );
}

function decodeSignalPacket(encoded: Uint8Array): DecodedSignalPacket {
  const value = decodeCanonical(encoded);
  const packet = expectExactMap(value, SIGNAL_PACKET_KEYS, "NostrSignalPacket");
  return Object.freeze({
    from: parseIdentityPublicKey(expectByteString(packet["from"], "NostrSignalPacket.from")),
    to: parseIdentityPublicKey(expectByteString(packet["to"], "NostrSignalPacket.to")),
    frame: decodeDataFrame(expectByteString(packet["frame"], "NostrSignalPacket.frame")),
  });
}

function normalizeAppId(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError("Nostr application ID must be non-empty text");
  }
  if (new TextEncoder().encode(value).length > MAX_APP_ID_BYTES) {
    throw new RangeError(`Nostr application ID must not exceed ${MAX_APP_ID_BYTES} bytes`);
  }
  return value;
}

function normalizeRelayUrls(values: readonly string[]): readonly string[] {
  if (!Array.isArray(values) || values.length === 0 || values.length > MAX_RELAY_URLS) {
    throw new RangeError(`Nostr relay list must contain 1 to ${MAX_RELAY_URLS} URLs`);
  }
  const normalized = new Set<string>();
  for (const candidate of values) {
    if (typeof candidate !== "string" || new TextEncoder().encode(candidate).length > MAX_RELAY_URL_BYTES) {
      throw new TypeError("Nostr relay URL must be bounded text");
    }
    let url: URL;
    try {
      url = new URL(candidate);
    } catch (cause) {
      throw new TypeError("Nostr relay URL is invalid", { cause });
    }
    const isLocalInsecure = url.protocol === "ws:" &&
      (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]");
    if (url.protocol !== "wss:" && !isLocalInsecure) {
      throw new TypeError("Nostr relay URL must use wss, except for localhost development");
    }
    if (url.username !== "" || url.password !== "" || url.hash !== "") {
      throw new TypeError("Nostr relay URL must not contain credentials or a fragment");
    }
    normalized.add(url.toString());
  }
  if (normalized.size === 0) {
    throw new RangeError("Nostr relay list must contain at least one unique URL");
  }
  return Object.freeze([...normalized]);
}

function selectRelayUrls(
  relayUrls: readonly string[],
  redundancy: number,
  topic: string,
): readonly string[] {
  return Object.freeze(
    relayUrls
      .map((url) => ({
        url,
        rank: bytesToHex(
          sha256(
            RELAY_SELECTION_DOMAIN,
            encodeCanonical({ topic, url }),
          ),
        ),
      }))
      .sort((left, right) => compareText(left.rank, right.rank) || compareText(left.url, right.url))
      .slice(0, redundancy)
      .map(({ url }) => url),
  );
}

function requireSignalingPayload(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array) || value.constructor !== Uint8Array) {
    throw new TypeError("Signaling payload must be a Uint8Array");
  }
  if (value.length > MAX_SIGNALING_MESSAGE_BYTES) {
    throw new RangeError(
      `Signaling payload must not exceed ${MAX_SIGNALING_MESSAGE_BYTES} bytes`,
    );
  }
  return value.slice();
}

function hasTopicTag(value: unknown, topic: string | null): boolean {
  return topic !== null &&
    Array.isArray(value) &&
    value.some((tag) =>
      Array.isArray(tag) && tag.length >= 2 && tag[0] === "x" && tag[1] === topic,
    );
}

function publishedEventId(encoded: string): string {
  if (encoded.length > MAX_NOSTR_RELAY_MESSAGE_CHARS) {
    throw new RangeError("Encoded Nostr event exceeds the profiled relay-message limit");
  }
  let message: unknown;
  try {
    message = JSON.parse(encoded);
  } catch (cause) {
    throw new TypeError("Nostr event factory returned invalid JSON", { cause });
  }
  if (
    !Array.isArray(message) ||
    message.length !== 2 ||
    message[0] !== "EVENT" ||
    !isRecord(message[1]) ||
    typeof message[1]["id"] !== "string" ||
    !/^[0-9a-f]{64}$/.test(message[1]["id"])
  ) {
    throw new TypeError("Nostr event factory returned a malformed event");
  }
  return message[1]["id"];
}

function snapshotRelay(relay: RelayState): NostrRelaySnapshot {
  return Object.freeze({
    url: relay.url,
    state: relay.state,
    lastError: relay.lastError,
  });
}

function identityKey(identity: Uint8Array): string {
  return bytesToHex(identity);
}

function uint32FromBytes(bytes: Uint8Array): number {
  if (bytes.length !== 4) {
    throw new TypeError("Frame ID seed must contain exactly four bytes");
  }
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0);
}

function encodeBase64Url(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let encoded = "";
  for (let offset = 0; offset < bytes.length; offset += 3) {
    const first = bytes[offset] ?? 0;
    const second = bytes[offset + 1] ?? 0;
    const third = bytes[offset + 2] ?? 0;
    const value = (first << 16) | (second << 8) | third;
    encoded += alphabet[(value >>> 18) & 0x3f];
    encoded += alphabet[(value >>> 12) & 0x3f];
    if (offset + 1 < bytes.length) {
      encoded += alphabet[(value >>> 6) & 0x3f];
    }
    if (offset + 2 < bytes.length) {
      encoded += alphabet[value & 0x3f];
    }
  }
  return encoded;
}

function decodeBase64Url(value: string): Uint8Array {
  if (value.length === 0 || value.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new TypeError("Nostr event content must be unpadded base64url");
  }
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const bytes = new Uint8Array(Math.floor((value.length * 6) / 8));
  let buffer = 0;
  let bits = 0;
  let offset = 0;
  for (const character of value) {
    const index = alphabet.indexOf(character);
    if (index < 0) {
      throw new TypeError("Nostr event content contains invalid base64url text");
    }
    buffer = (buffer << 6) | index;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes[offset] = (buffer >>> bits) & 0xff;
      offset += 1;
      buffer &= (1 << bits) - 1;
    }
  }
  if (buffer !== 0 || offset !== bytes.length || encodeBase64Url(bytes) !== value) {
    throw new TypeError("Nostr event content is not canonical base64url");
  }
  return bytes;
}

function ownedBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy;
}

function defaultSocketFactory(url: string): NostrRelaySocket {
  if (typeof WebSocket === "undefined") {
    throw new Error("WebSocket is unavailable for Nostr signaling");
  }
  return new WebSocket(url) as unknown as NostrRelaySocket;
}

function positiveInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new RangeError(`${label} must be a positive safe integer`);
  }
  return value as number;
}

function boundedPositiveInteger(value: unknown, label: string, maximum: number): number {
  const normalized = positiveInteger(value, label);
  if (normalized > maximum) {
    throw new RangeError(`${label} must not exceed the relay count`);
  }
  return normalized;
}

function requireFunction(value: unknown, label: string): asserts value is (...args: never[]) => unknown {
  if (typeof value !== "function") {
    throw new TypeError(`${label} must be a function`);
  }
}

function requireOptionalFunction(value: unknown, label: string): void {
  if (value !== undefined && typeof value !== "function") {
    throw new TypeError(`${label} must be a function when provided`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function settlesBeforeTimeout(
  promise: Promise<unknown>,
  timeoutMs: number,
): Promise<boolean> {
  let timer: ReturnType<typeof globalThis.setTimeout> | undefined;
  const timeout = new Promise<false>((resolve) => {
    timer = globalThis.setTimeout(() => resolve(false), timeoutMs);
  });
  try {
    return await Promise.race([promise.then(() => true), timeout]);
  } finally {
    if (timer !== undefined) {
      globalThis.clearTimeout(timer);
    }
  }
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function asError(cause: unknown, fallback: string): Error {
  return cause instanceof Error ? cause : new Error(fallback, { cause });
}
