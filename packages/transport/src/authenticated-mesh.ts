import {
  bytesEqual,
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  type Ed25519SecretKey,
} from "@p2pcards/crypto";
import {
  parseGameId,
  parseIdentityPublicKey,
  type GameId,
  type IdentityPublicKey,
} from "@p2pcards/protocol";

import { AuthenticatedPeerChannel } from "./authenticated-channel";
import {
  DEFAULT_MAX_RETAINED_FAILURES,
  FullMeshTransport,
  type IceConnectionPathDiagnostics,
  type FullMeshPeerSnapshot,
  type MeshPeerConnectionFactory,
} from "./full-mesh";
import type { FrameReassemblerOptions } from "./frame";
import type { FramedSendOptions } from "./framed-sender";
import type { SignalingAdapter } from "./signaling";

export const DEFAULT_PEER_SYNCHRONIZATION_TIMEOUT_MS = 30_000;
export const DEFAULT_MAX_QUEUED_SYNCHRONIZATION_MESSAGES = 64;
export const DEFAULT_MAX_QUEUED_SYNCHRONIZATION_BYTES = 8 * 1024 * 1024;

export interface PeerSynchronizationContext {
  readonly remote: IdentityPublicKey;
  readonly generation: number;
  readonly signal: AbortSignal;
  send(payload: Uint8Array): Promise<void>;
  onMessage(handler: (payload: Uint8Array) => void | Promise<void>): void;
}

export interface AuthenticatedMeshTransportOptions {
  readonly roomId: string;
  readonly gameId: Uint8Array;
  readonly self: Uint8Array;
  readonly secretKey: Ed25519SecretKey;
  readonly roster: readonly Uint8Array[];
  readonly signaling: SignalingAdapter;
  readonly rtcConfiguration?: RTCConfiguration;
  readonly createPeerConnection?: MeshPeerConnectionFactory;
  readonly maxPendingIceCandidates?: number;
  readonly maxAcceptedIceCandidates?: number;
  readonly maxQueuedPeerOperations?: number;
  readonly maxRetainedFailures?: number;
  readonly authenticationTimeoutMs?: number;
  readonly maxQueuedChannelMessages?: number;
  readonly synchronizationTimeoutMs?: number;
  readonly maxQueuedSynchronizationMessages?: number;
  readonly maxQueuedSynchronizationBytes?: number;
  readonly reassembler?: FrameReassemblerOptions;
  readonly sender?: FramedSendOptions;
  /** Trusted session owner: resolve only after verified, durably committed catch-up. */
  readonly synchronizePeer: (context: PeerSynchronizationContext) => Promise<void>;
  readonly onPeerAuthenticated?: (remote: IdentityPublicKey) => void;
  readonly onPeerReady?: (remote: IdentityPublicKey) => void;
  readonly onPeerDisconnected?: (remote: IdentityPublicKey, generation: number) => void;
  readonly onMessage: (remote: IdentityPublicKey, payload: Uint8Array) => void;
  readonly onError?: (error: Error, remote: IdentityPublicKey | null) => void;
}

export interface AuthenticatedMeshFailure {
  readonly error: Error;
  readonly remote: IdentityPublicKey | null;
}

interface PeerSession {
  readonly remote: IdentityPublicKey;
  readonly generation: number;
  readonly channel: RTCDataChannel;
  readonly onOpen: () => void;
  readonly onClose: () => void;
  readonly abortController: AbortController;
  readonly ready: Promise<void>;
  readonly resolveReady: () => void;
  readonly rejectReady: (error: Error) => void;
  phase: "connecting" | "authenticating" | "synchronizing" | "ready" | "closed";
  authenticatedChannel: AuthenticatedPeerChannel | null;
  synchronizationHandler: ((payload: Uint8Array) => void | Promise<void>) | null;
  receiveQueue: Promise<void>;
  queuedMessages: number;
  queuedBytes: number;
  timer: ReturnType<typeof globalThis.setTimeout> | null;
}

export class AuthenticatedMeshTransport {
  readonly #gameId: GameId;
  readonly #secretKey: Ed25519SecretKey;
  readonly #mesh: FullMeshTransport;
  readonly #authenticationOptions: Pick<
    AuthenticatedMeshTransportOptions,
    | "authenticationTimeoutMs"
    | "maxQueuedChannelMessages"
    | "reassembler"
    | "sender"
  >;
  readonly #onPeerAuthenticated:
    | ((remote: IdentityPublicKey) => void)
    | undefined;
  readonly #synchronizePeer: (context: PeerSynchronizationContext) => Promise<void>;
  readonly #onPeerReady: ((remote: IdentityPublicKey) => void) | undefined;
  readonly #onPeerDisconnected:
    | ((remote: IdentityPublicKey, generation: number) => void)
    | undefined;
  readonly #synchronizationTimeoutMs: number;
  readonly #maxQueuedSynchronizationMessages: number;
  readonly #maxQueuedSynchronizationBytes: number;
  readonly #onMessage: (remote: IdentityPublicKey, payload: Uint8Array) => void;
  readonly #onError:
    | ((error: Error, remote: IdentityPublicKey | null) => void)
    | undefined;
  readonly #maxRetainedFailures: number;
  readonly #sessions = new Map<string, PeerSession>();
  readonly #failures: AuthenticatedMeshFailure[] = [];
  #closed = false;

  constructor(options: AuthenticatedMeshTransportOptions) {
    if (typeof options !== "object" || options === null) {
      throw new TypeError("Authenticated mesh options are required");
    }
    this.#gameId = parseGameId(options.gameId);
    const self = parseIdentityPublicKey(options.self);
    this.#secretKey = importEd25519SecretKey(options.secretKey);
    if (!bytesEqual(deriveEd25519PublicKey(this.#secretKey), self)) {
      throw new Error("Authenticated mesh identity does not match its signing key");
    }
    if (typeof options.onMessage !== "function") {
      throw new TypeError("Authenticated mesh message handler must be a function");
    }
    if (typeof options.synchronizePeer !== "function") {
      throw new TypeError("Authenticated mesh requires an explicit peer synchronizer");
    }
    this.#synchronizePeer = options.synchronizePeer;
    this.#onPeerReady = options.onPeerReady;
    this.#onPeerDisconnected = options.onPeerDisconnected;
    this.#synchronizationTimeoutMs = positiveInteger(
      options.synchronizationTimeoutMs ?? DEFAULT_PEER_SYNCHRONIZATION_TIMEOUT_MS,
      "Peer synchronization timeout",
    );
    this.#maxQueuedSynchronizationMessages = positiveInteger(
      options.maxQueuedSynchronizationMessages ?? DEFAULT_MAX_QUEUED_SYNCHRONIZATION_MESSAGES,
      "Maximum queued synchronization messages",
    );
    this.#maxQueuedSynchronizationBytes = positiveInteger(
      options.maxQueuedSynchronizationBytes ?? DEFAULT_MAX_QUEUED_SYNCHRONIZATION_BYTES,
      "Maximum queued synchronization bytes",
    );
    this.#onMessage = options.onMessage;
    this.#onPeerAuthenticated = options.onPeerAuthenticated;
    this.#onError = options.onError;
    this.#maxRetainedFailures = positiveInteger(
      options.maxRetainedFailures ?? DEFAULT_MAX_RETAINED_FAILURES,
      "Maximum retained authenticated-mesh failures",
    );
    this.#authenticationOptions = Object.freeze({
      ...(options.authenticationTimeoutMs === undefined
        ? {}
        : { authenticationTimeoutMs: options.authenticationTimeoutMs }),
      ...(options.maxQueuedChannelMessages === undefined
        ? {}
        : { maxQueuedChannelMessages: options.maxQueuedChannelMessages }),
      ...(options.reassembler === undefined
        ? {}
        : { reassembler: { ...options.reassembler } }),
      ...(options.sender === undefined ? {} : { sender: { ...options.sender } }),
    });
    this.#mesh = new FullMeshTransport({
      roomId: options.roomId,
      self,
      roster: options.roster,
      signaling: options.signaling,
      ...(options.rtcConfiguration === undefined
        ? {}
        : { rtcConfiguration: options.rtcConfiguration }),
      ...(options.createPeerConnection === undefined
        ? {}
        : { createPeerConnection: options.createPeerConnection }),
      ...(options.maxPendingIceCandidates === undefined
        ? {}
        : { maxPendingIceCandidates: options.maxPendingIceCandidates }),
      ...(options.maxAcceptedIceCandidates === undefined
        ? {}
        : { maxAcceptedIceCandidates: options.maxAcceptedIceCandidates }),
      ...(options.maxQueuedPeerOperations === undefined
        ? {}
        : { maxQueuedPeerOperations: options.maxQueuedPeerOperations }),
      ...(options.maxRetainedFailures === undefined
        ? {}
        : { maxRetainedFailures: options.maxRetainedFailures }),
      onUnauthenticatedDataChannel: (remote, channel, generation) =>
        this.#bindChannel(remote, channel, generation),
      onPeerDisconnected: (remote, generation) => {
        const session = this.#sessions.get(identityKey(remote));
        if (session?.generation === generation) {
          const failure = session.authenticatedChannel?.failure;
          this.#discardSession(session, failure ?? new Error("Peer disconnected before transport shutdown"));
          if (failure !== null && failure !== undefined) {
            this.#report(failure, remote, generation);
          }
        }
        if (!this.#closed && this.#hasGeneration(remote, generation)) {
          try {
            this.#onPeerDisconnected?.(parseIdentityPublicKey(remote), generation);
          } catch (cause) {
            this.#report(cause, remote, generation);
          }
        }
      },
      onError: (error, remote) => this.#report(error, remote),
    });
  }

  get started(): boolean {
    return this.#mesh.started;
  }

  get peers(): readonly FullMeshPeerSnapshot[] {
    return this.#mesh.peers;
  }

  get authenticatedPeers(): readonly IdentityPublicKey[] {
    return Object.freeze(
      this.#mesh.peers
        .filter(({ identity }) => this.#sessions.get(identityKey(identity))?.authenticatedChannel?.authenticated)
        .map(({ identity }) => parseIdentityPublicKey(identity)),
    );
  }

  get readyPeers(): readonly IdentityPublicKey[] {
    return Object.freeze(
      this.#mesh.peers
        .filter(({ identity }) => this.#sessions.get(identityKey(identity))?.phase === "ready")
        .map(({ identity }) => parseIdentityPublicKey(identity)),
    );
  }

  get failures(): readonly AuthenticatedMeshFailure[] {
    return Object.freeze(
      this.#failures.map(({ error, remote }) =>
        Object.freeze({
          error,
          remote: remote === null ? null : parseIdentityPublicKey(remote),
        }),
      ),
    );
  }

  async start(): Promise<void> {
    if (this.#closed) {
      throw new Error("Authenticated mesh is closed");
    }
    await this.#mesh.start();
  }

  async requestNegotiation(remote: Uint8Array): Promise<void> {
    await this.#mesh.requestNegotiation(remote);
  }

  async reconnectPeer(remote: Uint8Array): Promise<void> {
    if (this.#closed) {
      throw new Error("Authenticated mesh is closed");
    }
    await this.#mesh.reconnectPeer(remote);
  }

  async connectionPath(remote: Uint8Array): Promise<IceConnectionPathDiagnostics> {
    return this.#mesh.connectionPath(remote);
  }

  authenticationFor(remote: Uint8Array): Promise<void> {
    const identity = parseIdentityPublicKey(remote);
    const channel = this.#sessions.get(identityKey(identity))?.authenticatedChannel;
    if (channel === undefined || channel === null) {
      return Promise.reject(new Error("Peer data channel is not open for authentication"));
    }
    return channel.start();
  }

  readyFor(remote: Uint8Array): Promise<void> {
    const identity = parseIdentityPublicKey(remote);
    const session = this.#sessions.get(identityKey(identity));
    return session?.ready ?? Promise.reject(new Error("Peer has no active synchronization boundary"));
  }

  async send(remote: Uint8Array, payload: Uint8Array): Promise<void> {
    const identity = parseIdentityPublicKey(remote);
    const session = this.#sessions.get(identityKey(identity));
    if (session?.phase !== "ready" || session.authenticatedChannel === null) {
      throw new Error("Application payload cannot be sent before peer authentication and synchronization");
    }
    await session.authenticatedChannel.send(payload);
  }

  async whenIdle(): Promise<void> {
    for (let pass = 0; pass < 3; pass += 1) {
      await this.#mesh.whenIdle();
      await Promise.all([...this.#sessions.values()].map(async (session) => {
        await session.authenticatedChannel?.whenIdle();
        await session.receiveQueue;
      }));
      await Promise.resolve();
    }
  }

  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    for (const session of [...this.#sessions.values()]) {
      this.#discardSession(session, new Error("Authenticated mesh is closed"));
    }
    await this.#mesh.close();
  }

  #bindChannel(remoteCandidate: IdentityPublicKey, channel: RTCDataChannel, generation: number): void {
    const remote = parseIdentityPublicKey(remoteCandidate);
    const key = identityKey(remote);
    if (this.#closed || this.#sessions.has(key)) {
      channel.close();
      this.#report(new Error("Rejected a duplicate or closed authenticated-mesh channel"), remote, generation);
      return;
    }
    let resolveReady!: () => void;
    let rejectReady!: (error: Error) => void;
    const ready = new Promise<void>((resolve, reject) => {
      resolveReady = resolve;
      rejectReady = reject;
    });
    void ready.catch(() => undefined);
    const onOpen = (): void => this.#beginAuthentication(session);
    const onClose = (): void => this.#failSession(session, new Error("Peer data channel closed before authentication"));
    const session: PeerSession = {
      remote, generation, channel, onOpen, onClose, ready, resolveReady, rejectReady,
      abortController: new AbortController(),
      phase: "connecting",
      authenticatedChannel: null,
      synchronizationHandler: null,
      receiveQueue: Promise.resolve(),
      queuedMessages: 0,
      queuedBytes: 0,
      timer: null,
    };
    this.#sessions.set(key, session);
    channel.addEventListener("open", onOpen);
    channel.addEventListener("close", onClose);
    if (channel.readyState === "open") {
      this.#beginAuthentication(session);
    } else if (channel.readyState !== "connecting") {
      onClose();
    }
  }

  #beginAuthentication(session: PeerSession): void {
    if (!this.#isCurrent(session) || session.phase !== "connecting") {
      return;
    }
    session.channel.removeEventListener("open", session.onOpen);
    session.channel.removeEventListener("close", session.onClose);
    session.phase = "authenticating";
    try {
      const fingerprints = this.#mesh.dtlsFingerprints(session.remote);
      const authenticationOptions = this.#authenticationOptions;
      const channel = new AuthenticatedPeerChannel({
        channel: session.channel,
        gameId: this.#gameId,
        secretKey: this.#secretKey,
        remoteIdentity: session.remote,
        localFingerprint: fingerprints.localFingerprint,
        remoteFingerprint: fingerprints.remoteFingerprint,
        onMessage: (payload) => this.#receive(session, payload),
        onAuthenticated: () => {
          this.#beginSynchronization(session);
          if (this.#isCurrent(session)) {
            this.#onPeerAuthenticated?.(parseIdentityPublicKey(session.remote));
          }
        },
        onError: (error) => this.#failSession(session, error),
        ...(authenticationOptions.authenticationTimeoutMs === undefined
          ? {}
          : { authenticationTimeoutMs: authenticationOptions.authenticationTimeoutMs }),
        ...(authenticationOptions.maxQueuedChannelMessages === undefined
          ? {}
          : { maxQueuedMessages: authenticationOptions.maxQueuedChannelMessages }),
        ...(authenticationOptions.reassembler === undefined
          ? {}
          : { reassembler: authenticationOptions.reassembler }),
        ...(authenticationOptions.sender === undefined
          ? {}
          : { sender: authenticationOptions.sender }),
      });
      session.authenticatedChannel = channel;
      void channel.start().catch(() => undefined);
    } catch (cause) {
      this.#failSession(session, asError(cause, "Failed to initialize channel authentication"));
    }
  }

  #beginSynchronization(session: PeerSession): void {
    if (!this.#isCurrent(session) || session.phase !== "authenticating") {
      return;
    }
    session.phase = "synchronizing";
    session.timer = globalThis.setTimeout(() => {
      this.#failSession(session, new Error("Peer synchronization timed out"));
    }, this.#synchronizationTimeoutMs);
    const context: PeerSynchronizationContext = Object.freeze({
      remote: parseIdentityPublicKey(session.remote),
      generation: session.generation,
      signal: session.abortController.signal,
      send: async (payload: Uint8Array): Promise<void> => {
        this.#requireSynchronizing(session);
        await session.authenticatedChannel!.send(payload);
        this.#requireSynchronizing(session);
      },
      onMessage: (handler: (payload: Uint8Array) => void | Promise<void>): void => {
        this.#requireSynchronizing(session);
        if (typeof handler !== "function") {
          throw new TypeError("Peer synchronization message handler must be a function");
        }
        session.synchronizationHandler = handler;
      },
    });
    try {
      const synchronization = this.#synchronizePeer(context);
      if (synchronization === null || synchronization === undefined || typeof synchronization.then !== "function") {
        throw new TypeError("Peer synchronizer must return a promise for completed synchronization");
      }
      void synchronization.then(() => this.#finishSynchronization(session)).catch((cause: unknown) => {
        this.#failSession(session, asError(cause, "Peer synchronization failed"));
      });
    } catch (cause) {
      this.#failSession(session, asError(cause, "Peer synchronization failed"));
    }
  }

  async #finishSynchronization(session: PeerSession): Promise<void> {
    for (;;) {
      this.#requireSynchronizing(session);
      const queue = session.receiveQueue;
      await Promise.race([queue, session.ready]);
      this.#requireSynchronizing(session);
      if (queue === session.receiveQueue) {
        break;
      }
    }
    if (session.timer !== null) {
      globalThis.clearTimeout(session.timer);
      session.timer = null;
    }
    session.synchronizationHandler = null;
    session.phase = "ready";
    this.#onPeerReady?.(parseIdentityPublicKey(session.remote));
    if (this.#isCurrent(session)) {
      session.resolveReady();
    }
  }

  #receive(session: PeerSession, payload: Uint8Array): void {
    if (!this.#isCurrent(session)) {
      return;
    }
    if (session.phase === "ready") {
      this.#onMessage(parseIdentityPublicKey(session.remote), payload);
      return;
    }
    this.#requireSynchronizing(session);
    const handler = session.synchronizationHandler;
    if (handler === null) {
      throw new Error("Peer synchronizer has no receive handler for pre-ready traffic");
    }
    const byteLength = payload.byteLength;
    if (
      session.queuedMessages >= this.#maxQueuedSynchronizationMessages ||
      session.queuedBytes + byteLength > this.#maxQueuedSynchronizationBytes
    ) {
      throw new Error("Queued peer synchronization traffic limit exceeded");
    }
    session.queuedMessages += 1;
    session.queuedBytes += byteLength;
    session.receiveQueue = session.receiveQueue.then(async () => {
      this.#requireSynchronizing(session);
      // Release queued payloads on cancellation even if the active receiver never settles.
      await Promise.race([handler(payload), session.ready]);
    }).catch((cause: unknown) => {
      this.#failSession(session, asError(cause, "Peer synchronization receive failed"));
    }).finally(() => {
      session.queuedMessages -= 1;
      session.queuedBytes -= byteLength;
    });
  }

  #requireSynchronizing(session: PeerSession): void {
    if (!this.#isCurrent(session) || session.phase !== "synchronizing") {
      throw new Error("Peer synchronization context is no longer active");
    }
  }

  #isCurrent(session: PeerSession): boolean {
    return !this.#closed && session.phase !== "closed" &&
      this.#sessions.get(identityKey(session.remote)) === session;
  }

  #hasGeneration(remote: IdentityPublicKey, generation: number): boolean {
    return this.#mesh.peers.some((peer) =>
      peer.generation === generation && bytesEqual(peer.identity, remote),
    );
  }

  #failSession(session: PeerSession, error: Error): void {
    if (!this.#isCurrent(session)) {
      return;
    }
    this.#discardSession(session, error);
    this.#mesh.disconnectPeer(session.remote, session.generation);
    this.#report(error, session.remote, session.generation);
  }

  #discardSession(session: PeerSession, error: Error): void {
    if (session.phase === "closed") {
      return;
    }
    if (this.#sessions.get(identityKey(session.remote)) === session) {
      this.#sessions.delete(identityKey(session.remote));
    }
    session.phase = "closed";
    session.channel.removeEventListener("open", session.onOpen);
    session.channel.removeEventListener("close", session.onClose);
    if (session.timer !== null) {
      globalThis.clearTimeout(session.timer);
      session.timer = null;
    }
    session.synchronizationHandler = null;
    session.rejectReady(error);
    session.abortController.abort(error);
    if (session.authenticatedChannel === null) {
      session.channel.close();
    } else {
      session.authenticatedChannel.close();
    }
  }

  #report(cause: unknown, remote: IdentityPublicKey | null, generation?: number): void {
    const error = asError(cause, "Authenticated mesh operation failed");
    const remoteSnapshot = remote === null ? null : parseIdentityPublicKey(remote);
    if (this.#failures.length >= this.#maxRetainedFailures) {
      this.#failures.shift();
    }
    this.#failures.push(Object.freeze({ error, remote: remoteSnapshot }));
    if (this.#closed || (remote !== null && generation !== undefined && !this.#hasGeneration(remote, generation))) {
      return;
    }
    try {
      this.#onError?.(error, remoteSnapshot === null ? null : parseIdentityPublicKey(remoteSnapshot));
    } catch {
      // Observers cannot alter authentication or transport state.
    }
  }
}

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${label} must be a positive safe integer`);
  }
  return value;
}

function identityKey(identity: Uint8Array): string {
  return Array.from(identity, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function asError(cause: unknown, fallback: string): Error {
  return cause instanceof Error ? cause : new Error(fallback, { cause });
}
