import {
  parseIdentityPublicKey,
  type DtlsFingerprint,
  type IdentityPublicKey,
} from "@p2pcards/protocol";

import { compareIdentities, perfectNegotiationRole, type PerfectNegotiationRole } from "./peer-role";
import { sha256FingerprintFromSdp } from "./dtls-fingerprint";
import {
  candidateSignal,
  candidateSignalInit,
  decodePeerSignal,
  descriptionSignal,
  encodePeerSignal,
  type CandidateSignal,
  type DescriptionSignal,
  type PeerSignal,
} from "./signaling-message";
import { parseSignalingRoomId, type SignalingAdapter } from "./signaling";

export const DATA_CHANNEL_LABEL = "p2pcards";
export const DATA_CHANNEL_ID = 0;
export const DEFAULT_MAX_PENDING_ICE_CANDIDATES = 256;
export const DEFAULT_MAX_ACCEPTED_ICE_CANDIDATES = 512;
export const DEFAULT_MAX_QUEUED_PEER_OPERATIONS = 256;
export const DEFAULT_MAX_RETAINED_FAILURES = 128;
const MAX_RETIRED_REMOTE_SESSIONS = 8;
export const DEFAULT_STUN_URLS = Object.freeze([
  "stun:stun.l.google.com:19302",
  "stun:stun.cloudflare.com:3478",
]);

export interface MeshPeerConnection {
  readonly signalingState: RTCSignalingState;
  readonly connectionState: RTCPeerConnectionState;
  readonly iceGatheringState: RTCIceGatheringState;
  readonly localDescription: RTCSessionDescriptionInit | null;
  readonly remoteDescription: RTCSessionDescriptionInit | null;
  onnegotiationneeded: ((event: Event) => void) | null;
  onicecandidate: ((event: RTCPeerConnectionIceEvent) => void) | null;
  ondatachannel: ((event: RTCDataChannelEvent) => void) | null;
  onconnectionstatechange: ((event: Event) => void) | null;
  setLocalDescription(description?: RTCSessionDescriptionInit): Promise<void>;
  setRemoteDescription(description: RTCSessionDescriptionInit): Promise<void>;
  addIceCandidate(candidate?: RTCIceCandidateInit | null): Promise<void>;
  createDataChannel(label: string, options?: RTCDataChannelInit): RTCDataChannel;
  getStats?(): Promise<RTCStatsReport>;
  close(): void;
}

export type MeshPeerConnectionFactory = (
  remote: IdentityPublicKey,
  configuration: RTCConfiguration,
) => MeshPeerConnection;

export interface FullMeshTransportOptions {
  readonly roomId: string;
  readonly self: Uint8Array;
  readonly roster: readonly Uint8Array[];
  readonly membership?: "finalized" | "lobby";
  readonly onUnknownPeer?: (remote: IdentityPublicKey) => boolean;
  readonly signaling: SignalingAdapter;
  readonly rtcConfiguration?: RTCConfiguration;
  readonly createPeerConnection?: MeshPeerConnectionFactory;
  readonly maxPendingIceCandidates?: number;
  readonly maxAcceptedIceCandidates?: number;
  readonly maxQueuedPeerOperations?: number;
  readonly maxRetainedFailures?: number;
  readonly onUnauthenticatedDataChannel?: (
    remote: IdentityPublicKey,
    channel: RTCDataChannel,
    generation: number,
  ) => void;
  readonly onPeerDisconnected?: (remote: IdentityPublicKey, generation: number) => void;
  readonly onError?: (error: Error, remote: IdentityPublicKey | null) => void;
}

export interface FullMeshPeerSnapshot {
  readonly identity: IdentityPublicKey;
  readonly generation: number;
  readonly role: PerfectNegotiationRole;
  readonly hasDataChannel: boolean;
  readonly signalingState: RTCSignalingState;
  readonly connectionState: RTCPeerConnectionState;
}

export interface FullMeshPeerFingerprints {
  readonly localFingerprint: DtlsFingerprint;
  readonly remoteFingerprint: DtlsFingerprint;
}

export type IceConnectionPath = "direct" | "relayed" | "unknown";

export interface IceConnectionPathDiagnostics {
  readonly path: IceConnectionPath;
  readonly selectedCandidatePairId: string | null;
  readonly localCandidateType: RTCIceCandidateType | null;
  readonly remoteCandidateType: RTCIceCandidateType | null;
}

export interface FullMeshTransportFailure {
  readonly error: Error;
  readonly remote: IdentityPublicKey | null;
}

interface PeerState {
  readonly identity: IdentityPublicKey;
  readonly generation: number;
  readonly role: PerfectNegotiationRole;
  readonly connection: MeshPeerConnection;
  readonly pendingCandidates: CandidateSignal[];
  readonly acceptedCandidateKeys: Set<string>;
  readonly retiredRemoteSessions: RemoteSession[];
  readonly iceInitialized: Promise<void>;
  readonly markIceInitialized: () => void;
  cancelOperation: (() => void) | null;
  retired: boolean;
  remoteSession: RemoteSession | null;
  remoteUfrag: string | null;
  acceptedCandidateUfrag: string | null;
  acceptedEndOfCandidates: boolean;
  queue: Promise<void>;
  queuedOperations: number;
  descriptionRevision: number;
  makingOffer: boolean;
  ignoreOffer: boolean;
  settingRemoteAnswer: boolean;
  ignoredRemoteUfrag: string | null;
  lastRemoteDescriptionKey: string | null;
  dataChannel: RTCDataChannel | null;
  onDataChannelClose: (() => void) | null;
}

interface RemoteSession {
  readonly origin: string | null;
  readonly version: bigint | null;
  readonly fingerprint: string | null;
}

interface EarlyPeerSignal {
  readonly identity: IdentityPublicKey;
  readonly signal: PeerSignal;
}

type Lifecycle = "new" | "starting" | "started" | "closing" | "closed";

export class FullMeshTransport {
  readonly #roomId: string;
  readonly #self: IdentityPublicKey;
  readonly #roster: readonly IdentityPublicKey[];
  readonly #rosterKeys: Set<string>;
  readonly #membership: "finalized" | "lobby";
  readonly #onUnknownPeer: ((remote: IdentityPublicKey) => boolean) | undefined;
  #lobbyGeneration = 0;
  readonly #signaling: SignalingAdapter;
  readonly #rtcConfiguration: RTCConfiguration;
  readonly #createPeerConnection: MeshPeerConnectionFactory;
  readonly #maxPendingIceCandidates: number;
  readonly #maxAcceptedIceCandidates: number;
  readonly #maxQueuedPeerOperations: number;
  readonly #maxRetainedFailures: number;
  readonly #onUnauthenticatedDataChannel:
    | ((remote: IdentityPublicKey, channel: RTCDataChannel, generation: number) => void)
    | undefined;
  readonly #onPeerDisconnected:
    | ((remote: IdentityPublicKey, generation: number) => void)
    | undefined;
  readonly #onError: ((error: Error, remote: IdentityPublicKey | null) => void) | undefined;
  readonly #peers = new Map<string, PeerState>();
  readonly #earlySignals: EarlyPeerSignal[] = [];
  readonly #failures: FullMeshTransportFailure[] = [];
  #lifecycle: Lifecycle = "new";

  constructor(options: FullMeshTransportOptions) {
    if (typeof options !== "object" || options === null) {
      throw new TypeError("Full-mesh transport options are required");
    }
    this.#roomId = parseSignalingRoomId(options.roomId);
    this.#self = parseIdentityPublicKey(options.self);
    this.#membership = options.membership ?? "finalized";
    if (this.#membership !== "finalized" && this.#membership !== "lobby") {
      throw new TypeError("Unknown mesh membership mode");
    }
    if (options.onUnknownPeer !== undefined && (this.#membership !== "lobby" || typeof options.onUnknownPeer !== "function")) {
      throw new TypeError("Unknown-peer admission requires explicit lobby membership");
    }
    this.#onUnknownPeer = options.onUnknownPeer;
    this.#roster = normalizeRoster(options.roster, this.#self, this.#membership === "lobby" ? 1 : 3);
    this.#rosterKeys = new Set(this.#roster.map(identityKey));
    this.#signaling = options.signaling;
    this.#rtcConfiguration = normalizeRtcConfiguration(options.rtcConfiguration);
    this.#createPeerConnection =
      options.createPeerConnection ?? defaultPeerConnectionFactory;
    this.#maxPendingIceCandidates = positiveInteger(
      options.maxPendingIceCandidates ?? DEFAULT_MAX_PENDING_ICE_CANDIDATES,
      "Maximum pending ICE candidates",
    );
    this.#maxAcceptedIceCandidates = positiveInteger(
      options.maxAcceptedIceCandidates ?? DEFAULT_MAX_ACCEPTED_ICE_CANDIDATES,
      "Maximum accepted ICE candidates",
    );
    this.#maxQueuedPeerOperations = positiveInteger(
      options.maxQueuedPeerOperations ?? DEFAULT_MAX_QUEUED_PEER_OPERATIONS,
      "Maximum queued peer operations",
    );
    this.#maxRetainedFailures = positiveInteger(
      options.maxRetainedFailures ?? DEFAULT_MAX_RETAINED_FAILURES,
      "Maximum retained transport failures",
    );
    this.#onUnauthenticatedDataChannel = options.onUnauthenticatedDataChannel;
    this.#onPeerDisconnected = options.onPeerDisconnected;
    this.#onError = options.onError;
  }

  get started(): boolean {
    return this.#lifecycle === "started";
  }

  get failures(): readonly FullMeshTransportFailure[] {
    return Object.freeze(
      this.#failures.map(({ error, remote }) =>
        Object.freeze({
          error,
          remote: remote === null ? null : parseIdentityPublicKey(remote),
        }),
      ),
    );
  }

  get peers(): readonly FullMeshPeerSnapshot[] {
    return Object.freeze(
      [...this.#peers.values()]
        .sort((left, right) => compareIdentities(left.identity, right.identity))
        .map((peer) =>
          Object.freeze({
            identity: parseIdentityPublicKey(peer.identity),
            generation: peer.generation,
            role: peer.role,
            hasDataChannel: peer.dataChannel !== null,
            signalingState: peer.retired ? "closed" : peer.connection.signalingState,
            connectionState: peer.retired ? "closed" : peer.connection.connectionState,
          }),
        ),
    );
  }

  dtlsFingerprints(remote: Uint8Array): FullMeshPeerFingerprints {
    const peer = this.#requirePeer(remote);
    const localSdp = peer.connection.localDescription?.sdp;
    const remoteSdp = peer.connection.remoteDescription?.sdp;
    if (localSdp === undefined || remoteSdp === undefined) {
      throw new Error("Peer DTLS fingerprints are unavailable before SDP negotiation");
    }
    return Object.freeze({
      localFingerprint: sha256FingerprintFromSdp(localSdp),
      remoteFingerprint: sha256FingerprintFromSdp(remoteSdp),
    });
  }

  async connectionPath(remote: Uint8Array): Promise<IceConnectionPathDiagnostics> {
    const peer = this.#requirePeer(remote);
    if (peer.connection.getStats === undefined) {
      throw new Error("Peer connection statistics are unavailable");
    }
    const report = await peer.connection.getStats();
    if (!this.#isCurrent(peer)) {
      throw new Error("Peer connection statistics were superseded");
    }
    return inspectIceConnectionPath(report);
  }

  async start(): Promise<void> {
    if (this.#lifecycle !== "new") {
      throw new Error("Full-mesh transport can only be started once");
    }
    this.#lifecycle = "starting";
    this.#signaling.onMessage((from, payload) => this.#receive(from, payload));
    try {
      await this.#signaling.join(this.#roomId, this.#self);
      if (this.#lifecycle !== "starting") {
        throw new Error("Full-mesh transport startup was cancelled");
      }
      for (const remote of this.#roster) {
        if (this.#lifecycle !== "starting") {
          throw new Error("Full-mesh transport startup was cancelled");
        }
        if (compareIdentities(remote, this.#self) !== 0) {
          this.#createPeer(remote);
        }
      }
      if (this.#lifecycle !== "starting") {
        throw new Error("Full-mesh transport startup was cancelled");
      }
      this.#lifecycle = "started";
      for (const early of this.#earlySignals.splice(0)) {
        const peer = this.#peers.get(identityKey(early.identity));
        if (peer !== undefined) {
          this.#submitSignal(peer, early.signal);
        } else if (this.#membership === "lobby") {
          this.#receive(early.identity, encodePeerSignal(early.signal));
        }
      }
    } catch (cause) {
      if (this.#lifecycle === "starting") {
        this.#lifecycle = "closed";
        this.#closePeers();
        await this.#signaling.leave().catch(() => undefined);
      }
      throw asError(cause, "Failed to start full-mesh transport");
    }
  }

  async requestNegotiation(remote: Uint8Array): Promise<void> {
    const peer = this.#requirePeer(remote);
    await this.#enqueue(peer, () => this.#negotiate(peer));
    if (!this.#isCurrent(peer)) {
      throw new Error("Peer negotiation was superseded");
    }
  }

  async admitPeer(remote: Uint8Array): Promise<void> {
    this.#requireLobby();
    const identity = parseIdentityPublicKey(remote);
    const existing = this.#peers.get(identityKey(identity));
    if (existing !== undefined) {
      if (!this.#rosterKeys.has(identityKey(identity))) {
        throw new Error("Peer removal is still in progress");
      }
      if (existing.retired) { await this.reconnectPeer(identity); }
      return;
    }
    const peer = this.#admit(identity);
    if (peer === null) { throw new Error("Peer admission was superseded"); }
    await this.#enqueue(peer, () => this.#negotiate(peer));
  }

  removePeer(remote: Uint8Array): void {
    this.#requireLobby();
    const identity = parseIdentityPublicKey(remote);
    const key = identityKey(identity);
    if (compareIdentities(identity, this.#self) === 0) { throw new Error("Cannot remove the local identity"); }
    this.#rosterKeys.delete(key);
    const peer = this.#peers.get(key);
    if (peer !== undefined) {
      this.#retirePeer(peer);
      if (this.#peers.get(key) === peer) { this.#peers.delete(key); }
    }
  }

  #requireLobby(): void {
    if (this.#membership !== "lobby" || this.#lifecycle !== "started") {
      throw new Error("Dynamic peer membership requires a started lobby mesh");
    }
  }

  #admit(identity: IdentityPublicKey): PeerState | null {
    this.#requireLobby();
    const key = identityKey(identity);
    if (compareIdentities(identity, this.#self) === 0) { throw new Error("Cannot admit the local identity twice"); }
    if (this.#peers.has(key)) { return this.#peers.get(key)!; }
    if (this.#rosterKeys.size >= 8) { throw new RangeError("Lobby transport member limit exceeded"); }
    this.#rosterKeys.add(key);
    try {
      return this.#createPeer(identity);
    } catch (cause) {
      if (!this.#peers.has(key)) { this.#rosterKeys.delete(key); }
      throw cause;
    }
  }

  /** Unknown peers, retired peers, and mismatched expected generations are no-ops. */
  disconnectPeer(remote: Uint8Array, generation?: number): void {
    const identity = parseIdentityPublicKey(remote);
    if (generation !== undefined) {
      positiveInteger(generation, "Expected peer generation");
    }
    const peer = this.#peers.get(identityKey(identity));
    if (peer !== undefined && (generation === undefined || generation === peer.generation)) {
      this.#retirePeer(peer);
    }
  }

  /** Waits for SDP signaling submission, not channel opening, HELLO, or synchronization. */
  async reconnectPeer(remote: Uint8Array): Promise<void> {
    const peer = this.#replacePeer(this.#requirePeer(remote, true));
    if (peer === null) {
      throw new Error("Peer replacement was superseded");
    }
    await this.#enqueue(peer, () => this.#negotiate(peer));
    if (!this.#isCurrent(peer)) {
      throw new Error("Peer negotiation was superseded");
    }
  }

  async whenIdle(): Promise<void> {
    for (;;) {
      const snapshot = [...this.#peers.values()].map((peer) => peer.queue);
      await Promise.all(snapshot);
      if ([...this.#peers.values()].every((peer, index) => peer.queue === snapshot[index])) {
        return;
      }
    }
  }

  async close(): Promise<void> {
    if (this.#lifecycle === "closed" || this.#lifecycle === "closing") {
      return;
    }
    this.#lifecycle = "closing";
    this.#closePeers();
    try {
      await this.#signaling.leave();
    } finally {
      this.#lifecycle = "closed";
    }
  }

  #createPeer(
    remote: IdentityPublicKey,
    previous?: PeerState,
    remoteSession: RemoteSession | null = null,
    remoteOfferUfrag: string | null = null,
  ): PeerState | null {
    const generation = this.#membership === "lobby"
      ? Math.max(this.#lobbyGeneration, previous?.generation ?? 0) + 1
      : (previous?.generation ?? 0) + 1;
    if (!Number.isSafeInteger(generation)) {
      throw new RangeError("Peer generation limit exceeded");
    }
    if (this.#membership === "lobby") { this.#lobbyGeneration = generation; }
    const identity = parseIdentityPublicKey(remote);
    const role = perfectNegotiationRole(this.#self, identity);
    const connection = this.#createPeerConnection(
      parseIdentityPublicKey(identity),
      cloneRtcConfiguration(this.#rtcConfiguration),
    );
    if (
      (this.#lifecycle !== "starting" && this.#lifecycle !== "started") ||
      !this.#rosterKeys.has(identityKey(identity)) ||
      this.#peers.get(identityKey(identity)) !== previous
    ) {
      connection.close();
      return null;
    }
    let markIceInitialized!: () => void;
    const iceInitialized = new Promise<void>((resolve) => { markIceInitialized = resolve; });
    const state: PeerState = {
      identity,
      generation,
      role,
      connection,
      iceInitialized,
      markIceInitialized,
      retired: false,
      retiredRemoteSessions: [...(previous?.retiredRemoteSessions ?? [])],
      remoteSession,
      remoteUfrag: remoteOfferUfrag,
      cancelOperation: null,
      pendingCandidates: previous?.pendingCandidates.filter((candidate) =>
        candidate.usernameFragment !== null && candidate.usernameFragment === remoteOfferUfrag
      ) ?? [],
      acceptedCandidateKeys: new Set(),
      acceptedCandidateUfrag: null,
      acceptedEndOfCandidates: false,
      queue: Promise.resolve(),
      queuedOperations: 0,
      descriptionRevision: 0,
      makingOffer: false,
      ignoreOffer: false,
      settingRemoteAnswer: false,
      ignoredRemoteUfrag: null,
      lastRemoteDescriptionKey: null,
      dataChannel: null,
      onDataChannelClose: null,
    };
    this.#peers.set(identityKey(identity), state);
    if (previous !== undefined) {
      previous.pendingCandidates.length = 0;
    }
    connection.onnegotiationneeded = () => {
      const revision = state.descriptionRevision;
      void this.#enqueue(state, async () => {
        // An explicit negotiation or incoming offer may satisfy this queued native event.
        if (state.descriptionRevision === revision && connection.signalingState === "stable") {
          await this.#negotiate(state);
        }
      }).catch(() => undefined);
    };
    connection.onicecandidate = (event) => {
      const localUfrag = iceUfrag(connection.localDescription?.sdp);
      state.markIceInitialized();
      void this.#enqueue(state, async () => {
        // EOC has no wire ufrag: never apply a rolled-back generation's completion to its answer.
        if (event.candidate === null && localUfrag !== iceUfrag(connection.localDescription?.sdp)) { return; }
        await this.#sendSignal(state, candidateSignal(event.candidate));
      }).catch(() => undefined);
    };
    connection.ondatachannel = (event) => {
      if (!this.#isCurrent(state)) {
        return;
      }
      event.channel.close();
      if (this.#isCurrent(state)) {
        this.#report(new Error("Rejected an unexpected in-band data channel"), state.identity);
      }
    };
    connection.onconnectionstatechange = () => {
      if (this.#isCurrent(state) && peerUnavailable(state)) {
        this.#retirePeer(state);
      }
    };

    try {
      const channel = connection.createDataChannel(DATA_CHANNEL_LABEL, {
        id: DATA_CHANNEL_ID,
        negotiated: true,
        ordered: true,
      });
      if (!this.#isCurrent(state)) {
        channel.close();
        return null;
      }
      if (!this.#acceptDataChannel(state, channel)) {
        throw new Error("Locally created data channel did not satisfy the transport profile");
      }
    } catch (cause) {
      this.#retirePeer(state);
      if (this.#peers.get(identityKey(state.identity)) === state) {
        this.#report(cause, state.identity);
      }
      throw cause;
    }
    return this.#isCurrent(state) ? state : null;
  }

  #replacePeer(
    peer: PeerState,
    remoteSession: RemoteSession | null = null,
    remoteOfferUfrag: string | null = null,
  ): PeerState | null {
    this.#retirePeer(peer);
    // Retirement observers may close the mesh or synchronously install another peer.
    if (
      (this.#lifecycle !== "starting" && this.#lifecycle !== "started") ||
      this.#peers.get(identityKey(peer.identity)) !== peer
    ) {
      return null;
    }
    return this.#createPeer(peer.identity, peer, remoteSession, remoteOfferUfrag);
  }

  async #negotiate(peer: PeerState): Promise<void> {
    if (!this.#isCurrent(peer)) {
      return;
    }
    if (
      peer.connection.signalingState === "have-local-offer" &&
      peer.connection.localDescription?.type === "offer"
    ) {
      await this.#sendSignal(
        peer,
        descriptionSignal(peer.connection.localDescription),
      );
      return;
    }
    peer.makingOffer = true;
    try {
      await peer.connection.setLocalDescription();
      if (!this.#isCurrent(peer)) {
        return;
      }
      peer.descriptionRevision += 1;
      const localDescription = peer.connection.localDescription;
      if (localDescription === null) {
        throw new Error("Peer connection produced no local description");
      }
      await this.#sendSignal(peer, descriptionSignal(localDescription));
    } finally {
      if (this.#isCurrent(peer)) {
        peer.makingOffer = false;
      }
    }
  }

  #receive(from: Uint8Array, payload: Uint8Array): void {
    if (this.#lifecycle !== "starting" && this.#lifecycle !== "started") {
      return;
    }
    let identity: IdentityPublicKey;
    try {
      identity = parseIdentityPublicKey(from);
    } catch (cause) {
      this.#report(cause, null);
      return;
    }
    const peer = this.#peers.get(identityKey(identity));
    if (peer === undefined) {
      if (this.#membership === "lobby" && this.#onUnknownPeer !== undefined &&
          !this.#rosterKeys.has(identityKey(identity)) && compareIdentities(identity, this.#self) !== 0) {
        try {
          const signal = decodePeerSignal(payload);
          if (signal.kind !== "description" || signal.descriptionType !== "offer") { return; }
          if (this.#lifecycle === "starting") {
            if (this.#earlySignals.length < this.#maxQueuedPeerOperations) { this.#earlySignals.push({ identity, signal }); }
            return;
          }
          if (this.#rosterKeys.size >= 8 || this.#onUnknownPeer(parseIdentityPublicKey(identity)) !== true) { return; }
          if (this.#lifecycle !== "started") { return; }
          const admitted = this.#admit(identity);
          if (admitted !== null) { this.#submitSignal(admitted, signal); }
        } catch (cause) { this.#report(cause, identity); }
        return;
      }
      if (
        this.#lifecycle === "starting" &&
        this.#rosterKeys.has(identityKey(identity)) &&
        compareIdentities(identity, this.#self) !== 0
      ) {
        if (this.#earlySignals.length >= this.#maxQueuedPeerOperations) {
          this.#report(new Error("Early signaling queue limit exceeded"), identity);
          return;
        }
        try {
          this.#earlySignals.push({
            identity: parseIdentityPublicKey(identity),
            signal: decodePeerSignal(payload),
          });
        } catch (cause) {
          this.#report(cause, identity);
        }
        return;
      }
      this.#report(new Error("Received signaling from an identity outside the roster"), identity);
      return;
    }
    let signal: PeerSignal;
    try {
      signal = decodePeerSignal(payload);
    } catch (cause) {
      this.#report(cause, identity);
      return;
    }
    this.#submitSignal(peer, signal);
  }

  #submitSignal(peer: PeerState, signal: PeerSignal): void {
    try {
      const target = this.#peerForSignal(peer, signal);
      if (target !== null) {
        if (
          signal.kind === "candidate" &&
          (target.retired || isPreOfferCandidate(target, signal))
        ) {
          // Admit before queueing: an earlier WebRTC operation may be stalled forever.
          this.#bufferCandidate(target, signal);
          return;
        }
        void this.#enqueue(target, () => this.#handleSignal(target, signal)).catch(() => undefined);
      }
    } catch (cause) {
      if (this.#peers.get(identityKey(peer.identity)) === peer) {
        this.#report(cause, peer.identity);
      }
    }
  }

  #peerForSignal(peer: PeerState, signal: PeerSignal): PeerState | null {
    if (
      (this.#lifecycle !== "starting" && this.#lifecycle !== "started") ||
      !this.#rosterKeys.has(identityKey(peer.identity)) ||
      this.#peers.get(identityKey(peer.identity)) !== peer
    ) {
      return null;
    }
    if (!peer.retired && peerUnavailable(peer)) {
      this.#retirePeer(peer);
      if (this.#peers.get(identityKey(peer.identity)) !== peer) {
        return null;
      }
    }
    if (signal.kind === "description") {
      const session = remoteSessionFromSdp(signal.sdp);
      // A certificate may be reused across distinct SDP origins (and vice versa).
      if (peer.retiredRemoteSessions.some((retired) =>
        !remoteSessionChanged(retired, session) &&
        ((session.origin !== null && retired.origin === session.origin) ||
          (session.fingerprint !== null && retired.fingerprint === session.fingerprint))
      )) {
        return null;
      }
      if (
        signal.descriptionType === "offer" &&
        (peer.retired ||
          (peer.remoteSession !== null && remoteSessionChanged(peer.remoteSession, session)))
      ) {
        // Do not wait for old WebRTC operations, which may never settle after close().
        return this.#replacePeer(peer, session, iceUfrag(signal.sdp));
      }
    }
    return this.#isCurrent(peer) || (peer.retired && signal.kind === "candidate") ? peer : null;
  }

  async #handleSignal(peer: PeerState, signal: PeerSignal): Promise<void> {
    // Earlier queued descriptions may have taught us a remote session since receipt.
    const target = this.#peerForSignal(peer, signal);
    if (target === null || target.retired) {
      return;
    }
    if (target !== peer) {
      await this.#enqueue(target, () => this.#handleSignal(target, signal));
      return;
    }
    if (signal.kind === "candidate") {
      await this.#handleCandidate(peer, signal);
      return;
    }
    await this.#handleDescription(peer, signal);
  }

  async #handleDescription(peer: PeerState, signal: DescriptionSignal): Promise<void> {
    const session = remoteSessionFromSdp(signal.sdp);
    const accepted = remoteSessionFromSdp(peer.connection.remoteDescription?.sdp ?? "");
    // A rolled-back offer can arrive after its newer answer, even if never seen in glare.
    if (session.origin !== null && session.origin === accepted.origin &&
        !remoteSessionChanged(accepted, session) &&
        session.version !== null && accepted.version !== null && session.version < accepted.version) {
      return;
    }
    const remoteSession = {
      origin: session.origin ?? peer.remoteSession?.origin ?? null,
      version: session.version,
      fingerprint: session.fingerprint ?? peer.remoteSession?.fingerprint ?? null,
    };
    const nextUfrag = iceUfrag(signal.sdp);
    // Gathering changes SDP text (including candidates/ports), not its origin/version.
    const remoteDescriptionKey = `${signal.descriptionType}\u0000${
      session.origin === null ? signal.sdp : `${session.origin} ${session.version} ${session.fingerprint}`
    }`;
    if (peer.lastRemoteDescriptionKey === remoteDescriptionKey) {
      if (
        signal.descriptionType === "offer" &&
        peer.connection.localDescription?.type === "answer"
      ) {
        await this.#sendSignal(
          peer,
          descriptionSignal(peer.connection.localDescription),
        );
      }
      return;
    }
    if (signal.descriptionType === "answer" && peer.connection.signalingState !== "have-local-offer") {
      // No pending offer can consume this answer; do not commit its session or ICE metadata.
      return;
    }
    const readyForOffer =
      !peer.makingOffer &&
      (peer.connection.signalingState === "stable" || peer.settingRemoteAnswer);
    const offerCollision = signal.descriptionType === "offer" && !readyForOffer;
    peer.ignoreOffer = peer.role === "impolite" && offerCollision;
    if (peer.ignoreOffer) {
      const ignoredUfrag = iceUfrag(signal.sdp);
      peer.ignoredRemoteUfrag = ignoredUfrag;
      if (ignoredUfrag !== null) {
        removePendingCandidateGeneration(peer, ignoredUfrag);
      }
      if (
        peer.connection.localDescription?.type === "offer"
      ) {
        await this.#sendSignal(
          peer,
          descriptionSignal(peer.connection.localDescription),
        );
      }
      return;
    }

    if (signal.descriptionType === "offer") {
      // Track only actionable in-flight offers so a new session can replace stalled SDP.
      peer.remoteSession = remoteSession;
      peer.remoteUfrag = nextUfrag;
    }
    peer.settingRemoteAnswer = signal.descriptionType === "answer";
    try {
      if (offerCollision && peer.connection.signalingState === "have-local-offer" &&
          peer.connection.remoteDescription === null && peer.connection.iceGatheringState !== "complete") {
        // Chromium can lose its first network update if initial gathering is rolled back too soon.
        // A candidate or completed gathering proves that this PC's network manager initialized.
        await peer.iceInitialized;
        if (!this.#isCurrent(peer)) { return; }
      }
      await peer.connection.setRemoteDescription({
        type: signal.descriptionType,
        sdp: signal.sdp,
      });
      if (!this.#isCurrent(peer)) {
        return;
      }
      peer.descriptionRevision += 1;
      peer.remoteSession = remoteSession;
      peer.remoteUfrag = nextUfrag;
      peer.lastRemoteDescriptionKey = remoteDescriptionKey;
      peer.ignoredRemoteUfrag = null;
      if (nextUfrag !== peer.acceptedCandidateUfrag) {
        peer.acceptedCandidateKeys.clear();
        peer.acceptedEndOfCandidates = false;
        peer.acceptedCandidateUfrag = nextUfrag;
      }
    } finally {
      if (this.#isCurrent(peer)) {
        peer.settingRemoteAnswer = false;
      }
    }
    peer.ignoreOffer = false;
    await this.#flushCandidates(peer);
    if (!this.#isCurrent(peer)) {
      return;
    }
    if (signal.descriptionType === "offer") {
      await peer.connection.setLocalDescription();
      if (!this.#isCurrent(peer)) {
        return;
      }
      peer.descriptionRevision += 1;
      const localDescription = peer.connection.localDescription;
      if (localDescription === null) {
        throw new Error("Peer connection produced no answer");
      }
      await this.#sendSignal(peer, descriptionSignal(localDescription));
    }
  }

  async #handleCandidate(peer: PeerState, signal: CandidateSignal): Promise<void> {
    if (
      peer.ignoreOffer &&
      (signal.usernameFragment === null ||
        signal.usernameFragment === peer.ignoredRemoteUfrag)
    ) {
      return;
    }
    const key = candidateKey(signal);
    if (
      (key === null ? peer.acceptedEndOfCandidates : peer.acceptedCandidateKeys.has(key)) ||
      peer.pendingCandidates.some((candidate) => candidateKey(candidate) === key)
    ) {
      return;
    }
    const activeUfrag = iceUfrag(peer.connection.remoteDescription?.sdp);
    if (
      peer.connection.remoteDescription === null ||
      (signal.usernameFragment !== null &&
        activeUfrag !== null &&
        signal.usernameFragment !== activeUfrag)
    ) {
      this.#bufferCandidate(peer, signal);
      return;
    }
    if (key !== null && peer.acceptedCandidateKeys.size >= this.#maxAcceptedIceCandidates) {
      throw new Error("Accepted ICE candidate limit exceeded");
    }
    await peer.connection.addIceCandidate(candidateSignalInit(signal));
    if (!this.#isCurrent(peer)) {
      return;
    }
    if (key === null) {
      peer.acceptedEndOfCandidates = true;
    } else {
      peer.acceptedCandidateKeys.add(key);
    }
  }

  #bufferCandidate(peer: PeerState, signal: CandidateSignal): void {
    if (peer.retired && !isPreOfferCandidate(peer, signal)) {
      return;
    }
    const key = candidateKey(signal);
    if (
      (key === null ? peer.acceptedEndOfCandidates : peer.acceptedCandidateKeys.has(key)) ||
      peer.pendingCandidates.some((candidate) => candidateKey(candidate) === key)
    ) {
      return;
    }
    if (peer.pendingCandidates.length >= this.#maxPendingIceCandidates) {
      throw new Error("Pending ICE candidate limit exceeded");
    }
    peer.pendingCandidates.push(signal);
  }

  async #flushCandidates(peer: PeerState): Promise<void> {
    const activeUfrag = iceUfrag(peer.connection.remoteDescription?.sdp);
    // Leave entries visible and counted until consumed, including while addIceCandidate awaits.
    for (let index = 0; index < peer.pendingCandidates.length;) {
      if (!this.#isCurrent(peer)) {
        return;
      }
      const signal = peer.pendingCandidates[index]!;
      if (
        signal.usernameFragment !== null &&
        activeUfrag !== null &&
        signal.usernameFragment !== activeUfrag
      ) {
        index += 1;
        continue;
      }
      const key = candidateKey(signal);
      if (key === null ? peer.acceptedEndOfCandidates : peer.acceptedCandidateKeys.has(key)) {
        peer.pendingCandidates.splice(index, 1);
        continue;
      }
      if (key !== null && peer.acceptedCandidateKeys.size >= this.#maxAcceptedIceCandidates) {
        peer.pendingCandidates.splice(index, 1);
        throw new Error("Accepted ICE candidate limit exceeded");
      }
      try {
        await peer.connection.addIceCandidate(candidateSignalInit(signal));
        if (!this.#isCurrent(peer)) {
          return;
        }
        if (key === null) {
          peer.acceptedEndOfCandidates = true;
        } else {
          peer.acceptedCandidateKeys.add(key);
        }
      } finally {
        if (this.#isCurrent(peer)) {
          peer.pendingCandidates.splice(index, 1);
        }
      }
    }
  }

  async #sendSignal(peer: PeerState, signal: PeerSignal): Promise<void> {
    if (this.#isCurrent(peer)) {
      await this.#signaling.send(parseIdentityPublicKey(peer.identity), encodePeerSignal(signal));
    }
  }

  #acceptDataChannel(peer: PeerState, channel: RTCDataChannel): boolean {
    if (
      channel.label !== DATA_CHANNEL_LABEL ||
      !channel.ordered ||
      !channel.negotiated ||
      channel.id !== DATA_CHANNEL_ID ||
      channel.maxPacketLifeTime !== null ||
      channel.maxRetransmits !== null
    ) {
      channel.close();
      if (this.#isCurrent(peer)) {
        this.#report(new Error("Rejected a non-profile data channel"), peer.identity);
      }
      return false;
    }
    if (peer.dataChannel !== null && peer.dataChannel !== channel) {
      channel.close();
      if (this.#isCurrent(peer)) {
        this.#report(new Error("Rejected a duplicate data channel"), peer.identity);
      }
      return false;
    }
    peer.dataChannel = channel;
    peer.onDataChannelClose = () => {
      if (this.#isCurrent(peer)) {
        this.#retirePeer(peer);
      }
    };
    channel.addEventListener("close", peer.onDataChannelClose);
    if (peerUnavailable(peer)) {
      this.#retirePeer(peer);
      return true;
    }
    try {
      this.#onUnauthenticatedDataChannel?.(
        parseIdentityPublicKey(peer.identity),
        channel,
        peer.generation,
      );
    } catch (cause) {
      if (this.#isCurrent(peer)) {
        this.#report(cause, peer.identity);
      }
    }
    return true;
  }

  async #enqueue(peer: PeerState, operation: () => Promise<void>): Promise<void> {
    if (!this.#isCurrent(peer)) {
      return;
    }
    if (peer.queuedOperations >= this.#maxQueuedPeerOperations) {
      const error = new Error("Queued peer operation limit exceeded");
      this.#report(error, peer.identity);
      throw error;
    }
    peer.queuedOperations += 1;
    const run = peer.queue.then(async () => {
      if (!this.#isCurrent(peer)) {
        return;
      }
      const cancelled = new Promise<void>((resolve) => { peer.cancelOperation = resolve; });
      try {
        await Promise.race([operation(), cancelled]);
      } catch (cause) {
        if (this.#isCurrent(peer)) {
          throw cause;
        }
      } finally {
        peer.cancelOperation = null;
      }
    });
    peer.queue = run.then(
      () => {
        peer.queuedOperations -= 1;
      },
      (cause: unknown) => {
        peer.queuedOperations -= 1;
        if (this.#isCurrent(peer)) {
          this.#report(cause, peer.identity);
        }
      },
    );
    await run;
  }

  #requirePeer(remote: Uint8Array, allowRetired = false): PeerState {
    this.#requireActive();
    const identity = parseIdentityPublicKey(remote);
    const peer = this.#peers.get(identityKey(identity));
    if (peer === undefined || !this.#rosterKeys.has(identityKey(identity))) {
      throw new Error("Identity is not a remote peer in this mesh");
    }
    if (peer.retired && !allowRetired) {
      throw new Error("Peer connection is retired");
    }
    return peer;
  }

  #isCurrent(peer: PeerState): boolean {
    return !peer.retired &&
      this.#rosterKeys.has(identityKey(peer.identity)) &&
      (this.#lifecycle === "starting" || this.#lifecycle === "started") &&
      this.#peers.get(identityKey(peer.identity)) === peer;
  }

  #requireActive(): void {
    if (this.#lifecycle !== "starting" && this.#lifecycle !== "started") {
      throw new Error("Full-mesh transport is not active");
    }
  }

  #report(cause: unknown, remote: IdentityPublicKey | null): void {
    const error = asError(cause, "Full-mesh transport operation failed");
    const remoteSnapshot = remote === null ? null : parseIdentityPublicKey(remote);
    this.#retainFailure(error, remoteSnapshot);
    try {
      this.#onError?.(error, remoteSnapshot);
    } catch (observerCause) {
      this.#retainFailure(
        asError(observerCause, "Full-mesh error observer failed"),
        remoteSnapshot,
      );
    }
  }

  #retainFailure(error: Error, remote: IdentityPublicKey | null): void {
    if (this.#failures.length >= this.#maxRetainedFailures) {
      this.#failures.shift();
    }
    this.#failures.push(Object.freeze({ error, remote }));
  }

  #retirePeer(peer: PeerState): void {
    if (peer.retired || this.#peers.get(identityKey(peer.identity)) !== peer) {
      return;
    }
    // Revoke the generation before calling observers or closing native objects.
    peer.retired = true;
    peer.markIceInitialized();
    peer.cancelOperation?.();
    peer.cancelOperation = null;
    if (peer.remoteSession !== null) {
      peer.retiredRemoteSessions.push(peer.remoteSession);
      if (peer.retiredRemoteSessions.length > MAX_RETIRED_REMOTE_SESSIONS) {
        peer.retiredRemoteSessions.shift();
      }
    }
    const channel = peer.dataChannel;
    peer.dataChannel = null;
    peer.connection.onnegotiationneeded = null;
    peer.connection.onicecandidate = null;
    peer.connection.ondatachannel = null;
    peer.connection.onconnectionstatechange = null;
    if (peer.onDataChannelClose !== null) {
      channel?.removeEventListener("close", peer.onDataChannelClose);
      peer.onDataChannelClose = null;
    }
    const preOfferCandidates = peer.pendingCandidates.filter((candidate) =>
      isPreOfferCandidate(peer, candidate)
    );
    peer.pendingCandidates.splice(0, peer.pendingCandidates.length, ...preOfferCandidates);
    peer.acceptedCandidateKeys.clear();
    peer.lastRemoteDescriptionKey = null;
    for (const action of [
      () => this.#onPeerDisconnected?.(parseIdentityPublicKey(peer.identity), peer.generation),
      () => channel?.close(),
      () => peer.connection.close(),
    ]) {
      try {
        action();
      } catch (cause) {
        if (this.#peers.get(identityKey(peer.identity)) === peer) {
          this.#report(cause, peer.identity);
        } else {
          this.#retainFailure(asError(cause, "Peer retirement failed"), parseIdentityPublicKey(peer.identity));
        }
      }
    }
  }

  #closePeers(): void {
    for (const peer of this.#peers.values()) {
      this.#retirePeer(peer);
      peer.pendingCandidates.length = 0;
    }
    this.#peers.clear();
    this.#earlySignals.length = 0;
  }
}

export function inspectIceConnectionPath(
  report: RTCStatsReport,
): IceConnectionPathDiagnostics {
  if (report === null || typeof report !== "object" || typeof report.forEach !== "function") {
    throw new TypeError("ICE path inspection requires an RTCStatsReport");
  }
  const records = new Map<string, Record<string, unknown>>();
  report.forEach((candidate: unknown) => {
    if (isStatsRecord(candidate) && typeof candidate["id"] === "string") {
      records.set(candidate["id"], candidate);
    }
  });
  const selectedPair = findSelectedCandidatePair(records);
  if (selectedPair === null) {
    return icePathDiagnostics(null, null, null);
  }
  const localCandidate = recordById(records, selectedPair["localCandidateId"]);
  const remoteCandidate = recordById(records, selectedPair["remoteCandidateId"]);
  return icePathDiagnostics(
    typeof selectedPair["id"] === "string" ? selectedPair["id"] : null,
    candidateType(localCandidate),
    candidateType(remoteCandidate),
  );
}

function findSelectedCandidatePair(
  records: ReadonlyMap<string, Record<string, unknown>>,
): Record<string, unknown> | null {
  const transports = [...records.values()]
    .filter((record) => record["type"] === "transport")
    .sort(compareStatsIds);
  for (const transport of transports) {
    const selected = recordById(records, transport["selectedCandidatePairId"]);
    if (selected?.["type"] === "candidate-pair") {
      return selected;
    }
  }
  const candidatePairs = [...records.values()]
    .filter(
      (record) =>
        record["type"] === "candidate-pair" && record["state"] === "succeeded",
    )
    .sort(compareStatsIds);
  const selected = candidatePairs.filter((record) => record["selected"] === true);
  if (selected.length !== 0) {
    return selected.length === 1 ? selected[0] ?? null : null;
  }
  const nominated = candidatePairs.filter((record) => record["nominated"] === true);
  return nominated.length === 1 ? nominated[0] ?? null : null;
}

function recordById(
  records: ReadonlyMap<string, Record<string, unknown>>,
  id: unknown,
): Record<string, unknown> | null {
  return typeof id === "string" ? records.get(id) ?? null : null;
}

function candidateType(record: Record<string, unknown> | null): RTCIceCandidateType | null {
  const value = record?.["candidateType"];
  return value === "host" || value === "srflx" || value === "prflx" || value === "relay"
    ? value
    : null;
}

function icePathDiagnostics(
  selectedCandidatePairId: string | null,
  localCandidateType: RTCIceCandidateType | null,
  remoteCandidateType: RTCIceCandidateType | null,
): IceConnectionPathDiagnostics {
  const path: IceConnectionPath =
    localCandidateType === "relay" || remoteCandidateType === "relay"
      ? "relayed"
      : localCandidateType !== null && remoteCandidateType !== null
        ? "direct"
        : "unknown";
  return Object.freeze({
    path,
    selectedCandidatePairId,
    localCandidateType,
    remoteCandidateType,
  });
}

function compareStatsIds(
  left: Record<string, unknown>,
  right: Record<string, unknown>,
): number {
  return String(left["id"] ?? "").localeCompare(String(right["id"] ?? ""));
}

function isStatsRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const defaultPeerConnectionFactory: MeshPeerConnectionFactory = (_remote, configuration) => {
  if (typeof RTCPeerConnection === "undefined") {
    throw new Error("RTCPeerConnection is unavailable in this environment");
  }
  return new RTCPeerConnection(configuration);
};

function normalizeRoster(
  candidates: readonly Uint8Array[],
  self: IdentityPublicKey,
  minimum: number,
): readonly IdentityPublicKey[] {
  if (!Array.isArray(candidates) || candidates.length < minimum || candidates.length > 8) {
    throw new RangeError(`Full-mesh roster must contain between ${minimum} and 8 identities`);
  }
  const seen = new Set<string>();
  let containsSelf = false;
  const roster = candidates.map((candidate) => {
    const identity = parseIdentityPublicKey(candidate);
    const key = identityKey(identity);
    if (seen.has(key)) {
      throw new Error("Full-mesh roster contains a duplicate identity");
    }
    seen.add(key);
    if (compareIdentities(identity, self) === 0) {
      containsSelf = true;
    }
    return identity;
  });
  if (!containsSelf) {
    throw new Error("Full-mesh roster does not contain the local identity");
  }
  return Object.freeze(roster);
}

function normalizeRtcConfiguration(
  configuration: RTCConfiguration | undefined,
): RTCConfiguration {
  const selected = configuration ?? {
    iceServers: [{ urls: [...DEFAULT_STUN_URLS] }],
    iceTransportPolicy: "all",
    bundlePolicy: "max-bundle",
  };
  const snapshot = cloneRtcConfiguration(selected);
  const urls = (snapshot.iceServers ?? []).flatMap((server) =>
    Array.isArray(server.urls) ? server.urls : [server.urls],
  );
  if (!urls.some((url) => /^stuns?:/i.test(url))) {
    throw new Error("RTC configuration must include at least one STUN server");
  }
  snapshot.iceTransportPolicy ??= "all";
  snapshot.bundlePolicy ??= "max-bundle";
  return snapshot;
}

function cloneRtcConfiguration(configuration: RTCConfiguration): RTCConfiguration {
  const snapshot: RTCConfiguration = { ...configuration };
  if (configuration.iceServers !== undefined) {
    snapshot.iceServers = configuration.iceServers.map((server) => ({
      ...server,
      urls: Array.isArray(server.urls) ? [...server.urls] : server.urls,
    }));
  }
  return snapshot;
}

function candidateKey(signal: CandidateSignal): string | null {
  if (signal.candidate === null) {
    return null;
  }
  return `candidate:${JSON.stringify([
    signal.candidate,
    signal.sdpMid,
    signal.sdpMLineIndex,
    signal.usernameFragment,
  ])}`;
}

function isPreOfferCandidate(peer: PeerState, signal: CandidateSignal): boolean {
  return signal.usernameFragment !== null &&
    signal.usernameFragment !== peer.remoteUfrag &&
    signal.usernameFragment !== peer.acceptedCandidateUfrag &&
    signal.usernameFragment !== peer.ignoredRemoteUfrag;
}

function iceUfrag(sdp: string | undefined): string | null {
  if (sdp === undefined) {
    return null;
  }
  const match = /(?:^|\r?\n)a=ice-ufrag:([^\r\n]+)/.exec(sdp);
  return match?.[1] ?? null;
}

function peerUnavailable(peer: PeerState): boolean {
  return peer.connection.connectionState === "disconnected" ||
    peer.connection.connectionState === "failed" ||
    peer.connection.connectionState === "closed" ||
    peer.connection.signalingState === "closed" ||
    peer.dataChannel?.readyState === "closing" ||
    peer.dataChannel?.readyState === "closed";
}

function remoteSessionFromSdp(sdp: string): RemoteSession {
  const origins = sdp.split(/\r?\n/).filter((line) => line.startsWith("o="));
  const match = origins.length === 1
    ? /^o=\S+[ \t]+([0-9]{1,20})[ \t]+([0-9]{1,20})[ \t]+IN[ \t]+IP[46][ \t]+\S+$/.exec(origins[0]!)
    : null;
  let fingerprint: string | null = null;
  try {
    fingerprint = identityKey(sha256FingerprintFromSdp(sdp));
  } catch {
    // Invalid/missing fingerprints are not restart evidence; WebRTC/HELLO validate SDP.
  }
  return {
    origin: match?.[1]?.replace(/^0+(?=\d)/, "") ?? null,
    version: match?.[2] === undefined ? null : BigInt(match[2]),
    fingerprint,
  };
}

function remoteSessionChanged(previous: RemoteSession, next: RemoteSession): boolean {
  // Session versions and ICE restarts are renegotiations, not new peer connections.
  return (previous.origin !== null && next.origin !== null && previous.origin !== next.origin) ||
    (previous.fingerprint !== null && next.fingerprint !== null &&
      previous.fingerprint !== next.fingerprint);
}

function removePendingCandidateGeneration(peer: PeerState, usernameFragment: string): void {
  const retained = peer.pendingCandidates.filter(
    (candidate) => candidate.usernameFragment !== usernameFragment,
  );
  peer.pendingCandidates.splice(0, peer.pendingCandidates.length, ...retained);
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
