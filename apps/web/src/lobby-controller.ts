import { LiveRound } from "./live-round";
import { HistorySync } from "./history-sync";
import { TableAbortVote } from "./table-abort";
import type { SaskuActionIntent } from "@p2pcards/game-sasku";
import { bytesEqual, bytesToHex, hexToBytes, importEd25519PublicKey, randomBytes, type Ed25519KeyPair } from "@p2pcards/crypto";
import {
  CHANNEL_CONTROL_PREFIX, MAX_GAME_ENVELOPE_BYTES, MAX_HISTORY_ENVELOPE_BYTES, decodeChannelControl, encodeChannelControl,
  decodeAndVerifyEnvelope, decodeJoinBody, decodeRosterBody, decodeReadyBody, deriveSignalingRoomId,
  encodeJoinBody, encodeReadyBody, encodeRosterBody, parseGameId, parseIdentityPublicKey,
  type ChannelControl, type EnvelopeArtifact, type IdentityPublicKey,
} from "@p2pcards/protocol";
import { LobbyChainRegistry, PersistentEnvelopeAuthor, PersistentLobbyReceiver, recoverLobby, type ChainHead, type EnvelopeContent } from "@p2pcards/session";
import { IndexedDbAuthoredEnvelopeStore, IndexedDbIdentityStore, IndexedDbSessionStore, type IndexedDbStoreOptions } from "@p2pcards/storage";
import { TrysteroNostrSignalingAdapter, type MeshPeerConnectionFactory } from "@p2pcards/transport";

import { browserIceDeployment, loadLobbyIce, type IceDeploymentConfig } from "./ice-config";
import { connectionRulesHash, lobbyIceConfigHash, parseRelayText } from "./lobby-config";
import { createLobbyInvitation, identityFingerprint, parseLobbyInvitation, type LobbyInvitation } from "./lobby-invitation";
import { LobbyTransport, type LobbyTransportLike, type LobbyTransportOptions } from "./lobby-transport";
import { parseRoundCompletionMarker, roundCompletionMarker, sameRoundCompletion } from "./round-completion-marker";
import type { BrowserLobbyActions, BrowserLobbySnapshot } from "./lobby-types";
import { exportTranscript } from "./transcript";

interface Room {
  readonly invitation: LobbyInvitation;
  readonly host: boolean;
  readonly stored: IndexedDbSessionStore;
  readonly authored: IndexedDbAuthoredEnvelopeStore;
  readonly author: PersistentEnvelopeAuthor;
  readonly abort: AbortController;
  readonly iceDeployment: IceDeploymentConfig | null;
  iceCredentialWarning: boolean;
  lobby: LobbyChainRegistry;
  receiver: PersistentLobbyReceiver;
  signaling: TrysteroNostrSignalingAdapter | null;
  transport: LobbyTransportLike | null;
  queue: Promise<void>;
  pending: number;
  blocked: boolean;
  recordCount: number;
  releaseLease: (() => void) | null;
  ownJoin: EnvelopeArtifact | null;
  headsTimer: ReturnType<typeof setInterval> | null;
  readonly votes: TableAbortVote;
  ended: number | null;
  game: LiveRound | null;
  playing: boolean;
  localReady: boolean;
  autoReadyRequested: boolean;
  readonly peerReady: Map<string, { generation: number; ready: boolean }>;
  readonly sync: Map<string, { generation: number; history: HistorySync }>;
  readonly roundCompletions: Map<string, Map<number, { generation: number; marker: Uint8Array }>>;
  readonly sentRoundCompletions: Map<string, Map<number, { generation: number; marker: Uint8Array }>>;
  readonly early: EnvelopeArtifact[];
  readonly restoredViolations: EnvelopeArtifact[];
  readonly lobbyPending: EnvelopeArtifact[];
  evidence: readonly [EnvelopeArtifact, EnvelopeArtifact] | null;
  readonly paths: Map<string, "direct" | "relayed" | "unknown">;
  readonly retryingPeers: Set<string>;
}

export interface BrowserLobbyControllerOptions {
  readonly baseUrl?: string;
  readonly initialInvitation?: string;
  readonly storage?: IndexedDbStoreOptions & { readonly keyRange?: Pick<typeof IDBKeyRange, "bound"> };
  readonly createPeerConnection?: MeshPeerConnectionFactory;
  readonly createTransport?: (options: Omit<LobbyTransportOptions, "signaling" | "createPeerConnection">) => LobbyTransportLike;
  readonly manageHistory?: boolean;
}

class LobbyProtocolError extends Error {}

export class BrowserLobbyController implements BrowserLobbyActions {
  readonly #listeners = new Set<() => void>();
  readonly #baseUrl: string;
  readonly #options: BrowserLobbyControllerOptions;
  #identityStore: IndexedDbIdentityStore | null = null;
  #identity: Ed25519KeyPair | null = null;
  #initializing: Promise<void> | null = null;
  #room: Room | null = null;
  #disposed = false;
  #epoch = 0;
  #snapshot: BrowserLobbySnapshot;

  constructor(options: BrowserLobbyControllerOptions = {}) {
    this.#options = options;
    this.#baseUrl = options.baseUrl ?? window.location.href;
    this.#snapshot = Object.freeze({
      phase: "loading", identity: null, pendingInvitation: options.initialInvitation ?? (new URL(this.#baseUrl).hash ? this.#baseUrl : ""),
      room: null, peers: [], relays: [], iceCredentialWarning: false, busy: "identity", error: null, events: [],
    });
  }

  readonly getSnapshot = (): BrowserLobbySnapshot => this.#snapshot;
  readonly subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener);
    return () => { this.#listeners.delete(listener); };
  };

  initialize(): Promise<void> {
    if (this.#identity !== null) { return Promise.resolve(); }
    if (this.#initializing !== null) { return this.#initializing; }
    this.#initializing = (async () => {
      try {
        if (this.#disposed) { return; }
        this.#identityStore ??= new IndexedDbIdentityStore(this.#options.storage);
        const identity = await this.#identityStore.getOrCreateIdentity();
        if (this.#disposed) { return; }
        this.#identity = identity;
        this.#set({ phase: "welcome", busy: null, identity: Object.freeze({ publicKey: bytesToHex(identity.publicKey), fingerprint: identityFingerprint(identity.publicKey) }) });
      } catch (cause) {
        this.#set({ phase: "welcome", busy: null, error: message(cause) });
        throw cause;
      } finally { this.#initializing = null; }
    })();
    return this.#initializing;
  }

  async create(relayText = ""): Promise<void> {
    const epoch = this.#epoch;
    await this.initialize();
    if (epoch !== this.#epoch) { throw new Error("Lobby operation was cancelled"); }
    const self = this.#self();
    await this.#open({ gameId: parseGameId(randomBytes(16)), host: parseIdentityPublicKey(self.publicKey) }, relayText);
  }

  async join(invitation: string, relayText = ""): Promise<void> {
    const epoch = this.#epoch;
    try {
      const parsed = parseLobbyInvitation(invitation);
      await this.initialize();
      if (epoch !== this.#epoch) { throw new Error("Lobby operation was cancelled"); }
      await this.#open(parsed, relayText);
    } catch (cause) { if (this.#epoch === epoch && this.#room === null) { this.#set({ error: message(cause) }); } throw cause; }
  }

  async #open(invitation: LobbyInvitation, relayText: string): Promise<void> {
    if (this.#room !== null || this.#disposed || this.#snapshot.busy !== null) { throw new Error("Leave the current table before opening another"); }
    const epoch = ++this.#epoch;
    const self = this.#self();
    const host = bytesEqual(invitation.host, self.publicKey);
    this.#set({ busy: host ? "hosting" : "joining", phase: "connecting", error: null, events: [], relays: [] });
    let room: Room | null = null;
    try {
      const relayUrls = parseRelayText(relayText);
      const iceDeployment = this.#options.createTransport ? null : browserIceDeployment(this.#baseUrl);
      const stored = new IndexedDbSessionStore(this.#options.storage);
      const authored = new IndexedDbAuthoredEnvelopeStore(this.#options.storage);
      const context = { gameId: invitation.gameId, host: invitation.host, rulesHash: connectionRulesHash(), iceConfigHash: lobbyIceConfigHash() };
      const lobby = new LobbyChainRegistry(context);
      const ended = this.#readTableEnd(invitation.gameId, self.publicKey);
      room = {
        invitation, host, stored, authored, author: new PersistentEnvelopeAuthor(invitation.gameId, self.secretKey, authored),
        abort: new AbortController(), iceDeployment, iceCredentialWarning: false, lobby, receiver: new PersistentLobbyReceiver(lobby, stored),
        signaling: null, transport: null, queue: Promise.resolve(), pending: 0, blocked: false, recordCount: 0, releaseLease: null, ownJoin: null, headsTimer: null, votes: new TableAbortVote(), ended, paths: new Map(), retryingPeers: new Set(), game: null, playing: false, localReady: true, autoReadyRequested: false, peerReady: new Map(), sync: new Map(), roundCompletions: new Map(), sentRoundCompletions: new Map(), early: [], restoredViolations: [], lobbyPending: [], evidence: null,
      };
      this.#room = room;
      this.#refresh(room);
      await this.#lease(room);
      this.#require(room, epoch);
      const records = await stored.loadTranscript(invitation.gameId);
      this.#require(room, epoch);
      if (records.length > 4096 || records.some(({ artifact }) =>
        artifact.canonicalBytes.length > (artifact.envelope.type === "VIOLATION" ? MAX_HISTORY_ENVELOPE_BYTES : MAX_GAME_ENVELOPE_BYTES))) {
        throw new Error("Stored history exceeds this Sasku match profile; it will not be discarded automatically");
      }
      const lobbyRecords = records.filter(({ artifact }) => ["JOIN", "ROSTER", "READY"].includes(artifact.envelope.type));
      room.recordCount = lobbyRecords.length;
      const roster = await stored.loadLobbyRoster(invitation.gameId, invitation.host);
      this.#require(room, epoch);
      if (records.length !== 0) {
        const ownHead = await authored.readAuthoredHead(invitation.gameId, parseIdentityPublicKey(self.publicKey));
        this.#require(room, epoch);
        if (ownHead === null) { throw new Error("Saved table history has no checkpoint for this identity; it cannot be resumed automatically"); }
        const latestHostRoster = records.filter(({ artifact }) => artifact.envelope.type === "ROSTER" && bytesEqual(artifact.envelope.from, invitation.host))
          .sort((left, right) => left.artifact.envelope.seq - right.artifact.envelope.seq).at(-1);
        const repairLocalSnapshot = host && latestHostRoster?.authored === true &&
          (roster === null || roster.artifact.envelope.seq < latestHostRoster.artifact.envelope.seq);
        const recovered = recoverLobby(context, lobbyRecords.map(({ artifact }) => artifact), repairLocalSnapshot ? undefined : roster?.artifact);
        if (recovered.lobby.roster !== null && recovered.lobby.roster.seats.length > 4) {
          throw new Error("Saved roster exceeds this connection-check profile");
        }
        if (repairLocalSnapshot) {
          const repaired = await stored.persistAcceptedRoster(invitation.host, latestHostRoster!.artifact);
          this.#require(room, epoch);
          if (repaired.status !== "stored" && repaired.status !== "duplicate") {
            throw new Error("Local roster snapshot changed during recovery");
          }
        }
        room.ownJoin = lobbyRecords.find(({ artifact }) => artifact.envelope.type === "JOIN" && bytesEqual(artifact.envelope.from, self.publicKey))?.artifact ?? null;
        room.lobby = recovered.lobby;
        room.receiver = new PersistentLobbyReceiver(room.lobby, stored);
        const gameRecords = records.filter(({ artifact }) => !["JOIN", "ROSTER", "READY"].includes(artifact.envelope.type));
        if (gameRecords.length || room.ended !== null) {
          const session = room.lobby.finalizedRegistry;
          if (!session) throw new Error("Saved round has no finalized roster");
          for (const { artifact } of gameRecords.sort((a, b) => a.artifact.envelope.seq - b.artifact.envelope.seq)) {
            if (session.ingest(artifact).status !== "accepted") throw new Error("Saved round history is not contiguous");
            if (artifact.envelope.type === "VIOLATION") room.restoredViolations.push(artifact);
          }
          room.playing = true;
        }
      } else if (host) {
        await this.#publish(room, { round: 0, phase: "lobby", type: "ROSTER", body: encodeRosterBody({ ...context, seats: [parseIdentityPublicKey(self.publicKey)] }) });
      } else {
        room.ownJoin = await room.author.author({ round: 0, phase: "lobby", type: "JOIN", body: encodeJoinBody({ pkId: parseIdentityPublicKey(self.publicKey), rulesHash: context.rulesHash, clientVersion: "sasku-match-candidate/4" }) });
        room.recordCount += 1;
      }
      this.#require(room, epoch);
      if (this.#options.manageHistory !== false && typeof window !== "undefined") { window.history.replaceState(null, "", createLobbyInvitation(this.#baseUrl, invitation.gameId, invitation.host)); }
      if (room.lobby.state === "finalized") {
        this.#event("Saved agreement restored. Synchronizing signed history with the other players.");
      }
      const current = room;
      const ice = iceDeployment === null ? null : await loadLobbyIce(iceDeployment, current.abort.signal);
      this.#require(current, epoch);
      current.iceCredentialWarning = ice?.credentialWarning ?? false;
      const signaling = this.#options.createTransport ? null : new TrysteroNostrSignalingAdapter({
        ...(relayUrls === undefined ? {} : { relayUrls, relayRedundancy: relayUrls.length }),
        onRelayStateChange: () => { if (this.#room === current) { this.#refresh(current); } },
        onError: (error) => { if (this.#room === current) { this.#event(message(error)); } },
      });
      room.signaling = signaling;
      const initial = room.lobby.roster?.seats ?? (host ? [parseIdentityPublicKey(self.publicKey)] : [parseIdentityPublicKey(self.publicKey), invitation.host]);
      const members = initial.some((key) => bytesEqual(key, self.publicKey)) ? initial : [...initial, parseIdentityPublicKey(self.publicKey)];
      const transportOptions: Omit<LobbyTransportOptions, "signaling" | "createPeerConnection"> = {
        roomId: bytesToHex(deriveSignalingRoomId(invitation.gameId)), gameId: invitation.gameId,
        identity: self, roster: members,
        onUnknownPeer: (remote) => {
          try { importEd25519PublicKey(remote); } catch { return false; }
          return this.#room === current && current.host && !current.blocked && current.lobby.state !== "finalized" &&
            (current.lobby.roster?.seats.length ?? 1) < 4 && (current.transport?.peers.length ?? 0) < 3;
        },
        onAuthenticated: (remote, generation) => {
          if (this.#room !== current) { return; }
          current.sync.set(bytesToHex(remote), { generation, history: new HistorySync() });
          this.#sendHeads(current, remote, generation);
          this.#sendTableEnd(current, remote, generation);
          current.peerReady.delete(bytesToHex(remote));
          current.roundCompletions.delete(bytesToHex(remote));
          current.sentRoundCompletions.delete(bytesToHex(remote));
          this.#event(`Identity verified: ${identityFingerprint(remote)}`);
          void current.transport!.send(remote, generation, Uint8Array.of(1, current.localReady ? 1 : 0)).catch((cause: unknown) => {
            if (this.#room === current) this.#event(`Ready status delivery failed: ${message(cause)}`);
          });
          void current.transport!.path(remote).then((path) => {
            if (this.#room === current && current.transport?.generation(remote) === generation) {
              current.paths.set(bytesToHex(remote), path.path); this.#refresh(current);
            }
          }).catch(() => undefined);
        },
        onMessage: (remote, payload, generation) => this.#incoming(current, remote, payload, generation),
        onDisconnected: (remote) => {
          if (this.#room !== current) { return; }
          current.sync.delete(bytesToHex(remote));
          current.peerReady.delete(bytesToHex(remote));
          current.roundCompletions.delete(bytesToHex(remote));
          current.sentRoundCompletions.delete(bytesToHex(remote));
          current.paths.delete(bytesToHex(remote));
          if (!current.lobby.isRosterMember(remote)) { current.transport?.remove(remote); }
          this.#refresh(current);
        },
        onError: (error) => { if (this.#room === current) { this.#event(message(error)); this.#refresh(current); } },
        onChange: () => { if (this.#room === current) { this.#refresh(current); } },
      };
      room.transport = this.#options.createTransport ? this.#options.createTransport(transportOptions) : new LobbyTransport({
        ...transportOptions, signaling: signaling!, rtcConfiguration: ice!.rtcConfiguration,
        ...(this.#options.createPeerConnection === undefined ? {} : { createPeerConnection: this.#options.createPeerConnection }),
      });
      await room.transport.start();
      this.#require(room, epoch);
      room.headsTimer = setInterval(() => this.#broadcastHeads(current), 5_000);
      this.#event(host ? "Table opened. Share the invitation with three other identities." : "Joining the host; waiting for a signed roster.");
      this.#set({ busy: null }); this.#refresh(room);
    } catch (cause) {
      if (this.#epoch === epoch) {
        const relays = relayViews(room?.signaling);
        await this.#closeRoom(room);
        this.#set({ phase: "welcome", busy: null, room: null, peers: [], relays, iceCredentialWarning: false, error: message(cause) });
      }
      throw cause;
    }
  }

  async #incoming(room: Room, remote: IdentityPublicKey, payload: Uint8Array, generation: number): Promise<void> {
    if (this.#room !== room || room.transport?.generation(remote) !== generation) return;
    if (payload[0] === CHANNEL_CONTROL_PREFIX) {
      const control = decodeChannelControl(payload);
      return this.#enqueue(room, async () => {
        if (room.transport?.generation(remote) === generation) await this.#control(room, remote, generation, control);
      });
    }
    if (payload[0] === 1) {
      if (payload.length !== 2 || (payload[1] !== 0 && payload[1] !== 1)) throw new LobbyProtocolError("Invalid ready status");
      room.peerReady.set(bytesToHex(remote), { generation, ready: payload[1] === 1 });
      this.#refresh(room); return;
    }
    if (payload[0] === 2) {
      const marker = parseRoundCompletionMarker(payload), key = bytesToHex(remote);
      const byRound = room.roundCompletions.get(key) ?? new Map();
      const previous = byRound.get(marker[1]!);
      if (previous?.generation === generation && !sameRoundCompletion(previous.marker, marker)) {
        throw new LobbyProtocolError("Peer changed its verified round result");
      }
      byRound.set(marker[1]!, { generation, marker });
      room.roundCompletions.set(key, byRound);
      this.#refresh(room); return;
    }
    if (payload.length > MAX_HISTORY_ENVELOPE_BYTES) throw new LobbyProtocolError("Envelope exceeds history size limit");
    const artifact = decodeAndVerifyEnvelope(payload);
    if (!bytesEqual(artifact.envelope.from, remote)) throw new LobbyProtocolError("Wrong authenticated sender");
    return this.#enqueue(room, async () => {
      if (room.transport?.generation(remote) !== generation) return;
      await this.#acceptArtifact(room, remote, artifact);
      this.#refresh(room);
    });
  }

  async #acceptArtifact(room: Room, source: IdentityPublicKey, artifact: EnvelopeArtifact): Promise<void> {
    const { from, game, seq, phase, round, type, body } = artifact.envelope;
    if (!bytesEqual(game, room.invitation.gameId) || !this.#allowedAuthor(room, source, from)) {
      throw new LobbyProtocolError("Signed history is outside this table");
    }
    const existing = this.#get(room, from, seq);
    if (existing) {
      if (!bytesEqual(existing.hash, artifact.hash)) this.#reportEquivocation(room, existing, artifact);
      return;
    }
    if (!["JOIN", "ROSTER", "READY"].includes(type)) {
      if (!room.lobby.isRosterMember(from)) throw new LobbyProtocolError("Round author is outside the roster");
      if (!["KEY_SHARE", "SHUFFLE", "SHARES", "ACTION", "AUDIT_DISCLOSE", "VIOLATION"].includes(type)) {
        throw new LobbyProtocolError("Unsupported match envelope");
      }
      if (room.game) {
        try { room.game.receiveHistory(artifact); }
        catch (cause) { throw new LobbyProtocolError(message(cause)); }
      }
      else {
        if (room.early.length >= 32) throw new LobbyProtocolError("Early round queue is full");
        room.early.push(artifact);
      }
      if (!room.playing && bytesEqual(from, room.invitation.host) && type === "KEY_SHARE") room.playing = true;
      return;
    }
    if (artifact.canonicalBytes.length > 4096 || round !== 0 || phase !== "lobby") {
      throw new LobbyProtocolError("Invalid lobby envelope scope or size");
    }
    try {
      if (type === "JOIN") decodeJoinBody(body);
      if (type === "ROSTER") decodeRosterBody(body);
      if (type === "READY") decodeReadyBody(body);
    } catch (cause) { throw new LobbyProtocolError(message(cause)); }
    if (room.lobbyPending.some(item => bytesEqual(item.hash, artifact.hash))) return;
    if (room.lobbyPending.length >= 32) throw new LobbyProtocolError("Lobby history queue is full");
    room.lobbyPending.push(artifact);
    while (true) {
      const index = room.lobbyPending.findIndex(({ envelope }) => {
        const head = room.lobby.headOf(envelope.from);
        return envelope.seq <= (head?.seq ?? -1) + 1 &&
          (envelope.type !== "READY" || room.lobby.roster?.seats.length === 4);
      });
      if (index < 0) return;
      await this.#acceptLobbyArtifact(room, room.lobbyPending.splice(index, 1)[0]!);
    }
  }

  async #acceptLobbyArtifact(room: Room, artifact: EnvelopeArtifact): Promise<void> {
    const remote = artifact.envelope.from;
    const existing = room.lobby.get(remote, artifact.envelope.seq);
    if (existing) {
      if (!bytesEqual(existing.hash, artifact.hash)) this.#reportEquivocation(room, existing, artifact);
      return;
    }
    if (room.recordCount >= 128) { throw new LobbyProtocolError("Connection-check history limit reached; open a new table"); }
    const envelope = artifact.envelope;
    if (envelope.type === "JOIN") {
      const join = decodeJoinBody(envelope.body);
      if (!bytesEqual(join.rulesHash, connectionRulesHash())) { throw new LobbyProtocolError("Rules bundle mismatch"); }
      if (room.host && !room.lobby.isRosterMember(remote)) {
        if ((room.lobby.roster?.seats.length ?? 1) >= 4) { throw new LobbyProtocolError("This table already has four seats"); }
        this.#accepted(room, await room.receiver.receiveAdmittedJoin(artifact));
        this.#require(room);
        const seats = [...room.lobby.roster!.seats, remote];
        await this.#publish(room, { round: 0, phase: "lobby", type: "ROSTER", body: encodeRosterBody({
          gameId: room.invitation.gameId, rulesHash: connectionRulesHash(), iceConfigHash: lobbyIceConfigHash(), seats,
        }) });
      } else {
        this.#accepted(room, await room.receiver.receiveRosterMemberJoin(artifact));
      }
    } else if (envelope.type === "ROSTER") {
      if (decodeRosterBody(envelope.body).seats.length > 4) { throw new LobbyProtocolError("Connection-check rosters have at most four seats"); }
      this.#accepted(room, await room.receiver.receiveRoster(artifact));
      this.#require(room);
      await this.#afterRoster(room);
    } else {
      if (room.lobby.roster?.seats.length !== 4) { throw new LobbyProtocolError("Readiness requires four seats"); }
      this.#accepted(room, await room.receiver.receiveReady(artifact));
    }
    this.#require(room);
    this.#refresh(room);
  }

  async #afterRoster(room: Room): Promise<void> {
    const self = parseIdentityPublicKey(this.#self().publicKey);
    if (!room.host && room.lobby.isRosterMember(self) && !room.lobby.hasSender(self)) {
      if (!room.ownJoin) throw new Error("Local JOIN is unavailable");
      this.#accepted(room, await room.receiver.receiveRosterMemberJoin(room.ownJoin));
    }
    this.#require(room);
    for (const member of room.lobby.roster?.seats ?? []) {
      if (!bytesEqual(member, self) && room.transport !== null && !room.transport.peers.some(({ identity }) => bytesEqual(identity, member))) {
        void room.transport.admit(member).catch((cause: unknown) => { if (this.#room === room) { this.#event(message(cause)); } });
      }
    }
  }

  async #publish(room: Room, content: EnvelopeContent): Promise<void> {
    this.#require(room);
    if (room.recordCount >= 128) { throw new Error("Connection-check history limit reached; open a new table"); }
    const artifact = await room.author.author(content);
    this.#require(room);
    room.recordCount += 1;
    this.#accepted(room, content.type === "ROSTER" ? await room.receiver.receiveRoster(artifact) : await room.receiver.receiveReady(artifact));
    this.#require(room);
    if (content.type === "ROSTER") { await this.#afterRoster(room); }
    this.#broadcastArtifact(room, artifact);
    if (content.type === "ROSTER") this.#broadcastHeads(room);
  }

  #allowedAuthor(room: Room, remote: IdentityPublicKey, from: IdentityPublicKey): boolean {
    return room.lobby.isRosterMember(from) || bytesEqual(room.invitation.host, from) ||
      bytesEqual(this.#self().publicKey, from) || bytesEqual(remote, from);
  }

  #get(room: Room, from: IdentityPublicKey, seq: number): EnvelopeArtifact | undefined {
    return room.game?.get(from, seq) ?? room.lobby.get(from, seq) ??
      (seq === 0 && room.ownJoin && bytesEqual(room.ownJoin.envelope.from, from) ? room.ownJoin : undefined);
  }

  #head(room: Room, from: IdentityPublicKey): ChainHead | null {
    const head = room.lobby.finalizedRegistry?.heads().find(head => bytesEqual(head.from, from)) ?? room.lobby.headOf(from);
    if (head) return head;
    if (room.ownJoin && bytesEqual(room.ownJoin.envelope.from, from)) return { from, seq: 0, hash: room.ownJoin.hash };
    return null;
  }

  #sendHeads(room: Room, remote: IdentityPublicKey, generation: number): void {
    const self = parseIdentityPublicKey(this.#self().publicKey);
    // An unseated guest only needs the host's roster history to bootstrap.
    const authors = room.lobby.isRosterMember(remote) ? room.lobby.roster!.seats : [self];
    const heads = authors.flatMap(from => this.#head(room, from) ?? []);
    this.#send(room, remote, generation, encodeChannelControl({ type: "HEADS", body: { heads } }));
  }

  #broadcastHeads(room: Room): void {
    if (this.#room !== room) return;
    for (const peer of room.transport?.peers ?? []) {
      if (room.transport?.authenticated(peer.identity)) this.#sendHeads(room, peer.identity, peer.generation);
    }
  }

  #broadcastArtifact(room: Room, artifact: EnvelopeArtifact): void {
    for (const peer of room.transport?.peers ?? []) {
      if (room.transport?.authenticated(peer.identity)) this.#send(room, peer.identity, peer.generation, artifact.canonicalBytes);
    }
  }

  #send(room: Room, remote: IdentityPublicKey, generation: number, payload: Uint8Array): void {
    void room.transport?.send(remote, generation, payload).catch((cause: unknown) => {
      if (this.#room === room && room.transport?.generation(remote) === generation) this.#event(message(cause));
    });
  }

  #historySource(room: Room, remote: IdentityPublicKey) {
    return {
      allowed: (from: IdentityPublicKey) => this.#allowedAuthor(room, remote, from),
      head: (from: IdentityPublicKey) => this.#head(room, from),
      get: (from: IdentityPublicKey, seq: number) => this.#get(room, from, seq),
    };
  }

  async #control(room: Room, remote: IdentityPublicKey, generation: number, control: ChannelControl): Promise<void> {
    const sync = room.sync.get(bytesToHex(remote));
    if (!sync || sync.generation !== generation) return;
    switch (control.type) {
      case "HEADS":
        if (control.body.heads.some(head => head.seq >= 4096)) throw new LobbyProtocolError("Advertised history exceeds match limit");
        sync.history.advertise(control.body.heads);
        break;
      case "SYNC_REQ": {
        const { from, fromSeq } = control.body;
        const mayShare = bytesEqual(from, this.#self().publicKey) || (room.lobby.isRosterMember(remote) && room.lobby.isRosterMember(from));
        const artifact = mayShare ? this.#get(room, from, fromSeq) : undefined;
        this.#send(room, remote, generation, encodeChannelControl({
          type: "SYNC_RESP", id: control.id, body: artifact ? { envelopes: [artifact] } : null,
        }));
        break;
      }
      case "SYNC_RESP": {
        if (control.body?.envelopes.some(artifact => !bytesEqual(artifact.envelope.game, room.invitation.gameId))) {
          throw new LobbyProtocolError("SYNC_RESP contains history from another table");
        }
        let result;
        try {
          result = sync.history.receive(control, this.#historySource(room, remote));
        } catch (cause) { throw new LobbyProtocolError(message(cause)); }
        if (result && "request" in result) this.#send(room, remote, generation, encodeChannelControl(result.request));
        else if (result?.conflict) this.#reportEquivocation(room, result.conflict, result.artifact);
        else if (result) await this.#acceptArtifact(room, remote, result.artifact);
        break;
      }
      case "ABORT_VOTE": {
        const seat = room.lobby.finalizedRegistry?.seatOf(remote);
        if (seat !== undefined && seat !== null) {
          const { missing, ended } = control.body;
          if (ended && room.votes.confirm(seat, missing)) this.#endTable(room, missing);
          else if (!ended && room.playing) room.votes.receive(seat, missing);
        }
        break;
      }
    }
    this.#refresh(room);
  }

  #reportEquivocation(room: Room, left: EnvelopeArtifact, right: EnvelopeArtifact): void {
    if (room.game) room.game.reportEquivocation(left, right);
    else if (room.evidence === null && room.lobby.isRosterMember(left.envelope.from)) {
      room.evidence = [left, right];
      this.#set({ error: "A player signed conflicting lobby history." });
    }
  }

  async markReady(): Promise<void> {
    const room = this.#room;
    if (room === null) { throw new Error("No active table"); }
    if (this.#snapshot.busy !== null) { throw new Error("A lobby action is already in progress"); }
    this.#set({ busy: "ready", error: null });
    try {
      await this.#enqueue(room, async () => {
        this.#refresh(room);
        if (!this.#snapshot.room?.canReady || room.lobby.rosterHash === null) { throw new LobbyProtocolError("Wait for all four identities and their lobby histories before marking ready"); }
        await this.#publish(room, { round: 0, phase: "lobby", type: "READY", body: encodeReadyBody({ rosterHash: room.lobby.rosterHash }) });
        this.#require(room);
        this.#refresh(room);
      });
    } catch (cause) { if (this.#room === room) { room.autoReadyRequested = false; this.#set({ error: message(cause) }); } throw cause; }
    finally { if (this.#room === room) { this.#set({ busy: null }); } }
  }

  async setReady(ready: boolean): Promise<void> {
    const room = this.#room;
    if (room === null) throw new Error("No active table");
    if (room.playing) throw new Error("The round has already started");
    room.localReady = ready;
    this.#set({ error: null });
    this.#refresh(room);
    try {
      await Promise.all((room.transport?.peers ?? []).filter(peer => room.transport?.authenticated(peer.identity)).map(peer =>
        room.transport!.send(peer.identity, peer.generation, Uint8Array.of(1, ready ? 1 : 0))));
    } catch (cause) {
      if (this.#room === room) this.#set({ error: `Ready status delivery failed: ${message(cause)}` });
      throw cause;
    }
  }

  exportTranscript(): Uint8Array {
    const lobby = this.#room?.lobby;
    if (!lobby?.finalizedRegistry || !lobby.rosterArtifact) throw new Error("The table needs four ready players before export");
    return exportTranscript(lobby.finalizedRegistry, lobby.rosterArtifact);
  }

  async playAction(intent: SaskuActionIntent): Promise<void> {
    const room = this.#room;
    if (!room?.game || !room.playing || room.ended !== null) throw new Error("No active round");
    await room.game.act(intent);
  }
  async voteToEndTable(): Promise<void> {
    const room = this.#room;
    if (!room?.playing || !room.game || room.ended !== null || !room.votes.available ||
        room.game.view.phase === "match_complete" || room.game.view.error) throw new Error("A table vote is not available");
    const seat = room.game.view.seat;
    if (room.votes.hasVoted(seat)) return;
    const body = { missing: room.votes.missing, ended: false };
    room.votes.receive(seat, body.missing);
    for (const peer of room.transport?.peers ?? []) {
      if (room.transport?.authenticated(peer.identity) && room.lobby.isRosterMember(peer.identity)) {
        this.#send(room, peer.identity, peer.generation, encodeChannelControl({ type: "ABORT_VOTE", body }));
      }
    }
    this.#refresh(room);
  }

  async retryPeer(publicKey: string): Promise<void> {
    const room = this.#room;
    if (room === null || room.transport === null || room.blocked || room.retryingPeers.has(publicKey)) return;
    room.retryingPeers.add(publicKey);
    try {
      const remote = parseIdentityPublicKey(hexToBytes(publicKey));
      const ice = room.iceDeployment?.credentialEndpoint
        ? await loadLobbyIce(room.iceDeployment, room.abort.signal)
        : null;
      this.#require(room);
      if (ice !== null) {
        room.iceCredentialWarning = ice.credentialWarning;
        this.#refresh(room);
      }
      await room.transport.retry(remote, ice?.rtcConfiguration);
      this.#refresh(room);
    } catch (cause) {
      if (this.#room === room) this.#set({ error: message(cause) });
    } finally {
      room.retryingPeers.delete(publicKey);
    }
  }

  #enqueue(room: Room, operation: () => Promise<void>): Promise<void> {
    if (room.pending >= 32) { return Promise.reject(new LobbyProtocolError("Lobby receive queue is full")); }
    room.pending += 1;
    const result = room.queue.then(async () => {
      this.#require(room);
      if (room.blocked) { throw new Error("Lobby storage needs recovery; leave and reopen the invitation"); }
      await operation();
    }).catch((cause: unknown) => {
      this.#recordFailure(room, cause);
      throw cause;
    }).finally(() => { room.pending -= 1; });
    room.queue = result.then(() => undefined, () => undefined);
    return result;
  }

  #recordFailure(room: Room, cause: unknown): void {
    if (this.#room !== room) return;
    if (!(cause instanceof LobbyProtocolError)) room.blocked = true;
    this.#set({ error: message(cause) });
    this.#refresh(room);
  }

  #accepted(room: Room, result: { readonly status: string; readonly reason?: string; readonly persistenceStatus?: string }): void {
    if (result.status !== "accepted" && result.status !== "duplicate") { throw new LobbyProtocolError(`Lobby message rejected: ${result.reason ?? result.status}`); }
    if (result.persistenceStatus === "stored") { room.recordCount += 1; }
  }

  async leave(): Promise<void> {
    ++this.#epoch;
    this.#set({ busy: "leaving" });
    await this.#closeRoom(this.#room);
    if (this.#options.manageHistory !== false && typeof window !== "undefined") { const url = new URL(this.#baseUrl); url.hash = ""; window.history.replaceState(null, "", url); }
    this.#set({ phase: "welcome", room: null, game: null, tableStatus: null, peers: [], relays: [], busy: null, error: null, events: [] });
  }

  async #closeRoom(room: Room | null): Promise<void> {
    if (room === null) { return; }
    if (this.#room === room) { this.#room = null; }
    room.abort.abort();
    if (room.headsTimer !== null) clearInterval(room.headsTimer);
    await room.transport?.close().catch(() => undefined);
    await room.queue;
    await room.game?.close();
    try { await Promise.allSettled([room.stored.close(), room.authored.close()]); }
    finally { room.releaseLease?.(); room.releaseLease = null; }
  }

  async #lease(room: Room): Promise<void> {
    if (typeof navigator === "undefined" || navigator.locks === undefined) {
      throw new Error("This table requires Web Locks to prevent two tabs from writing the same table");
    }
    await new Promise<void>((resolve, reject) => {
      const name = `p2pcards-lobby:${bytesToHex(room.invitation.gameId)}:${bytesToHex(this.#self().publicKey)}`;
      void navigator.locks.request(name, { ifAvailable: true }, async (lock) => {
        if (lock === null) { reject(new Error("This table is already open in another tab with the same identity")); return; }
        if (room.abort.signal.aborted || this.#room !== room) { reject(new Error("Lobby operation was cancelled")); return; }
        await new Promise<void>((release) => { room.releaseLease = release; resolve(); });
      }).catch(reject);
    });
  }

  async dispose(): Promise<void> {
    this.#disposed = true;
    ++this.#epoch;
    await this.#closeRoom(this.#room);
    await this.#identityStore?.close().catch(() => undefined);
    this.#listeners.clear();
  }

  #self(): Ed25519KeyPair {
    if (this.#identity === null || this.#disposed) { throw new Error("Browser identity is not available"); }
    return this.#identity;
  }

  #require(room: Room, epoch = this.#epoch): void {
    if (this.#disposed || this.#room !== room || room.abort.signal.aborted || epoch !== this.#epoch) { throw new Error("Lobby operation was cancelled"); }
  }

  #refresh(room: Room): void {
    if (this.#room !== room || this.#identity === null) { return; }
    if (room.lobby.finalizedRegistry && room.game === null) {
      room.game = new LiveRound({ session: room.lobby.finalizedRegistry, roster: room.lobby.roster!, self: parseIdentityPublicKey(this.#identity.publicKey),
        author: room.author, stored: room.stored, restoredViolations: room.restoredViolations, ...(this.#options.storage ? { storage: this.#options.storage } : {}),
        changed: () => this.#refresh(room), published: artifact => this.#broadcastArtifact(room, artifact) });
      if (room.evidence) room.game.reportEquivocation(...room.evidence);
      for (const artifact of room.early.splice(0)) {
        try { room.game.receiveHistory(artifact); }
        catch (cause) { this.#event(message(cause)); }
      }
    }
    for (const peer of room.transport?.peers ?? []) {
      const entry = room.sync.get(bytesToHex(peer.identity));
      if (entry?.generation !== peer.generation) continue;
      for (const request of entry.history.advance(this.#historySource(room, peer.identity))) {
        this.#send(room, peer.identity, entry.generation, encodeChannelControl(request));
      }
    }
    const roster = room.lobby.roster?.seats ?? [];
    const self = parseIdentityPublicKey(this.#identity.publicKey);
    const readySeats = room.lobby.readySeats;
    const ownSeat = roster.findIndex((key) => bytesEqual(key, self));
    const seats = roster.map((key, seat) => Object.freeze({
      publicKey: bytesToHex(key), fingerprint: identityFingerprint(key), isSelf: bytesEqual(key, self),
      isHost: bytesEqual(key, room.invitation.host), ready: bytesEqual(key, self) ? room.localReady : room.peerReady.get(bytesToHex(key))?.ready ?? false,
      connected: bytesEqual(key, self) || (room.transport?.authenticated(key) ?? false),
    }));
    const peers = (room.transport?.peers ?? []).map((peer) => Object.freeze({
      publicKey: bytesToHex(peer.identity), fingerprint: identityFingerprint(peer.identity), generation: peer.generation,
      state: room.transport?.authenticated(peer.identity) ? "authenticated" as const : peer.connectionState === "failed" ? "failed" as const :
        ["closed", "disconnected"].includes(peer.connectionState) ? "disconnected" as const : "connecting" as const,
      path: room.paths.get(bytesToHex(peer.identity)) ?? "unknown" as const,
    }));
    const disconnected = seats.flatMap(({ connected }, seat) => connected ? [] : [seat]);
    room.votes.update(disconnected.reduce((mask, seat) => mask | (1 << seat), 0));
    if (room.playing && room.votes.ended) this.#endTable(room, room.votes.missing);
    const synchronized = roster.length === 4 && roster.every(key => bytesEqual(key, self) ||
      (room.transport?.authenticated(key) && room.sync.get(bytesToHex(key))?.history.ready));
    room.game?.connected(room.playing && synchronized && room.ended === null);
    const gameView = room.game?.view;
    const audited = gameView?.state?.audit?.result;
    const completion = gameView && audited?.status === "valid" && gameView.match.completed.length < gameView.match.round
      ? roundCompletionMarker(gameView.match.round, audited.score) : null;
    const markers = gameView?.match.completed.map(item => roundCompletionMarker(item.round, item.score)) ?? [];
    if (completion !== null) markers.push(completion);
    for (const peer of room.transport?.peers ?? []) {
      if (!room.transport?.authenticated(peer.identity)) continue;
      const key = bytesToHex(peer.identity), sent = room.sentRoundCompletions.get(key) ?? new Map();
      room.sentRoundCompletions.set(key, sent);
      for (const marker of markers) {
        const previous = sent.get(marker[1]!);
        if (previous?.generation === peer.generation && sameRoundCompletion(previous.marker, marker)) continue;
        sent.set(marker[1]!, { generation: peer.generation, marker });
        void room.transport.send(peer.identity, peer.generation, marker).catch((cause: unknown) => {
          if (this.#room === room) {
            sent.delete(marker[1]!);
            this.#event(`Round completion delivery failed: ${message(cause)}`);
          }
        });
      }
    }
    if (completion !== null && !room.blocked && roster.some(key => {
      if (bytesEqual(key, self)) return false;
      const remote = room.roundCompletions.get(bytesToHex(key))?.get(completion[1]!);
      return remote !== undefined && remote.generation === room.transport?.generation(key) && !sameRoundCompletion(remote.marker, completion);
    })) {
      room.blocked = true;
      this.#set({ error: "Players disagree on the verified round result; reopen the table to inspect signed history" });
    }
    const allComplete = completion !== null && roster.length === 4 && roster.every(key => bytesEqual(key, self) || (() => {
      const remote = room.roundCompletions.get(bytesToHex(key))?.get(completion[1]!);
      return remote !== undefined && remote.generation === room.transport?.generation(key) && sameRoundCompletion(remote.marker, completion);
    })()) && !room.blocked;
    room.game?.roundReady(allComplete && room.ended === null ? gameView!.match.round : 0);
    const canReady = !room.blocked && room.recordCount < 128 && room.lobby.state !== "finalized" && roster.length === 4 && ownSeat >= 0 &&
      !readySeats.includes(ownSeat) && roster.every((key) => room.lobby.headOf(key) !== null) && seats.every(({ connected }) => connected);
    const allReadyKnown = room.localReady && roster.length === 4 && roster.every(key => bytesEqual(key, self) || (
      room.peerReady.get(bytesToHex(key))?.generation === room.transport?.generation(key) && room.peerReady.get(bytesToHex(key))?.ready === true));
    const canStart = room.host && room.lobby.state === "finalized" && !room.playing && synchronized && allReadyKnown && !room.blocked;
    if (canStart) {
      room.playing = true;
      room.game?.connected(synchronized);
    }
    this.#set({
      game: room.playing ? room.game?.view ?? null : null,
      tableStatus: room.playing ? { disconnected, ended: room.ended === null ? null : "The connected players voted to end this table.",
        canVote: room.votes.available && room.ended === null && gameView?.phase !== "match_complete" && !gameView?.error,
        voted: room.votes.hasVoted(ownSeat),
        votes: room.votes.count, needed: seats.length - disconnected.length } : null,
      phase: room.lobby.state === "finalized" ? "agreed" : room.transport === null ? "connecting" : "lobby",
      room: Object.freeze({ gameId: bytesToHex(room.invitation.gameId), host: bytesToHex(room.invitation.host), isHost: room.host,
        invitation: createLobbyInvitation(this.#baseUrl, room.invitation.gameId, room.invitation.host), seats: Object.freeze(seats),
        rosterHash: room.lobby.rosterHash === null ? null : bytesToHex(room.lobby.rosterHash), canReady, ownReady: room.localReady }),
      iceCredentialWarning: room.iceCredentialWarning,
      peers: Object.freeze(peers), relays: relayViews(room.signaling),
    });
    if (canReady && !room.autoReadyRequested && this.#snapshot.busy === null) {
      room.autoReadyRequested = true;
      queueMicrotask(() => { if (this.#room === room) void this.markReady().catch(() => undefined); });
    }
  }

  #endTable(room: Room, missing: number): void {
    if (room.ended !== null || room.game?.view.phase === "match_complete") return;
    room.ended = missing;
    room.playing = true;
    const self = this.#self().publicKey;
    try { globalThis.localStorage?.setItem(tableEndKey(room.invitation.gameId, self), String(missing)); }
    catch { this.#event("This browser could not save the table vote result."); }
    for (const peer of room.transport?.peers ?? []) {
      if (room.transport?.authenticated(peer.identity)) this.#sendTableEnd(room, peer.identity, peer.generation);
    }
  }

  #sendTableEnd(room: Room, remote: IdentityPublicKey, generation: number): void {
    const missing = room.ended;
    const seat = room.lobby.finalizedRegistry?.seatOf(parseIdentityPublicKey(this.#self().publicKey));
    if (missing !== null && seat !== undefined && seat !== null && (missing & (1 << seat)) === 0 && room.lobby.isRosterMember(remote)) {
      this.#send(room, remote, generation, encodeChannelControl({ type: "ABORT_VOTE", body: { missing, ended: true } }));
    }
  }

  #readTableEnd(game: Uint8Array, self: Uint8Array): number | null {
    try {
      const missing = Number(globalThis.localStorage?.getItem(tableEndKey(game, self)));
      return Number.isInteger(missing) && missing > 0 && missing < 15 ? missing : null;
    } catch {
      return null;
    }
  }

  #event(event: string): void { this.#set({ events: Object.freeze([...this.#snapshot.events.slice(-7), event.slice(0, 240)]) }); }
  #set(update: Partial<BrowserLobbySnapshot>): void {
    if (this.#disposed) { return; }
    this.#snapshot = Object.freeze({ ...this.#snapshot, ...update });
    for (const listener of this.#listeners) { try { listener(); } catch { /* View observers cannot change protocol effects. */ } }
  }
}

function relayViews(signaling?: TrysteroNostrSignalingAdapter | null): BrowserLobbySnapshot["relays"] {
  return Object.freeze((signaling?.relayDiagnostics ?? []).map(relay => Object.freeze({
    url: relay.url, state: relay.state, error: relay.lastError === null ? null : message(relay.lastError),
  })));
}

function message(cause: unknown): string { return (cause instanceof Error ? cause.message : "Lobby operation failed").slice(0, 300); }

function tableEndKey(game: Uint8Array, self: Uint8Array): string {
  return `p2pcards:table-ended:${bytesToHex(game)}:${bytesToHex(self)}`;
}
