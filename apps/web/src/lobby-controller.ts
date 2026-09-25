import { LiveRound } from "./live-round";
import { PeerHistoryBarrier } from "./peer-history-barrier";
import type { SaskuActionIntent } from "@p2pcards/game-sasku";
import { bytesEqual, bytesToHex, hexToBytes, importEd25519PublicKey, randomBytes, type Ed25519KeyPair } from "@p2pcards/crypto";
import {
  decodeAndVerifyEnvelope, decodeJoinBody, decodeRosterBody, decodeReadyBody, deriveSignalingRoomId,
  encodeJoinBody, encodeReadyBody, encodeRosterBody, parseGameId, parseIdentityPublicKey,
  type EnvelopeArtifact, type IdentityPublicKey,
} from "@p2pcards/protocol";
import { LobbyChainRegistry, PersistentEnvelopeAuthor, PersistentLobbyReceiver, recoverLobby, replayAuthoredHistory, type EnvelopeContent } from "@p2pcards/session";
import { IndexedDbAuthoredEnvelopeStore, IndexedDbIdentityStore, IndexedDbSessionStore, type IndexedDbStoreOptions } from "@p2pcards/storage";
import { TrysteroNostrSignalingAdapter, type MeshPeerConnectionFactory } from "@p2pcards/transport";

import { connectionRulesHash, lobbyIceConfigHash, parseRelayText } from "./lobby-config";
import { createLobbyInvitation, identityFingerprint, parseLobbyInvitation, type LobbyInvitation } from "./lobby-invitation";
import { LobbyTransport, type LobbyTransportLike, type LobbyTransportOptions } from "./lobby-transport";
import type { BrowserLobbyActions, BrowserLobbySnapshot } from "./lobby-types";

interface Room {
  readonly invitation: LobbyInvitation;
  readonly host: boolean;
  readonly stored: IndexedDbSessionStore;
  readonly authored: IndexedDbAuthoredEnvelopeStore;
  readonly author: PersistentEnvelopeAuthor;
  readonly abort: AbortController;
  lobby: LobbyChainRegistry;
  receiver: PersistentLobbyReceiver;
  signaling: TrysteroNostrSignalingAdapter | null;
  transport: LobbyTransportLike | null;
  queue: Promise<void>;
  pending: number;
  blocked: boolean;
  recordCount: number;
  releaseLease: (() => void) | null;
  readonly flushes: Map<string, { generation: number; dirty: boolean }>;
  game: LiveRound | null;
  playing: boolean;
  localReady: boolean;
  autoReadyRequested: boolean;
  readonly peerReady: Map<string, { generation: number; ready: boolean }>;
  readonly barriers: Map<string, { generation: number; barrier: PeerHistoryBarrier }>;
  readonly early: { remote: IdentityPublicKey; payload: Uint8Array }[];
  readonly paths: Map<string, "direct" | "relayed" | "unknown">;
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
      room: null, peers: [], relays: [], busy: "identity", error: null, events: [],
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
    this.#set({ busy: host ? "hosting" : "joining", phase: "connecting", error: null, events: [] });
    let room: Room | null = null;
    try {
      const relayUrls = parseRelayText(relayText);
      const stored = new IndexedDbSessionStore(this.#options.storage);
      const authored = new IndexedDbAuthoredEnvelopeStore(this.#options.storage);
      const context = { gameId: invitation.gameId, host: invitation.host, rulesHash: connectionRulesHash(), iceConfigHash: lobbyIceConfigHash() };
      const lobby = new LobbyChainRegistry(context);
      room = {
        invitation, host, stored, authored, author: new PersistentEnvelopeAuthor(invitation.gameId, self.secretKey, authored),
        abort: new AbortController(), lobby, receiver: new PersistentLobbyReceiver(lobby, stored),
        signaling: null, transport: null, queue: Promise.resolve(), pending: 0, blocked: false, recordCount: 0, releaseLease: null, flushes: new Map(), paths: new Map(), game: null, playing: false, localReady: true, autoReadyRequested: false, peerReady: new Map(), barriers: new Map(), early: [],
      };
      this.#room = room;
      this.#refresh(room);
      await this.#lease(room);
      this.#require(room, epoch);
      const records = await stored.loadTranscript(invitation.gameId);
      this.#require(room, epoch);
      if (records.length > 512 || records.some(({ artifact }) => artifact.canonicalBytes.length > 65536)) {
        throw new Error("Stored history exceeds this connection-check profile; it will not be discarded automatically");
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
        room.lobby = recovered.lobby;
        room.receiver = new PersistentLobbyReceiver(room.lobby, stored);
        const gameRecords = records.filter(({ artifact }) => !["JOIN", "ROSTER", "READY"].includes(artifact.envelope.type));
        if (gameRecords.length) {
          const session = room.lobby.finalizedRegistry;
          if (!session) throw new Error("Saved round has no finalized roster");
          for (const { artifact } of gameRecords.sort((a, b) => a.artifact.envelope.seq - b.artifact.envelope.seq)) {
            if (session.ingest(artifact).status !== "accepted") throw new Error("Saved round history is not contiguous");
          }
          room.playing = true;
        }
      } else if (host) {
        await this.#publish(room, { round: 0, phase: "lobby", type: "ROSTER", body: encodeRosterBody({ ...context, seats: [parseIdentityPublicKey(self.publicKey)] }) });
      } else {
        await room.author.author({ round: 0, phase: "lobby", type: "JOIN", body: encodeJoinBody({ pkId: parseIdentityPublicKey(self.publicKey), rulesHash: context.rulesHash, clientVersion: "sasku-first-round-candidate/1" }) });
        room.recordCount += 1;
      }
      this.#require(room, epoch);
      if (this.#options.manageHistory !== false && typeof window !== "undefined") { window.history.replaceState(null, "", createLobbyInvitation(this.#baseUrl, invitation.gameId, invitation.host)); }
      if (room.lobby.state === "finalized") {
        this.#event("Saved agreement restored. Synchronizing signed history with the other players.");
      }
      const current = room;
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
          current.barriers.set(bytesToHex(remote), { generation, barrier: new PeerHistoryBarrier() });
          current.peerReady.delete(bytesToHex(remote));
          this.#event(`Identity verified: ${identityFingerprint(remote)}`);
          void current.transport!.send(remote, generation, Uint8Array.of(1, current.localReady ? 1 : 0)).catch((cause: unknown) => {
            if (this.#room === current) this.#event(`Ready status delivery failed: ${message(cause)}`);
          });
          this.#flush(current, remote, generation);
          void current.transport!.path(remote).then((path) => {
            if (this.#room === current && current.transport?.generation(remote) === generation) {
              current.paths.set(bytesToHex(remote), path.path); this.#refresh(current);
            }
          }).catch(() => undefined);
        },
        onMessage: (remote, payload, generation) => this.#incoming(current, remote, payload, generation),
        onDisconnected: (remote) => {
          if (this.#room !== current) { return; }
          current.barriers.delete(bytesToHex(remote));
          current.peerReady.delete(bytesToHex(remote));
          current.paths.delete(bytesToHex(remote));
          current.flushes.delete(bytesToHex(remote));
          if (!current.lobby.isRosterMember(remote)) { current.transport?.remove(remote); }
          this.#refresh(current);
        },
        onError: (error) => { if (this.#room === current) { this.#event(message(error)); this.#refresh(current); } },
        onChange: () => { if (this.#room === current) { this.#refresh(current); } },
      };
      room.transport = this.#options.createTransport ? this.#options.createTransport(transportOptions) : new LobbyTransport({
        ...transportOptions, signaling: signaling!,
        ...(this.#options.createPeerConnection === undefined ? {} : { createPeerConnection: this.#options.createPeerConnection }),
      });
      await room.transport.start();
      this.#require(room, epoch);
      this.#event(host ? "Table opened. Share the invitation with three other identities." : "Joining the host; waiting for a signed roster.");
      this.#set({ busy: null }); this.#refresh(room);
    } catch (cause) {
      if (this.#epoch === epoch) {
        await this.#closeRoom(room);
        this.#set({ phase: "welcome", busy: null, room: null, peers: [], relays: [], error: message(cause) });
      }
      throw cause;
    }
  }

  async #incoming(room: Room, remote: IdentityPublicKey, payload: Uint8Array, generation: number): Promise<void> {
    if (this.#room !== room || room.transport?.generation(remote) !== generation) return;
    if (payload[0] === 0) {
      room.barriers.get(bytesToHex(remote))?.barrier.receive(payload); this.#refresh(room); return;
    }
    if (payload[0] === 1) {
      if (payload.length !== 2 || (payload[1] !== 0 && payload[1] !== 1)) throw new LobbyProtocolError("Invalid ready status");
      room.peerReady.set(bytesToHex(remote), { generation, ready: payload[1] === 1 });
      this.#refresh(room); return;
    }
    if (payload.length > 65536) throw new LobbyProtocolError("Envelope exceeds 64 KiB");
    const candidate = decodeAndVerifyEnvelope(payload);
    if (!["JOIN", "ROSTER", "READY"].includes(candidate.envelope.type)) {
      if (!bytesEqual(candidate.envelope.from, remote) || !bytesEqual(candidate.envelope.game, room.invitation.gameId)) throw new LobbyProtocolError("Wrong authenticated round sender");
      return this.#enqueue(room, async () => {
        if (room.game) room.game.receive(remote, payload);
        else {
          if (room.early.length >= 32) throw new LobbyProtocolError("Early round queue is full");
          room.early.push({ remote, payload: payload.slice() });
        }
        if (!room.playing && bytesEqual(remote, room.invitation.host) && candidate.envelope.type === "KEY_SHARE") {
          room.playing = true;
          this.#refresh(room);
        }
      });
    }
    if (payload.length > 4096) { throw new LobbyProtocolError("Lobby envelope exceeds 4 KiB"); }
    let artifact: EnvelopeArtifact;
    try {
      artifact = decodeAndVerifyEnvelope(payload);
      if (!bytesEqual(artifact.envelope.game, room.invitation.gameId) || !bytesEqual(artifact.envelope.from, remote) ||
          artifact.envelope.round !== 0 || artifact.envelope.phase !== "lobby" || !["JOIN", "ROSTER", "READY"].includes(artifact.envelope.type)) {
        throw new Error("Only this authenticated author's lobby messages are accepted");
      }
      if (artifact.envelope.type === "JOIN") { decodeJoinBody(artifact.envelope.body); }
      if (artifact.envelope.type === "ROSTER") { decodeRosterBody(artifact.envelope.body); }
      if (artifact.envelope.type === "READY") { decodeReadyBody(artifact.envelope.body); }
    } catch (cause) { throw new LobbyProtocolError(message(cause)); }
    return this.#enqueue(room, async () => {
      const existing = room.lobby.get(remote, artifact.envelope.seq);
      if (existing !== undefined && bytesEqual(existing.canonicalBytes, artifact.canonicalBytes)) { return; }
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
    });
  }

  async #afterRoster(room: Room): Promise<void> {
    const self = parseIdentityPublicKey(this.#self().publicKey);
    if (!room.host && room.lobby.isRosterMember(self) && !room.lobby.hasSender(self)) {
      const own = await room.authored.readAuthoredPage(room.invitation.gameId, self, 0, 0);
      this.#require(room);
      this.#accepted(room, await room.receiver.receiveRosterMemberJoin(own[0]!));
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
    for (const peer of room.transport?.peers ?? []) {
      if (room.transport?.authenticated(peer.identity)) { this.#flush(room, peer.identity, peer.generation); }
    }
  }

  #flush(room: Room, remote: IdentityPublicKey, generation: number): void {
    const key = bytesToHex(remote);
    const existing = room.flushes.get(key);
    if (existing?.generation === generation) { existing.dirty = true; return; }
    const flush = { generation, dirty: true };
    let failed = false;
    room.flushes.set(key, flush);
    void (async () => {
      while (flush.dirty && this.#room === room && room.transport?.generation(remote) === generation) {
        flush.dirty = false;
        const result = await replayAuthoredHistory(room.authored, room.invitation.gameId, parseIdentityPublicKey(this.#self().publicKey),
          (bytes) => room.transport!.send(remote, generation, bytes),
          { signal: room.abort.signal, maxEnvelopes: 128, maxBytes: 4 * 1024 * 1024 });
        if (result.status === "failed") {
          if (this.#room === room && result.stage !== "send") {
            room.blocked = true;
            this.#set({ error: `Local authored history needs recovery: ${message(result.error)}` });
            this.#refresh(room);
          }
          throw result.error;
        }
        if (result.status === "cancelled") { return; }
        const entry = room.barriers.get(key);
        const head = await room.author.readHead();
        if (head && entry?.generation === generation && room.transport?.generation(remote) === generation) {
          await room.transport.send(remote, generation, entry.barrier.announce(head));
          this.#refresh(room);
        }
      }
    })().catch((cause: unknown) => {
      failed = true;
      if (this.#room === room && room.transport?.generation(remote) === generation) { this.#event(`History delivery failed: ${message(cause)}`); }
    }).finally(() => {
      if (room.flushes.get(key) === flush) {
        room.flushes.delete(key);
        if (!failed && flush.dirty && this.#room === room && room.transport?.generation(remote) === generation) {
          this.#flush(room, remote, generation);
        }
      }
    });
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

  async playAction(intent: SaskuActionIntent): Promise<void> {
    const room = this.#room;
    if (!room?.game || !room.playing) throw new Error("No active round");
    await room.game.act(intent);
  }
  #flushAll(room: Room): void {
    for (const peer of room.transport?.peers ?? []) if (room.transport?.authenticated(peer.identity)) this.#flush(room, peer.identity, peer.generation);
  }

  async retryPeer(publicKey: string): Promise<void> {
    const room = this.#room;
    if (room === null || room.transport === null || room.blocked) { return; }
    try { await room.transport.retry(parseIdentityPublicKey(hexToBytes(publicKey))); }
    catch (cause) { if (this.#room === room) { this.#set({ error: message(cause) }); } }
  }

  #enqueue(room: Room, operation: () => Promise<void>): Promise<void> {
    if (room.pending >= 32) { return Promise.reject(new LobbyProtocolError("Lobby receive queue is full")); }
    room.pending += 1;
    const result = room.queue.then(async () => {
      this.#require(room);
      if (room.blocked) { throw new Error("Lobby storage needs recovery; leave and reopen the invitation"); }
      await operation();
    }).catch((cause: unknown) => {
      if (this.#room === room) {
        if (!(cause instanceof LobbyProtocolError)) { room.blocked = true; }
        this.#set({ error: message(cause) }); this.#refresh(room);
      }
      throw cause;
    }).finally(() => { room.pending -= 1; });
    room.queue = result.then(() => undefined, () => undefined);
    return result;
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
    this.#set({ phase: "welcome", room: null, game: null, peers: [], relays: [], busy: null, error: null, events: [] });
  }

  async #closeRoom(room: Room | null): Promise<void> {
    if (room === null) { return; }
    if (this.#room === room) { this.#room = null; }
    room.abort.abort();
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
        author: room.author, stored: room.stored, ...(this.#options.storage ? { storage: this.#options.storage } : {}),
        changed: () => this.#refresh(room), published: () => this.#flushAll(room) });
      for (const item of room.early.splice(0)) room.game.receive(item.remote, item.payload);
      this.#flushAll(room);
    }
    for (const [key, entry] of room.barriers) {
      const remote = parseIdentityPublicKey(hexToBytes(key));
      const ack = entry.barrier.acknowledge(seq => room.game?.get(remote, seq) ?? room.lobby.get(remote, seq));
      if (ack) void room.transport?.send(remote, entry.generation, ack).catch(() => undefined);
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
      state: room.transport?.authenticated(peer.identity) ? "authenticated" as const : peer.connectionState === "closed" ? "disconnected" as const : "connecting" as const,
      path: room.paths.get(bytesToHex(peer.identity)) ?? "unknown" as const,
    }));
    const synchronized = roster.length === 4 && roster.every(key => bytesEqual(key, self) ||
      (room.transport?.authenticated(key) && room.barriers.get(bytesToHex(key))?.barrier.ready));
    room.game?.connected(room.playing && synchronized);
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
      phase: room.lobby.state === "finalized" ? "agreed" : room.transport === null ? "connecting" : "lobby",
      room: Object.freeze({ gameId: bytesToHex(room.invitation.gameId), host: bytesToHex(room.invitation.host), isHost: room.host,
        invitation: createLobbyInvitation(this.#baseUrl, room.invitation.gameId, room.invitation.host), seats: Object.freeze(seats),
        rosterHash: room.lobby.rosterHash === null ? null : bytesToHex(room.lobby.rosterHash), canReady, ownReady: room.localReady }),
      peers: Object.freeze(peers), relays: Object.freeze((room.signaling?.relayDiagnostics ?? []).map((relay) => Object.freeze({
        url: relay.url, state: relay.state, error: relay.lastError === null ? null : message(relay.lastError),
      }))),
    });
    if (canReady && !room.autoReadyRequested && this.#snapshot.busy === null) {
      room.autoReadyRequested = true;
      queueMicrotask(() => { if (this.#room === room) void this.markReady().catch(() => undefined); });
    }
  }

  #event(event: string): void { this.#set({ events: Object.freeze([...this.#snapshot.events.slice(-7), event.slice(0, 240)]) }); }
  #set(update: Partial<BrowserLobbySnapshot>): void {
    if (this.#disposed) { return; }
    this.#snapshot = Object.freeze({ ...this.#snapshot, ...update });
    for (const listener of this.#listeners) { try { listener(); } catch { /* View observers cannot change protocol effects. */ } }
  }
}

function message(cause: unknown): string { return (cause instanceof Error ? cause.message : "Lobby operation failed").slice(0, 300); }
