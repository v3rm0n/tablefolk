import {
  bytesEqual,
  bytesToHex,
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  type Ed25519SecretKey,
} from "@p2pcards/crypto";
import type { CborValue } from "@p2pcards/encoding";
import {
  decodeAndVerifyEnvelope,
  encodeJoinBody,
  encodeReadyBody,
  encodeRosterBody,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  signEnvelope,
  type EnvelopeArtifact,
  type Hash256,
  type IdentityPublicKey,
  type UnsignedEnvelope,
} from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";

import { LobbyChainRegistry, type LobbyBootstrapContext } from "./lobby-bootstrap";
import {
  PersistentLobbyReceiver,
  PersistentLobbyReceiverError,
  type AcceptedLobbyEnvelopeStore,
  type AcceptedLobbyRosterPersistenceOutcome,
} from "./persistent-lobby-receiver";
import type { AcceptedEnvelopePersistenceOutcome } from "./persistent-receiver";

interface TestIdentity {
  readonly secretKey: Ed25519SecretKey;
  readonly publicKey: IdentityPublicKey;
}

const HOST = identity(41);
const ALICE = identity(42);
const BOB = identity(43);
const MALLORY = identity(44);
const GAME_ID = parseGameId(new Uint8Array(16).fill(0x71));
const RULES_HASH = parseHash256(new Uint8Array(32).fill(0x72));
const ICE_CONFIG_HASH = parseHash256(new Uint8Array(32).fill(0x73));
const ZERO_HASH = parseHash256(new Uint8Array(32));
const CONTEXT: LobbyBootstrapContext = {
  gameId: GAME_ID,
  host: HOST.publicKey,
  rulesHash: RULES_HASH,
  iceConfigHash: ICE_CONFIG_HASH,
};

describe("persistent lobby receiver", () => {
  it("does not admit a JOIN until its durable write resolves", async () => {
    const lobby = new LobbyChainRegistry(CONTEXT);
    const store = new MemoryLobbyStore();
    const gate = deferred<void>();
    const started = deferred<void>();
    store.beforeEnvelopeCommit = async () => {
      started.resolve();
      await gate.promise;
    };
    const receiver = new PersistentLobbyReceiver(lobby, store);
    const join = joinEnvelope(ALICE);
    const expectedHash = join.hash.slice();

    const pending = receiver.receiveAdmittedJoin(join);
    join.canonicalBytes.fill(0xff);
    join.hash.fill(0xff);
    await started.promise;
    expect(lobby.hasSender(ALICE.publicKey)).toBe(false);

    gate.resolve();
    await expect(pending).resolves.toMatchObject({
      status: "accepted",
      persistenceStatus: "stored",
      rosterSnapshotStatus: null,
      transition: { status: "accepted" },
    });
    expect(lobby.headOf(ALICE.publicKey)?.hash).toEqual(expectedHash);
    expect(store.records[0]?.hash).toEqual(expectedHash);
  });

  it("does not install a ROSTER until transcript and snapshot commit", async () => {
    const lobby = new LobbyChainRegistry(CONTEXT);
    const store = new MemoryLobbyStore();
    const gate = deferred<void>();
    const started = deferred<void>();
    store.beforeRosterCommit = async () => {
      started.resolve();
      await gate.promise;
    };
    const receiver = new PersistentLobbyReceiver(lobby, store);
    const roster = rosterEnvelope(0, ZERO_HASH, [HOST.publicKey, ALICE.publicKey, BOB.publicKey]);

    const pending = receiver.receiveRoster(roster);
    await started.promise;
    expect(lobby.roster).toBeNull();
    expect(lobby.headOf(HOST.publicKey)).toBeNull();

    gate.resolve();
    await expect(pending).resolves.toMatchObject({
      status: "accepted",
      persistenceStatus: "stored",
      rosterSnapshotStatus: "stored",
    });
    expect(lobby.roster?.seats).toEqual([HOST.publicKey, ALICE.publicKey, BOB.publicKey]);
    expect(store.rosterSnapshot?.hash).toEqual(roster.hash);
  });

  it("does not finalize readiness until the last READY is durable", async () => {
    const fixture = readyLobby();
    const gate = deferred<void>();
    const started = deferred<void>();
    fixture.store.beforeEnvelopeCommit = async () => {
      started.resolve();
      await gate.promise;
    };
    const receiver = new PersistentLobbyReceiver(fixture.lobby, fixture.store);
    const bobReady = readyEnvelope(BOB, 1, fixture.bobJoin.hash, fixture.rosterHash);

    const pending = receiver.receiveReady(bobReady);
    await started.promise;
    expect(fixture.lobby.state).toBe("collecting_ready");
    expect(fixture.lobby.readySeats).toEqual([0, 1]);
    expect(fixture.lobby.headOf(BOB.publicKey)).toMatchObject({ seq: 0 });

    gate.resolve();
    await expect(pending).resolves.toMatchObject({
      status: "accepted",
      transition: { state: "finalized" },
    });
    expect(fixture.lobby.state).toBe("finalized");
    expect(fixture.lobby.finalizedRegistry?.heads()).toEqual([
      expect.objectContaining({ from: HOST.publicKey, seq: 1 }),
      expect.objectContaining({ from: ALICE.publicKey, seq: 1 }),
      expect.objectContaining({ from: BOB.publicKey, seq: 1, hash: bobReady.hash }),
    ]);
  });

  it("persists a later semantic READY duplicate before advancing its chain", async () => {
    const lobby = new LobbyChainRegistry(CONTEXT);
    const store = new MemoryLobbyStore();
    const roster = rosterEnvelope(0, ZERO_HASH, [HOST.publicKey, ALICE.publicKey, BOB.publicKey]);
    const aliceJoin = joinEnvelope(ALICE);
    const bobJoin = joinEnvelope(BOB);
    lobby.ingestRoster(roster);
    lobby.bootstrapJoin(aliceJoin);
    lobby.bootstrapJoin(bobJoin);
    const rosterHash = lobby.rosterHash!;
    const first = readyEnvelope(ALICE, 1, aliceJoin.hash, rosterHash);
    const repeated = readyEnvelope(ALICE, 2, first.hash, rosterHash);
    lobby.ingestReady(first);
    store.seed(roster);
    store.seed(aliceJoin);
    store.seed(bobJoin);
    store.seed(first);
    store.setRosterSnapshot(roster);
    const receiver = new PersistentLobbyReceiver(lobby, store);

    await expect(receiver.receiveReady(repeated)).resolves.toMatchObject({
      status: "duplicate",
      persistenceStatus: "stored",
      transition: {
        status: "duplicate",
        chainResult: { status: "accepted" },
      },
    });
    expect(lobby.readySeats).toEqual([1]);
    expect(lobby.headOf(ALICE.publicKey)).toMatchObject({ seq: 2, hash: repeated.hash });
  });

  it("does not write semantically rejected lobby transitions", async () => {
    const lobby = new LobbyChainRegistry(CONTEXT);
    const store = new MemoryLobbyStore();
    const receiver = new PersistentLobbyReceiver(lobby, store);
    const invalidJoin = signed(ALICE, {
      seq: 0,
      prev: ZERO_HASH,
      type: "JOIN",
      body: {},
    });
    const wrongRoster = rosterEnvelope(0, ZERO_HASH, [HOST.publicKey], ALICE);
    const readyWithoutRoster = readyEnvelope(HOST, 0, ZERO_HASH, ZERO_HASH);

    await expect(receiver.receiveAdmittedJoin(invalidJoin)).resolves.toMatchObject({
      status: "rejected",
      reason: "malformed_body",
    });
    await expect(receiver.receiveRoster(wrongRoster)).resolves.toMatchObject({
      status: "rejected",
      reason: "wrong_sender",
    });
    await expect(receiver.receiveReady(readyWithoutRoster)).resolves.toMatchObject({
      status: "rejected",
      reason: "no_roster",
    });
    await expect(receiver.receiveRosterMemberJoin(joinEnvelope(MALLORY))).resolves.toMatchObject({
      status: "rejected",
      reason: "not_roster_member",
    });
    expect(store.rosterCalls).toEqual([]);
    expect(store.envelopeCalls).toEqual([]);
  });

  it("does not allow lobby control messages through generic chain receipt", async () => {
    const lobby = new LobbyChainRegistry(CONTEXT);
    const store = new MemoryLobbyStore();
    const receiver = new PersistentLobbyReceiver(lobby, store);

    await expect(receiver.receiveKnown(joinEnvelope(ALICE))).rejects.toThrow(
      /dedicated lobby receive method/,
    );
    expect(store.envelopeCalls).toEqual([]);
    expect(lobby.hasSender(ALICE.publicKey)).toBe(false);
  });

  it("leaves lobby state unchanged on storage failure and keeps its queue usable", async () => {
    const lobby = new LobbyChainRegistry(CONTEXT);
    const store = new MemoryLobbyStore();
    const receiver = new PersistentLobbyReceiver(lobby, store);
    const roster = rosterEnvelope(0, ZERO_HASH, [HOST.publicKey]);
    store.failNextRoster = true;

    await expect(receiver.receiveRoster(roster)).rejects.toThrow("roster storage failure");
    expect(lobby.roster).toBeNull();
    expect(lobby.headOf(HOST.publicKey)).toBeNull();
    await expect(receiver.receiveRoster(roster)).resolves.toMatchObject({ status: "accepted" });
    expect(lobby.roster?.seats).toEqual([HOST.publicKey]);
  });

  it("serializes concurrent roster transitions in invocation order", async () => {
    const lobby = new LobbyChainRegistry(CONTEXT);
    const store = new MemoryLobbyStore();
    const gate = deferred<void>();
    let calls = 0;
    store.beforeRosterCommit = async () => {
      calls += 1;
      if (calls === 1) {
        await gate.promise;
      }
    };
    const receiver = new PersistentLobbyReceiver(lobby, store);
    const first = rosterEnvelope(0, ZERO_HASH, [HOST.publicKey]);
    const second = rosterEnvelope(1, first.hash, [HOST.publicKey, ALICE.publicKey]);

    const firstPending = receiver.receiveRoster(first);
    const secondPending = receiver.receiveRoster(second);
    await Promise.resolve();
    expect(store.rosterCalls.map(({ envelope }) => envelope.seq)).toEqual([0]);
    expect(lobby.roster).toBeNull();

    gate.resolve();
    await expect(Promise.all([firstPending, secondPending])).resolves.toMatchObject([
      { status: "accepted" },
      { status: "accepted" },
    ]);
    expect(store.rosterCalls.map(({ envelope }) => envelope.seq)).toEqual([0, 1]);
    expect(lobby.roster?.seats).toEqual([HOST.publicKey, ALICE.publicKey]);
  });

  it("fails closed on durable conflicts and ahead-of-memory roster snapshots", async () => {
    const candidateJoin = joinEnvelope(ALICE);
    const conflictingJoin = joinEnvelope(ALICE, {
      pkId: ALICE.publicKey,
      rulesHash: RULES_HASH,
      clientVersion: "conflict/1",
    });
    const conflictLobby = new LobbyChainRegistry(CONTEXT);
    const conflictStore = new MemoryLobbyStore();
    conflictStore.seed(conflictingJoin);
    const conflictReceiver = new PersistentLobbyReceiver(conflictLobby, conflictStore);

    await expect(conflictReceiver.receiveAdmittedJoin(candidateJoin)).resolves.toMatchObject({
      status: "rejected",
      reason: "durable_conflict",
      existing: conflictingJoin,
    });
    expect(conflictLobby.hasSender(ALICE.publicKey)).toBe(false);

    const staleLobby = new LobbyChainRegistry(CONTEXT);
    const staleStore = new MemoryLobbyStore();
    const first = rosterEnvelope(0, ZERO_HASH, [HOST.publicKey]);
    const newer = rosterEnvelope(1, first.hash, [HOST.publicKey, ALICE.publicKey]);
    staleStore.setRosterSnapshot(newer);
    const staleReceiver = new PersistentLobbyReceiver(staleLobby, staleStore);

    await expect(staleReceiver.receiveRoster(first)).rejects.toThrow(
      /Durable roster is ahead/,
    );
    expect(staleLobby.roster).toBeNull();
    expect(staleLobby.headOf(HOST.publicKey)).toBeNull();
  });

  it("rejects invalid artifacts and construction inputs", async () => {
    const lobby = new LobbyChainRegistry(CONTEXT);
    const store = new MemoryLobbyStore();
    const receiver = new PersistentLobbyReceiver(lobby, store);
    const corrupt = joinEnvelope(ALICE);
    const lastIndex = corrupt.canonicalBytes.length - 1;
    corrupt.canonicalBytes[lastIndex] = corrupt.canonicalBytes[lastIndex]! ^ 1;

    await expect(receiver.receiveAdmittedJoin(corrupt)).rejects.toThrow(
      PersistentLobbyReceiverError,
    );
    expect(() => new PersistentLobbyReceiver({} as LobbyChainRegistry, store)).toThrow(TypeError);
    expect(() => new PersistentLobbyReceiver(lobby, {} as AcceptedLobbyEnvelopeStore)).toThrow(
      TypeError,
    );
  });
});

class MemoryLobbyStore implements AcceptedLobbyEnvelopeStore {
  readonly records: EnvelopeArtifact[] = [];
  readonly envelopeCalls: EnvelopeArtifact[] = [];
  readonly rosterCalls: EnvelopeArtifact[] = [];
  rosterSnapshot: EnvelopeArtifact | null = null;
  beforeEnvelopeCommit: (() => Promise<void>) | null = null;
  beforeRosterCommit: (() => Promise<void>) | null = null;
  failNextEnvelope = false;
  failNextRoster = false;

  seed(candidate: EnvelopeArtifact): void {
    const artifact = decodeAndVerifyEnvelope(candidate.canonicalBytes);
    if (this.#find(artifact) === undefined) {
      this.records.push(artifact);
    }
  }

  setRosterSnapshot(candidate: EnvelopeArtifact): void {
    this.rosterSnapshot = decodeAndVerifyEnvelope(candidate.canonicalBytes);
  }

  async persistAcceptedEnvelope(
    candidate: EnvelopeArtifact,
  ): Promise<AcceptedEnvelopePersistenceOutcome> {
    const received = decodeAndVerifyEnvelope(candidate.canonicalBytes);
    this.envelopeCalls.push(received);
    if (this.beforeEnvelopeCommit !== null) {
      await this.beforeEnvelopeCommit();
    }
    if (this.failNextEnvelope) {
      this.failNextEnvelope = false;
      throw new Error("envelope storage failure");
    }
    return this.#persist(received);
  }

  async persistAcceptedRoster(
    _expectedHost: IdentityPublicKey,
    candidate: EnvelopeArtifact,
  ): Promise<AcceptedLobbyRosterPersistenceOutcome> {
    const received = decodeAndVerifyEnvelope(candidate.canonicalBytes);
    this.rosterCalls.push(received);
    if (this.beforeRosterCommit !== null) {
      await this.beforeRosterCommit();
    }
    if (this.failNextRoster) {
      this.failNextRoster = false;
      throw new Error("roster storage failure");
    }

    const transcript = this.#persist(received);
    if (transcript.status === "conflict") {
      return transcript;
    }
    const current = this.rosterSnapshot;
    if (current === null || received.envelope.seq > current.envelope.seq) {
      this.rosterSnapshot = received;
      return {
        status: "stored",
        transcriptStatus: transcript.status,
        snapshot: { artifact: received },
      };
    }
    if (received.envelope.seq < current.envelope.seq) {
      return {
        status: "stale",
        transcriptStatus: transcript.status,
        snapshot: { artifact: current },
      };
    }
    return {
      status: "duplicate",
      transcriptStatus: transcript.status,
      snapshot: { artifact: current },
    };
  }

  #persist(received: EnvelopeArtifact): AcceptedEnvelopePersistenceOutcome {
    const existing = this.#find(received);
    if (existing !== undefined) {
      return bytesEqual(existing.canonicalBytes, received.canonicalBytes)
        ? { status: "duplicate", record: { artifact: existing } }
        : { status: "conflict", existing: { artifact: existing }, received };
    }
    this.records.push(received);
    return { status: "stored", record: { artifact: received } };
  }

  #find(received: EnvelopeArtifact): EnvelopeArtifact | undefined {
    return this.records.find(
      ({ envelope }) =>
        bytesToHex(envelope.game) === bytesToHex(received.envelope.game) &&
        bytesToHex(envelope.from) === bytesToHex(received.envelope.from) &&
        envelope.seq === received.envelope.seq,
    );
  }
}

function readyLobby() {
  const lobby = new LobbyChainRegistry(CONTEXT);
  const store = new MemoryLobbyStore();
  const roster = rosterEnvelope(0, ZERO_HASH, [HOST.publicKey, ALICE.publicKey, BOB.publicKey]);
  const aliceJoin = joinEnvelope(ALICE);
  const bobJoin = joinEnvelope(BOB);
  lobby.ingestRoster(roster);
  lobby.bootstrapJoin(aliceJoin);
  lobby.bootstrapJoin(bobJoin);
  const rosterHash = lobby.rosterHash!;
  const hostReady = readyEnvelope(HOST, 1, roster.hash, rosterHash);
  const aliceReady = readyEnvelope(ALICE, 1, aliceJoin.hash, rosterHash);
  lobby.ingestReady(hostReady);
  lobby.ingestReady(aliceReady);
  for (const artifact of [roster, aliceJoin, bobJoin, hostReady, aliceReady]) {
    store.seed(artifact);
  }
  store.setRosterSnapshot(roster);
  return { lobby, store, roster, aliceJoin, bobJoin, rosterHash };
}

function identity(fill: number): TestIdentity {
  const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(fill));
  return {
    secretKey,
    publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)),
  };
}

function joinEnvelope(
  author: TestIdentity,
  body: {
    readonly pkId: IdentityPublicKey;
    readonly rulesHash: Hash256;
    readonly clientVersion: string;
  } = {
    pkId: author.publicKey,
    rulesHash: RULES_HASH,
    clientVersion: "test/1",
  },
): EnvelopeArtifact {
  return signed(author, {
    seq: 0,
    prev: ZERO_HASH,
    type: "JOIN",
    body: encodeJoinBody(body),
  });
}

function rosterEnvelope(
  seq: number,
  prev: Hash256,
  seats: readonly IdentityPublicKey[],
  author: TestIdentity = HOST,
): EnvelopeArtifact {
  return signed(author, {
    seq,
    prev,
    type: "ROSTER",
    body: encodeRosterBody({
      gameId: GAME_ID,
      rulesHash: RULES_HASH,
      iceConfigHash: ICE_CONFIG_HASH,
      seats,
    }),
  });
}

function readyEnvelope(
  author: TestIdentity,
  seq: number,
  prev: Hash256,
  rosterHash: Hash256,
): EnvelopeArtifact {
  return signed(author, {
    seq,
    prev,
    type: "READY",
    body: encodeReadyBody({ rosterHash }),
  });
}

function signed(
  author: TestIdentity,
  fields: Pick<UnsignedEnvelope, "seq" | "prev" | "type"> & { readonly body: CborValue },
): EnvelopeArtifact {
  return signEnvelope(
    {
      v: 1,
      game: GAME_ID,
      from: author.publicKey,
      seq: fields.seq,
      prev: fields.prev,
      round: 0,
      phase: "lobby",
      type: fields.type,
      body: fields.body,
    },
    author.secretKey,
  );
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}
