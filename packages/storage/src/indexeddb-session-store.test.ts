import {
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  scalarFromBigInt,
  type Ed25519SecretKey,
} from "@p2pcards/crypto";
import {
  encodeJoinBody,
  encodeReadyBody,
  encodeRosterBody,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  signEnvelope,
  type EnvelopeArtifact,
  type GameId,
  type Hash256,
  type IdentityPublicKey,
  type UnsignedEnvelope,
} from "@p2pcards/protocol";
import {
  LobbyChainRegistry,
  PersistentEnvelopeAuthor,
  PersistentLobbyReceiver,
  PersistentSessionReceiver,
  SessionChainRegistry,
  recoverLobby,
  recoverSessionChains,
  type EnvelopeContent,
} from "@p2pcards/session";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { describe, expect, it } from "vitest";

import { GAMES_STORE, openP2pCardsDatabase, TRANSCRIPTS_STORE } from "./database";
import { IndexedDbAuthoredEnvelopeStore } from "./indexeddb-envelope-store";
import { IndexedDbGameSecretStore } from "./indexeddb-game-secret-store";
import { IndexedDbSessionStore, SessionStoreError } from "./indexeddb-session-store";

interface TestIdentity {
  readonly secretKey: Ed25519SecretKey;
  readonly publicKey: IdentityPublicKey;
}

const HOST = identity(1);
const ALICE = identity(2);
const BOB = identity(3);
const GAME_ID = parseGameId(new Uint8Array(16).fill(0x41));
const OTHER_GAME_ID = parseGameId(new Uint8Array(16).fill(0x42));
const RULES_HASH = parseHash256(new Uint8Array(32).fill(0x51));
const ICE_CONFIG_HASH = parseHash256(new Uint8Array(32).fill(0x61));
const ZERO_HASH = parseHash256(new Uint8Array(32));

describe("IndexedDB accepted session storage", () => {
  it("persists accepted incoming envelopes and restores verified artifacts after restart", async () => {
    const factory = new IDBFactory();
    const databaseName = "incoming-restart";
    const first = messageEnvelope(ALICE, 0, ZERO_HASH, "first");
    const second = messageEnvelope(ALICE, 1, first.hash, "second");
    const store = new IndexedDbSessionStore({ factory, databaseName });

    expect(await store.persistAcceptedEnvelope(first)).toMatchObject({
      status: "stored",
      record: { arrival: 1, authored: false },
    });
    expect(await store.persistAcceptedEnvelope(second)).toMatchObject({
      status: "stored",
      record: { arrival: 2, authored: false },
    });
    await store.close();

    const resumed = new IndexedDbSessionStore({ factory, databaseName });
    const records = await resumed.loadTranscript(GAME_ID);
    expect(records.map(({ arrival, authored }) => ({ arrival, authored }))).toEqual([
      { arrival: 1, authored: false },
      { arrival: 2, authored: false },
    ]);
    expect(records.map(({ artifact }) => artifact.hash)).toEqual([first.hash, second.hash]);
    expect(records[1]!.artifact.envelope.prev).toEqual(first.hash);
    await resumed.close();
  });

  it("loads complete sender chains in canonical identity and sequence order", async () => {
    const factory = new IDBFactory();
    const store = new IndexedDbSessionStore({ factory, databaseName: "canonical-transcript" });
    const aliceZero = messageEnvelope(ALICE, 0, ZERO_HASH, "alice zero");
    const aliceOne = messageEnvelope(ALICE, 1, aliceZero.hash, "alice one");
    const bobZero = messageEnvelope(BOB, 0, ZERO_HASH, "bob zero");
    await store.persistAcceptedEnvelope(aliceOne);
    await store.persistAcceptedEnvelope(bobZero);
    await store.persistAcceptedEnvelope(aliceZero);

    const arrival = await store.loadTranscript(GAME_ID);
    const canonical = await store.loadCanonicalEnvelopeTranscript(GAME_ID);
    const expected = [
      [ALICE.publicKey, [aliceZero.hash, aliceOne.hash]],
      [BOB.publicKey, [bobZero.hash]],
    ] as const;
    const expectedHashes = [...expected]
      .sort(([left], [right]) => hexIdentity(left).localeCompare(hexIdentity(right)))
      .flatMap(([, hashes]) => hashes);

    expect(arrival.map(({ artifact }) => artifact.hash)).toEqual([
      aliceOne.hash,
      bobZero.hash,
      aliceZero.hash,
    ]);
    expect(canonical.map(({ artifact }) => artifact.hash)).toEqual(expectedHashes);
    expect(canonical.map(({ arrival }) => arrival).sort((a, b) => a - b)).toEqual([1, 2, 3]);
    await store.close();
  });

  it("is idempotent for the same artifact and surfaces signed sequence conflicts", async () => {
    const factory = new IDBFactory();
    const store = new IndexedDbSessionStore({ factory, databaseName: "incoming-conflict" });
    const first = messageEnvelope(ALICE, 0, ZERO_HASH, "first");
    const conflict = messageEnvelope(ALICE, 0, ZERO_HASH, "conflict");

    expect(await store.persistAcceptedEnvelope(first)).toMatchObject({ status: "stored" });
    expect(await store.persistAcceptedEnvelope(first)).toMatchObject({
      status: "duplicate",
      record: { artifact: first },
    });
    expect(await store.persistAcceptedEnvelope(conflict)).toMatchObject({
      status: "conflict",
      existing: { artifact: first },
      received: conflict,
    });
    expect((await store.loadTranscript(GAME_ID)).map(({ artifact }) => artifact.hash)).toEqual([
      first.hash,
    ]);
    await store.close();
  });

  it("serializes duplicate writes across independent connections", async () => {
    const factory = new IDBFactory();
    const databaseName = "incoming-concurrency";
    const left = new IndexedDbSessionStore({ factory, databaseName });
    const right = new IndexedDbSessionStore({ factory, databaseName });
    const artifact = messageEnvelope(ALICE, 0, ZERO_HASH, "shared");

    const results = await Promise.all([
      left.persistAcceptedEnvelope(artifact),
      right.persistAcceptedEnvelope(artifact),
    ]);
    expect(results.map(({ status }) => status).sort()).toEqual(["duplicate", "stored"]);
    expect(await left.loadTranscript(GAME_ID)).toHaveLength(1);
    await Promise.all([left.close(), right.close()]);
  });

  it("recognizes an existing authored row without changing its provenance", async () => {
    const factory = new IDBFactory();
    const databaseName = "authored-provenance";
    const authoredStore = new IndexedDbAuthoredEnvelopeStore({ factory, databaseName, keyRange: IDBKeyRange });
    const author = new PersistentEnvelopeAuthor(GAME_ID, HOST.secretKey, authoredStore);
    const artifact = await author.author(messageContent("local"));
    const sessionStore = new IndexedDbSessionStore({ factory, databaseName });

    expect(await sessionStore.persistAcceptedEnvelope(artifact)).toMatchObject({
      status: "duplicate",
      record: { authored: true },
    });
    expect(await sessionStore.loadTranscript(GAME_ID)).toMatchObject([{ authored: true }]);
    await Promise.all([authoredStore.close(), sessionStore.close()]);
  });

  it("snapshots input before asynchronous storage and isolates loaded records", async () => {
    const factory = new IDBFactory();
    const databaseName = "incoming-copy";
    const store = new IndexedDbSessionStore({ factory, databaseName });
    const artifact = messageEnvelope(ALICE, 0, ZERO_HASH, "stable");
    const originalBytes = artifact.canonicalBytes.slice();
    const pending = store.persistAcceptedEnvelope(artifact);
    artifact.canonicalBytes.fill(0xff);
    artifact.envelope.prev.fill(0xff);
    await pending;

    const loaded = await store.loadTranscript(GAME_ID);
    expect(loaded[0]!.artifact.canonicalBytes).toEqual(originalBytes);
    loaded[0]!.artifact.canonicalBytes.fill(0xee);
    expect((await store.loadTranscript(GAME_ID))[0]!.artifact.canonicalBytes).toEqual(originalBytes);
    await store.close();
  });

  it("rejects invalid artifacts without creating transcript rows", async () => {
    const factory = new IDBFactory();
    const store = new IndexedDbSessionStore({ factory, databaseName: "incoming-invalid" });
    const artifact = messageEnvelope(ALICE, 0, ZERO_HASH, "tamper");
    const lastIndex = artifact.canonicalBytes.length - 1;
    artifact.canonicalBytes[lastIndex] = artifact.canonicalBytes[lastIndex]! ^ 1;

    await expect(store.persistAcceptedEnvelope(artifact)).rejects.toThrow(SessionStoreError);
    expect(await store.loadTranscript(GAME_ID)).toEqual([]);
    await store.close();
  });

  it("feeds verified durable records into order-independent lobby recovery", async () => {
    const factory = new IDBFactory();
    const store = new IndexedDbSessionStore({ factory, databaseName: "storage-recovery" });
    const roster = rosterEnvelope(0, ZERO_HASH, [HOST.publicKey, ALICE.publicKey, BOB.publicKey]);
    const aliceJoin = joinEnvelope(ALICE);
    const bobJoin = joinEnvelope(BOB);
    await store.persistAcceptedEnvelope(aliceJoin);
    await store.persistAcceptedRoster(HOST.publicKey, roster);
    await store.persistAcceptedEnvelope(bobJoin);

    const records = await store.loadTranscript(GAME_ID);
    const snapshot = await store.loadLobbyRoster(GAME_ID, HOST.publicKey);
    const recovered = recoverLobby(
      {
        gameId: GAME_ID,
        host: HOST.publicKey,
        rulesHash: RULES_HASH,
        iceConfigHash: ICE_CONFIG_HASH,
      },
      records.map(({ artifact }) => artifact),
      snapshot?.artifact ?? null,
    );

    expect(records.map(({ artifact }) => artifact.hash)).toEqual([
      aliceJoin.hash,
      roster.hash,
      bobJoin.hash,
    ]);
    expect(recovered.lobby.state).toBe("collecting_ready");
    expect(recovered.lobby.roster?.seats).toEqual([
      HOST.publicKey,
      ALICE.publicKey,
      BOB.publicKey,
    ]);
    expect(recovered.lobby.headOf(ALICE.publicKey)).toMatchObject({ seq: 0 });
    await store.close();
  });

  it("gates live chain advancement and rebuilds finalized chains after restart", async () => {
    const factory = new IDBFactory();
    const databaseName = "established-recovery";
    const store = new IndexedDbSessionStore({ factory, databaseName });
    const liveRegistry = new SessionChainRegistry(GAME_ID, [
      HOST.publicKey,
      ALICE.publicKey,
      BOB.publicKey,
    ]);
    const receiver = new PersistentSessionReceiver(liveRegistry, store);
    const first = messageEnvelope(ALICE, 0, ZERO_HASH, "first");
    const second = messageEnvelope(ALICE, 1, first.hash, "second");

    await expect(receiver.receive(first)).resolves.toMatchObject({
      status: "accepted",
      persistenceStatus: "stored",
    });
    await expect(receiver.receive(second)).resolves.toMatchObject({
      status: "accepted",
      persistenceStatus: "stored",
    });
    expect(liveRegistry.heads()).toEqual([
      expect.objectContaining({ from: ALICE.publicKey, seq: 1, hash: second.hash }),
    ]);
    await store.close();

    const resumed = new IndexedDbSessionStore({ factory, databaseName });
    const records = await resumed.loadTranscript(GAME_ID);
    const recovered = recoverSessionChains(
      GAME_ID,
      [HOST.publicKey, ALICE.publicKey, BOB.publicKey],
      records.map(({ artifact }) => artifact),
    );
    expect(recovered.envelopeCount).toBe(2);
    expect(recovered.registry.heads()).toEqual([
      expect.objectContaining({ from: ALICE.publicKey, seq: 1, hash: second.hash }),
    ]);
    await resumed.close();
  });

  it("commits a complete lobby before finalization and recovers it after restart", async () => {
    const factory = new IDBFactory();
    const databaseName = "durable-lobby-finalization";
    const store = new IndexedDbSessionStore({ factory, databaseName });
    const lobby = new LobbyChainRegistry({
      gameId: GAME_ID,
      host: HOST.publicKey,
      rulesHash: RULES_HASH,
      iceConfigHash: ICE_CONFIG_HASH,
    });
    const receiver = new PersistentLobbyReceiver(lobby, store);
    const roster = rosterEnvelope(0, ZERO_HASH, [HOST.publicKey, ALICE.publicKey, BOB.publicKey]);
    const aliceJoin = joinEnvelope(ALICE);
    const bobJoin = joinEnvelope(BOB);

    await expect(receiver.receiveRoster(roster)).resolves.toMatchObject({
      status: "accepted",
      rosterSnapshotStatus: "stored",
    });
    await expect(receiver.receiveRosterMemberJoin(aliceJoin)).resolves.toMatchObject({
      status: "accepted",
    });
    await expect(receiver.receiveRosterMemberJoin(bobJoin)).resolves.toMatchObject({
      status: "accepted",
    });
    const rosterHash = lobby.rosterHash!;
    const hostReady = readyEnvelope(HOST, 1, roster.hash, rosterHash);
    const aliceReady = readyEnvelope(ALICE, 1, aliceJoin.hash, rosterHash);
    const bobReady = readyEnvelope(BOB, 1, bobJoin.hash, rosterHash);
    await receiver.receiveReady(hostReady);
    await receiver.receiveReady(aliceReady);
    await expect(receiver.receiveReady(bobReady)).resolves.toMatchObject({
      status: "accepted",
      transition: { state: "finalized" },
    });
    expect(lobby.finalizedRegistry?.heads()).toEqual([
      expect.objectContaining({ from: HOST.publicKey, seq: 1, hash: hostReady.hash }),
      expect.objectContaining({ from: ALICE.publicKey, seq: 1, hash: aliceReady.hash }),
      expect.objectContaining({ from: BOB.publicKey, seq: 1, hash: bobReady.hash }),
    ]);
    await store.close();

    const resumed = new IndexedDbSessionStore({ factory, databaseName });
    const transcript = await resumed.loadTranscript(GAME_ID);
    const snapshot = await resumed.loadLobbyRoster(GAME_ID, HOST.publicKey);
    const recovered = recoverLobby(
      {
        gameId: GAME_ID,
        host: HOST.publicKey,
        rulesHash: RULES_HASH,
        iceConfigHash: ICE_CONFIG_HASH,
      },
      transcript.map(({ artifact }) => artifact),
      snapshot?.artifact ?? null,
    );
    expect(transcript).toHaveLength(6);
    expect(recovered.lobby.state).toBe("finalized");
    expect(recovered.lobby.finalizedRegistry?.heads()).toEqual(
      lobby.finalizedRegistry?.heads(),
    );
    await resumed.close();
  });
});

describe("IndexedDB lobby roster snapshots", () => {
  it("atomically persists the roster transcript row and restores the latest snapshot", async () => {
    const factory = new IDBFactory();
    const databaseName = "roster-restart";
    const roster = rosterEnvelope(0, ZERO_HASH, [HOST.publicKey, ALICE.publicKey]);
    const store = new IndexedDbSessionStore({ factory, databaseName });

    expect(await store.persistAcceptedRoster(HOST.publicKey, roster)).toMatchObject({
      status: "stored",
      transcriptStatus: "stored",
      snapshot: { artifact: roster },
    });
    await store.close();

    const resumed = new IndexedDbSessionStore({ factory, databaseName });
    expect(await resumed.loadLobbyRoster(GAME_ID, HOST.publicKey)).toMatchObject({
      artifact: roster,
      body: { seats: [HOST.publicKey, ALICE.publicKey] },
    });
    expect(await resumed.loadTranscript(GAME_ID)).toMatchObject([
      { authored: false, artifact: roster },
    ]);
    await resumed.close();
  });

  it("updates snapshots monotonically under competing connections", async () => {
    const factory = new IDBFactory();
    const databaseName = "roster-concurrency";
    const older = rosterEnvelope(0, ZERO_HASH, [HOST.publicKey]);
    const newer = rosterEnvelope(1, older.hash, [HOST.publicKey, ALICE.publicKey]);
    const left = new IndexedDbSessionStore({ factory, databaseName });
    const right = new IndexedDbSessionStore({ factory, databaseName });

    await Promise.all([
      left.persistAcceptedRoster(HOST.publicKey, newer),
      right.persistAcceptedRoster(HOST.publicKey, older),
    ]);

    expect(await left.loadLobbyRoster(GAME_ID, HOST.publicKey)).toMatchObject({
      artifact: { envelope: { seq: 1 } },
      body: { seats: [HOST.publicKey, ALICE.publicKey] },
    });
    expect(await left.loadTranscript(GAME_ID)).toHaveLength(2);
    expect(await left.persistAcceptedRoster(HOST.publicKey, older)).toMatchObject({
      status: "stale",
      transcriptStatus: "duplicate",
      snapshot: { artifact: { envelope: { seq: 1 } } },
    });
    await Promise.all([left.close(), right.close()]);
  });

  it("does not replace a snapshot with an equivocating roster at the same sequence", async () => {
    const factory = new IDBFactory();
    const store = new IndexedDbSessionStore({ factory, databaseName: "roster-conflict" });
    const first = rosterEnvelope(0, ZERO_HASH, [HOST.publicKey]);
    const conflict = rosterEnvelope(0, ZERO_HASH, [HOST.publicKey, ALICE.publicKey]);
    await store.persistAcceptedRoster(HOST.publicKey, first);

    expect(await store.persistAcceptedRoster(HOST.publicKey, conflict)).toMatchObject({
      status: "conflict",
      existing: { artifact: first },
      received: conflict,
    });
    expect(await store.loadLobbyRoster(GAME_ID, HOST.publicKey)).toMatchObject({
      artifact: first,
      body: { seats: [HOST.publicKey] },
    });
    expect(await store.loadTranscript(GAME_ID)).toHaveLength(1);
    await store.close();
  });

  it("adds a snapshot for an already durable authored roster without duplicating the transcript", async () => {
    const factory = new IDBFactory();
    const databaseName = "authored-roster";
    const authoredStore = new IndexedDbAuthoredEnvelopeStore({ factory, databaseName, keyRange: IDBKeyRange });
    const author = new PersistentEnvelopeAuthor(GAME_ID, HOST.secretKey, authoredStore);
    const roster = await author.author(rosterContent([HOST.publicKey, ALICE.publicKey]));
    const sessionStore = new IndexedDbSessionStore({ factory, databaseName });

    expect(await sessionStore.persistAcceptedRoster(HOST.publicKey, roster)).toMatchObject({
      status: "stored",
      transcriptStatus: "duplicate",
    });
    expect(await sessionStore.loadTranscript(GAME_ID)).toMatchObject([{ authored: true }]);
    expect(await sessionStore.loadLobbyRoster(GAME_ID, HOST.publicKey)).toMatchObject({
      artifact: roster,
    });
    await Promise.all([authoredStore.close(), sessionStore.close()]);
  });

  it("preserves an existing durable game secret when updating the roster snapshot", async () => {
    const factory = new IDBFactory();
    const databaseName = "roster-preserves-secret";
    const secretStore = new IndexedDbGameSecretStore({ factory, databaseName });
    await secretStore.getOrCreateGameSecret(GAME_ID, () => scalarFromBigInt(17n));
    const sessionStore = new IndexedDbSessionStore({ factory, databaseName });
    await sessionStore.persistAcceptedRoster(
      HOST.publicKey,
      rosterEnvelope(0, ZERO_HASH, [HOST.publicKey]),
    );

    expect(await secretStore.loadGameSecret(GAME_ID)).toBe(17n);
    await Promise.all([secretStore.close(), sessionStore.close()]);
  });

  it("rejects the wrong host, malformed metadata, and mismatched body game", async () => {
    const factory = new IDBFactory();
    const store = new IndexedDbSessionStore({ factory, databaseName: "roster-invalid" });
    const roster = rosterEnvelope(0, ZERO_HASH, [HOST.publicKey]);
    const wrongBodyGame = rosterEnvelope(
      0,
      ZERO_HASH,
      [HOST.publicKey],
      { bodyGame: OTHER_GAME_ID },
    );
    const notRoster = messageEnvelope(HOST, 0, ZERO_HASH, "not roster");

    await expect(store.persistAcceptedRoster(ALICE.publicKey, roster)).rejects.toThrow(
      /expected host/,
    );
    await expect(store.persistAcceptedRoster(HOST.publicKey, wrongBodyGame)).rejects.toThrow(
      /wrong game identifier/,
    );
    await expect(store.persistAcceptedRoster(HOST.publicKey, notRoster)).rejects.toThrow(
      /invalid lobby metadata/,
    );
    expect(await store.loadTranscript(GAME_ID)).toEqual([]);
    expect(await store.loadLobbyRoster(GAME_ID, HOST.publicKey)).toBeNull();
    await store.close();
  });

  it("rejects malformed persisted transcript and roster records during recovery", async () => {
    const factory = new IDBFactory();
    const transcriptDatabaseName = "corrupt-transcript";
    const transcriptDatabase = await openP2pCardsDatabase({
      factory,
      databaseName: transcriptDatabaseName,
    });
    await putRecord(transcriptDatabase, TRANSCRIPTS_STORE, {
      game: hexGame(GAME_ID),
      sender: "00".repeat(32),
      seq: 0,
      bytes: new Uint8Array([0xff]),
      authored: false,
    });
    transcriptDatabase.close();
    const transcriptStore = new IndexedDbSessionStore({
      factory,
      databaseName: transcriptDatabaseName,
    });
    await expect(transcriptStore.loadTranscript(GAME_ID)).rejects.toThrow(SessionStoreError);
    await transcriptStore.close();

    const rosterDatabaseName = "corrupt-roster";
    const rosterDatabase = await openP2pCardsDatabase({ factory, databaseName: rosterDatabaseName });
    await putRecord(rosterDatabase, GAMES_STORE, {
      game: hexGame(GAME_ID),
      lobbyRoster: { host: hexIdentity(HOST.publicKey), seq: 0, bytes: new Uint8Array([0xff]) },
    });
    rosterDatabase.close();
    const rosterStore = new IndexedDbSessionStore({ factory, databaseName: rosterDatabaseName });
    await expect(rosterStore.loadLobbyRoster(GAME_ID, HOST.publicKey)).rejects.toThrow(
      SessionStoreError,
    );
    await rosterStore.close();
  });
});

function identity(fill: number): TestIdentity {
  const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(fill));
  return {
    secretKey,
    publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)),
  };
}

function messageEnvelope(
  author: TestIdentity,
  seq: number,
  prev: Hash256,
  marker: string,
): EnvelopeArtifact {
  return signEnvelope(
    {
      v: 1,
      game: GAME_ID,
      from: author.publicKey,
      seq,
      prev,
      round: 0,
      phase: "lobby",
      type: "READY",
      body: { marker },
    },
    author.secretKey,
  );
}

function joinEnvelope(author: TestIdentity): EnvelopeArtifact {
  return signEnvelope(
    {
      v: 1,
      game: GAME_ID,
      from: author.publicKey,
      seq: 0,
      prev: ZERO_HASH,
      round: 0,
      phase: "lobby",
      type: "JOIN",
      body: encodeJoinBody({
        pkId: author.publicKey,
        rulesHash: RULES_HASH,
        clientVersion: "storage-test/1",
      }),
    },
    author.secretKey,
  );
}

function rosterEnvelope(
  seq: number,
  prev: Hash256,
  seats: readonly IdentityPublicKey[],
  options: { readonly bodyGame?: GameId } = {},
): EnvelopeArtifact {
  return signEnvelope(
    {
      v: 1,
      game: GAME_ID,
      from: HOST.publicKey,
      seq,
      prev,
      round: 0,
      phase: "lobby",
      type: "ROSTER",
      body: encodeRosterBody({
        gameId: options.bodyGame ?? GAME_ID,
        rulesHash: RULES_HASH,
        iceConfigHash: ICE_CONFIG_HASH,
        seats,
      }),
    },
    HOST.secretKey,
  );
}

function readyEnvelope(
  author: TestIdentity,
  seq: number,
  prev: Hash256,
  rosterHash: Hash256,
): EnvelopeArtifact {
  return signEnvelope(
    {
      v: 1,
      game: GAME_ID,
      from: author.publicKey,
      seq,
      prev,
      round: 0,
      phase: "lobby",
      type: "READY",
      body: encodeReadyBody({ rosterHash }),
    },
    author.secretKey,
  );
}

function messageContent(marker: string): EnvelopeContent {
  return {
    round: 0,
    phase: "lobby",
    type: "READY",
    body: { marker },
  };
}

function rosterContent(seats: readonly IdentityPublicKey[]): EnvelopeContent {
  return {
    round: 0,
    phase: "lobby",
    type: "ROSTER",
    body: encodeRosterBody({
      gameId: GAME_ID,
      rulesHash: RULES_HASH,
      iceConfigHash: ICE_CONFIG_HASH,
      seats,
    }),
  };
}

function hexGame(value: GameId): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexIdentity(value: IdentityPublicKey): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function putRecord(database: IDBDatabase, storeName: string, value: object): Promise<void> {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeName, "readwrite");
    transaction.objectStore(storeName).put(value);
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error);
    transaction.onerror = () => reject(transaction.error);
  });
}
