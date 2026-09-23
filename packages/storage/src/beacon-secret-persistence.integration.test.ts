import {
  bytesEqual, bytesToHex, deriveEd25519PublicKey, encodeRistrettoScalar,
  importEd25519SecretKey, RistrettoPoint, scalarFromBigInt, sha256, type RistrettoScalar,
} from "@p2pcards/crypto";
import * as deck from "@p2pcards/deck";
import {
  PersistentSetupReceiver, prepareLocalBeaconContribution,
  prepareLocalGameKeyShare, recoverSetup, restoreLocalBeaconContribution, type BeaconContribution,
} from "@p2pcards/engine";
import * as protocol from "@p2pcards/protocol";
import {
  beaconCommitment, decodeAndVerifyEnvelope, decodeRandCommitBody, decodeRandRevealBody,
  encodeRandCommitBody, encodeRandRevealBody, parseGameId, parseIdentityPublicKey,
  snapshotSetupBeaconScope, type EnvelopeArtifact,
} from "@p2pcards/protocol";
import {
  PersistentEnvelopeAuthor, PersistentSessionReceiver, SessionChainRegistry,
  orderEnvelopeTranscript, recoverSessionChains, replayAuthoredHistory,
} from "@p2pcards/session";
import { IDBFactory, IDBKeyRange, IDBObjectStore } from "fake-indexeddb";
import { afterEach, describe, expect, it, onTestFinished, vi } from "vitest";

import * as protocolRandom from "../../crypto/src/random";
import {
  AUTHORED_HEADS_STORE, GAMES_STORE, IDENTITY_STORE, TRANSCRIPTS_STORE,
  openP2pCardsDatabase, type IndexedDbStoreOptions,
} from "./database";
import { IndexedDbAuthoredEnvelopeStore } from "./indexeddb-envelope-store";
import { IndexedDbGameSecretStore } from "./indexeddb-game-secret-store";
import { IndexedDbSessionStore } from "./indexeddb-session-store";
import { IndexedDbSetupBeaconSecretStore } from "./indexeddb-setup-beacon-secret-store";

const IDENTITIES = [81, 82, 83, 84].map((fill) => {
  const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(fill));
  return { secretKey, publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)) };
});
const ROSTER = IDENTITIES.map(({ publicKey }) => publicKey);
const GAME_ID = parseGameId(new Uint8Array(16).fill(0x63));
const SETUP_ROUND = 0;
type Peer = ReturnType<typeof createPeer>;

afterEach(() => vi.restoreAllMocks());

describe("durable native setup beacon integration (manual fixture phase coordination)", () => {
  it("restarts one of four independent peers after commitment and reveals only its restored secret", async () => {
    const peers = await committedPeers();
    const originals = peers.flatMap((peer) => peer.messages.filter(({ envelope }) =>
      bytesEqual(envelope.from, peer.scope.sender)));
    expect(originals).toHaveLength(8);
    const before = await Promise.all(peers.map(expectStoredPeer));
    const aggregate = RistrettoPoint.base().multiply(scalarFromBigInt(
      peers.reduce((sum, peer) => sum + peer.key!, 0n),
    )).toBytes();

    for (const peer of peers) {
      const snapshot = peer.receiver.snapshot;
      expect(snapshot.state).toBe("rand_reveal");
      expect(snapshot.seed).toBeNull();
      expect(snapshot.aggregateKey).toBe(bytesToHex(aggregate));
      expect(peer.receiver.gameId).toEqual(GAME_ID);
      expect(peer.receiver.round).toBe(SETUP_ROUND);
      expect(peer.receiver.roster).toEqual(ROSTER);
      expect(peer.receiver.self).toEqual(peer.scope.sender);
      expect(Reflect.ownKeys(peer.receiver)).toEqual([]);
      expect(Object.entries(Object.getOwnPropertyDescriptors(Object.getPrototypeOf(peer.receiver)))
        .filter(([, descriptor]) => descriptor.get !== undefined).map(([name]) => name).sort())
        .toEqual(["closed", "failure", "gameId", "pendingBytes", "pendingEnvelopes", "roster", "round", "self", "snapshot"]);
      expect(Object.keys(snapshot).sort()).toEqual(["aggregateKey", "commitments", "pendingSenders", "publicKeys", "seed", "state"]);
      for (const value of [snapshot, snapshot.publicKeys, snapshot.commitments, snapshot.pendingSenders]) {
        expect(Object.isFrozen(value)).toBe(true);
      }
      expect(snapshot).not.toHaveProperty("x");
      expect(snapshot).not.toHaveProperty("s");
      for (const [seat, other] of peers.entries()) {
        expect(snapshot.publicKeys[seat]).toBe(bytesToHex(RistrettoPoint.base().multiply(other.key!).toBytes()));
        expect(snapshot.commitments[seat]).toBe(bytesToHex(other.beacon!.commitment));
      }
    }
    // Validate public field meanings, not byte substrings: zero bytes also occur in public predecessors/proofs.
    for (const original of originals) {
      const { envelope } = decodeAndVerifyEnvelope(original.canonicalBytes);
      const seat = ROSTER.findIndex((identity) => bytesEqual(identity, envelope.from));
      if (envelope.type === "KEY_SHARE") {
        expect(envelope.body).toEqual(deck.encodeGameKeyShareBody(deck.decodeGameKeyShareBody(envelope.body)));
      } else {
        expect(envelope.type).toBe("RAND_COMMIT");
        expect(envelope.body).toEqual({ cm: peers[seat]!.beacon!.commitment });
      }
    }

    const peer = peers[0]!;
    const heads = peer.chains.heads();
    const checkpoint = await peer.authored.readAuthoredHead(GAME_ID, peer.scope.sender);
    expect(checkpoint!.envelope).toMatchObject({ type: "RAND_COMMIT", seq: 1 });
    expect(peer.beacon!.secret).toEqual(new Uint8Array(32));
    const noGeneration = forbidRegeneration();
    const noWrites = forbidAuthoredWrites();
    const persist = vi.spyOn(IndexedDbSessionStore.prototype, "persistAcceptedEnvelope").mockImplementation(forbidden);
    const commit = await reopenAndRecover(peer);
    const load = vi.spyOn(peer.beaconStore, "loadSetupBeaconSecret");
    peer.beacon = await restoreLocalBeaconContribution(peer.scope, peer.beaconStore, decodeRandCommitBody(commit.envelope.body).cm);
    expect(load).toHaveBeenCalledTimes(1);
    expect(load).toHaveBeenCalledWith(peer.scope);
    expect(peer.beacon.secret).toEqual(new Uint8Array(32));
    expect(peer.beacon.commitment).toEqual(decodeRandCommitBody(checkpoint!.envelope.body).cm);
    expect(peer.beacon.commitment).toEqual(beaconCommitment(GAME_ID, SETUP_ROUND, peer.seat, peer.beacon.secret));
    expect(peer.chains.heads()).toEqual(heads);
    expect(peer.receiver.snapshot.state).toBe("rand_reveal");
    expect(peer.receiver.snapshot.seed).toBeNull();
    expect(peer.receiver.snapshot.aggregateKey).toBe(bytesToHex(aggregate));
    expect(await peer.authored.readAuthoredHead(GAME_ID, peer.scope.sender)).toEqual(checkpoint);
    expect(await expectStoredPeer(peer)).toEqual(before[peer.seat]);
    expect(persist).not.toHaveBeenCalled();
    persist.mockRestore();

    const replayed: Uint8Array[] = [];
    await expect(replayAuthoredHistory(peer.authored, GAME_ID, peer.scope.sender, async (bytes) => {
      replayed.push(bytes);
      const original = decodeAndVerifyEnvelope(bytes);
      for (const recipient of peers) {
        await expect(recipient.receiver.receive(original)).resolves.toMatchObject({
          status: "duplicate", chainResult: { status: "duplicate", persistenceStatus: "duplicate" },
        });
      }
    })).resolves.toMatchObject({ status: "replayed", submittedCount: 2, checkpoint: { seq: 1, hash: commit.hash } });
    expect(replayed).toEqual(originals.filter(({ envelope }) => bytesEqual(envelope.from, peer.scope.sender))
      .map(({ canonicalBytes }) => canonicalBytes));
    for (const recipient of peers) {
      expect(recipient.chains.heads()).toEqual(heads);
      expect(recipient.receiver.snapshot.state).toBe("rand_reveal");
      expect(await expectStoredPeer(recipient)).toEqual(before[recipient.seat]);
    }
    for (const spy of [...noGeneration, ...noWrites]) expect(spy).not.toHaveBeenCalled();
    for (const spy of noWrites) spy.mockRestore();

    const sign = vi.spyOn(protocol, "signEnvelope");
    const reveals: EnvelopeArtifact[] = [];
    // Private material is not reveal authorization. Never sign a premature reveal and advance the native checkpoint.
    for (const sender of peers) {
      expect(sender.receiver.snapshot.state).toBe("rand_reveal");
      const artifact = await sender.author.author({
        round: SETUP_ROUND, phase: "setup.rand", type: "RAND_REVEAL",
        body: encodeRandRevealBody({ s: sender.beacon!.secret }),
      });
      const ownCommit = originals.find(({ envelope }) => envelope.type === "RAND_COMMIT" &&
        bytesEqual(envelope.from, sender.scope.sender))!;
      expect(artifact.envelope).toMatchObject({ seq: 2, prev: ownCommit.hash, body: { s: sender.beacon!.secret } });
      expect(decodeRandRevealBody(artifact.envelope.body).s).toEqual(sender.beacon!.secret);
      await expect(sender.receiver.receive(artifact)).resolves.toMatchObject({
        status: "accepted", chainResult: { status: "accepted", persistenceStatus: "duplicate" },
      });
      sender.messages.push(artifact);
      reveals.push(artifact);
    }
    await exchange(peers, [reveals[2]!, reveals[0]!, reveals[3]!, reveals[1]!]);
    originals.push(...reveals);
    const canonical = orderEnvelopeTranscript(GAME_ID, originals).map(({ canonicalBytes }) => canonicalBytes);
    const seed = sha256(...peers.map((sender) => sender.beacon!.secret));
    expect(seed).not.toEqual(sha256(...[2, 0, 3, 1].map((seat) => peers[seat]!.beacon!.secret)));
    expect(new Set(canonical.map(bytesToHex)).size).toBe(12);
    for (const recipient of peers) {
      expect(recipient.receiver.snapshot.state).toBe("complete");
      expect(recipient.receiver.snapshot.aggregateKey).toBe(bytesToHex(aggregate));
      expect(recipient.receiver.snapshot.seed).toBe(bytesToHex(seed));
      expect(recipient.receiver.getCompletedSetup().seed).toEqual(seed);
      expect(recipient.chains.heads()).toEqual(peers[0]!.chains.heads());
      const records = await recipient.store.loadCanonicalEnvelopeTranscript(GAME_ID);
      expect(records).toHaveLength(12);
      expect(records.map(({ artifact }) => artifact.canonicalBytes)).toEqual(canonical);
      expect(records.filter(({ authored }) => authored).map(({ artifact }) => artifact.envelope.type))
        .toEqual(["KEY_SHARE", "RAND_COMMIT", "RAND_REVEAL"]);
      expect(records.filter(({ authored }) => !authored)).toHaveLength(9);
      const stored = await expectStoredPeer(recipient);
      expect(stored[GAMES_STORE]).toEqual(before[recipient.seat]![GAMES_STORE]);
      expect(recipient.keySource.fill).toHaveBeenCalledTimes(2);
      expect(recipient.beaconSource.fill).toHaveBeenCalledTimes(1);
    }
    expect(sign).toHaveBeenCalledTimes(4);
    for (const spy of noGeneration) expect(spy).not.toHaveBeenCalled();
  });

  it("fails closed after an accepted commitment when its private field is missing, corrupt, or mismatched", async () => {
    const peers = await committedPeers();
    const peer = peers[0]!;
    const pristine = await expectStoredPeer(peer);
    const { setupBeaconSecret, ...withoutBeacon } = pristine[GAMES_STORE]![0]!;
    const privateField = setupBeaconSecret as Record<string, unknown>;
    const checkpoint = await peer.authored.readAuthoredHead(GAME_ID, peer.scope.sender);
    const noGeneration = forbidRegeneration();
    for (const [record, error] of [
      [withoutBeacon, { name: "LocalBeaconSecretError", code: "missing_secret" }],
      [{ ...withoutBeacon, setupBeaconSecret: { ...privateField, version: 2 } },
        { name: "SetupBeaconSecretStoreError", message: "IndexedDB contains a malformed setup beacon secret" }],
      [{ ...withoutBeacon, setupBeaconSecret: { ...privateField, secret: new Uint8Array(32).fill(0xff) } },
        { name: "LocalBeaconSecretError", code: "commitment_mismatch" }],
    ] as const) {
      // Fault injection is confined to this test's fresh fake IndexedDB, never user files or a real database.
      const database = await openP2pCardsDatabase(peer.options);
      try {
        await new Promise<void>((resolve, reject) => {
          const transaction = database.transaction(GAMES_STORE, "readwrite");
          transaction.objectStore(GAMES_STORE).put(record);
          transaction.oncomplete = () => resolve();
          transaction.onabort = () => reject(transaction.error);
          transaction.onerror = () => reject(transaction.error);
        });
      } finally { database.close(); }
      const damaged = await databaseContents(peer.options);
      expect(damaged).toEqual({ ...pristine, [GAMES_STORE]: [record] });
      const noWrites = forbidAuthoredWrites();
      const persist = vi.spyOn(IndexedDbSessionStore.prototype, "persistAcceptedEnvelope").mockImplementation(forbidden);
      try {
        const commit = await reopenAndRecover(peer);
        const load = vi.spyOn(peer.beaconStore, "loadSetupBeaconSecret");
        await expect(restoreLocalBeaconContribution(peer.scope, peer.beaconStore, decodeRandCommitBody(commit.envelope.body).cm))
          .rejects.toMatchObject(error);
        expect(load).toHaveBeenCalledTimes(1);
        expect(load).toHaveBeenCalledWith(peer.scope);
        expect(peer.beacon).toBeNull();
        expect(peer.receiver.snapshot.state).toBe("rand_reveal");
        expect(peer.receiver.snapshot.seed).toBeNull();
        expect(await peer.authored.readAuthoredHead(GAME_ID, peer.scope.sender)).toEqual(checkpoint);
        const records = await peer.store.loadTranscript(GAME_ID);
        expect(records).toHaveLength(8);
        expect(records.some(({ artifact }) => artifact.envelope.type === "RAND_REVEAL")).toBe(false);
        expect(await databaseContents(peer.options)).toEqual(damaged);
        for (const spy of [...noGeneration, ...noWrites, persist]) expect(spy).not.toHaveBeenCalled();
      } finally {
        persist.mockRestore();
        for (const spy of noWrites) spy.mockRestore();
      }
    }
  });
});

async function committedPeers(): Promise<Peer[]> {
  // Manual phase barriers and direct original delivery are a fixture, not a shipping setup author/coordinator or transport.
  const peers = ROSTER.map((_, seat) => createPeer(seat));
  expect(new Set(peers.map(({ options }) => options.factory)).size).toBe(4);
  expect(new Set(peers.map(({ options }) => options.databaseName)).size).toBe(4);
  const keys: EnvelopeArtifact[] = [];
  for (const peer of peers) {
    expect(peer.receiver.snapshot.state).toBe("keys");
    const local = await prepareLocalGameKeyShare(
      { gameId: GAME_ID, round: SETUP_ROUND, phase: "setup.keys" }, peer.keyStore, peer.keySource,
    );
    peer.key = local.secret;
    expect(await peer.keyStore.loadGameSecret(GAME_ID)).toBe(local.secret);
    expect(local.secret).toBe(BigInt(11 + peer.seat));
    expect(peer.keySource.fill).toHaveBeenCalledTimes(2);
    await expectStoredPeer(peer);
    const artifact = await peer.author.author({
      round: SETUP_ROUND, phase: "setup.keys", type: "KEY_SHARE", body: deck.encodeGameKeyShareBody(local.share),
    });
    expect(artifact.envelope).toMatchObject({ seq: 0, prev: new Uint8Array(32), from: peer.scope.sender });
    await expect(peer.receiver.receive(artifact)).resolves.toMatchObject({
      status: "accepted", chainResult: { status: "accepted", persistenceStatus: "duplicate" },
    });
    peer.messages.push(artifact);
    keys.push(artifact);
  }
  await exchange(peers, [keys[3]!, keys[1]!, keys[0]!, keys[2]!]);
  expect(peers.map(({ receiver }) => receiver.snapshot.state)).toEqual(Array(4).fill("rand_commit"));
  const commits: EnvelopeArtifact[] = [];
  for (const peer of peers) {
    const before = await expectStoredPeer(peer);
    peer.beacon = await prepareLocalBeaconContribution(peer.scope, peer.beaconStore, peer.beaconSource);
    // Initial preparation is idempotent; recovery below never calls get-or-create.
    expect(await prepareLocalBeaconContribution(peer.scope, peer.beaconStore, peer.beaconSource)).toEqual(peer.beacon);
    expect(peer.beaconSource.fill).toHaveBeenCalledTimes(1);
    expect(peer.beacon.secret).toEqual(new Uint8Array(32).fill(peer.seat));
    expect(peer.beacon.commitment).toEqual(beaconCommitment(GAME_ID, SETUP_ROUND, peer.seat, peer.beacon.secret));
    const after = await expectStoredPeer(peer);
    expect(after).toEqual({ ...before, [GAMES_STORE]: [{
      ...before[GAMES_STORE]![0],
      setupBeaconSecret: { version: 1, round: SETUP_ROUND, sender: peer.scope.sender, roster: ROSTER, secret: peer.beacon.secret },
    }] });
    expect(peer.receiver.snapshot.state).toBe("rand_commit");
    expect(peer.receiver.snapshot.seed).toBeNull();
    const artifact = await peer.author.author({
      round: SETUP_ROUND, phase: "setup.rand", type: "RAND_COMMIT", body: encodeRandCommitBody({ cm: peer.beacon.commitment }),
    });
    expect(artifact.envelope).toMatchObject({ seq: 1, prev: keys[peer.seat]!.hash, from: peer.scope.sender });
    await expect(peer.receiver.receive(artifact)).resolves.toMatchObject({
      status: "accepted", chainResult: { status: "accepted", persistenceStatus: "duplicate" },
    });
    peer.messages.push(artifact);
    commits.push(artifact);
    expect(peer.receiver.snapshot.state).toBe("rand_commit");
  }
  await exchange(peers, [commits[1]!, commits[3]!, commits[2]!, commits[0]!]);
  expect(peers.map(({ receiver }) => receiver.snapshot.state)).toEqual(Array(4).fill("rand_reveal"));
  return peers;
}

function createPeer(seat: number) {
  const options = { factory: new IDBFactory(), databaseName: `beacon-secret-peer-${seat}`, keyRange: IDBKeyRange };
  const store = new IndexedDbSessionStore(options);
  const authored = new IndexedDbAuthoredEnvelopeStore(options);
  const scope = snapshotSetupBeaconScope({ gameId: GAME_ID, round: SETUP_ROUND, roster: ROSTER, sender: ROSTER[seat]! });
  expect(Object.isFrozen(scope)).toBe(true);
  expect(Object.isFrozen(scope.roster)).toBe(true);
  const chains = new SessionChainRegistry(GAME_ID, ROSTER);
  let keyDraws = 0;
  const peer = {
    seat, options, scope, store, authored, chains,
    keyStore: new IndexedDbGameSecretStore(options),
    beaconStore: new IndexedDbSetupBeaconSecretStore(options),
    author: new PersistentEnvelopeAuthor(GAME_ID, IDENTITIES[seat]!.secretKey, authored),
    receiver: new PersistentSetupReceiver({
      round: SETUP_ROUND, self: scope.sender, session: chains, sessionReceiver: new PersistentSessionReceiver(chains, store),
    }),
    key: null as RistrettoScalar | null,
    beacon: null as BeaconContribution | null,
    messages: [] as EnvelopeArtifact[],
    keySource: { fill: vi.fn((target: Uint8Array) => {
      const value = [11 + seat, 31 + seat][keyDraws++];
      if (value === undefined) throw new Error("Game key or proof nonce was regenerated");
      target.fill(0);
      target[0] = value;
    }) },
    beaconSource: { fill: vi.fn((target: Uint8Array) => {
      expect(target).toHaveLength(32);
      target.fill(seat);
    }) },
  };
  onTestFinished(() => closeStores(peer));
  return peer;
}

async function closeStores(peer: Peer): Promise<void> {
  await Promise.all([peer.store.close(), peer.authored.close(), peer.keyStore.close(), peer.beaconStore.close()]);
}

async function reopenAndRecover(peer: Peer): Promise<EnvelopeArtifact> {
  await closeStores(peer);
  peer.key = null;
  peer.beacon = null;
  peer.store = new IndexedDbSessionStore(peer.options);
  peer.authored = new IndexedDbAuthoredEnvelopeStore(peer.options);
  peer.keyStore = new IndexedDbGameSecretStore(peer.options);
  peer.beaconStore = new IndexedDbSetupBeaconSecretStore(peer.options);
  peer.author = new PersistentEnvelopeAuthor(GAME_ID, IDENTITIES[peer.seat]!.secretKey, peer.authored);
  peer.key = await peer.keyStore.loadGameSecret(GAME_ID);
  expect(peer.key).toBe(BigInt(11 + peer.seat));
  const records = await peer.store.loadTranscript(GAME_ID);
  const transcript = records.map(({ artifact }) => artifact).reverse();
  peer.chains = recoverSessionChains(GAME_ID, ROSTER, transcript).registry;
  const recovered = recoverSetup(GAME_ID, SETUP_ROUND, ROSTER, transcript);
  expect(recovered.setupEnvelopeCount).toBe(8);
  peer.receiver = new PersistentSetupReceiver({
    round: SETUP_ROUND, self: peer.scope.sender, session: peer.chains,
    sessionReceiver: new PersistentSessionReceiver(peer.chains, peer.store),
  });
  expect(peer.receiver.snapshot.state).toBe(recovered.coordinator.state);
  expect(peer.receiver.snapshot.aggregateKey).toBe(bytesToHex(recovered.coordinator.aggregateKey!.toBytes()));
  const ownCommit = records.find(({ artifact, authored }) => authored && artifact.envelope.type === "RAND_COMMIT" &&
    bytesEqual(artifact.envelope.from, peer.scope.sender));
  if (ownCommit === undefined) throw new Error("Missing durable local commitment");
  const commit = decodeAndVerifyEnvelope(ownCommit.artifact.canonicalBytes);
  expect(commit.envelope).toMatchObject({ game: GAME_ID, from: peer.scope.sender, round: SETUP_ROUND, phase: "setup.rand", seq: 1 });
  expect(peer.chains.classify(commit)).toMatchObject({ status: "duplicate" });
  expect(recovered.coordinator.classify(commit)).toMatchObject({ status: "duplicate", seat: peer.seat, state: "rand_reveal" });
  return commit;
}

async function exchange(peers: readonly Peer[], originals: readonly EnvelopeArtifact[]) {
  for (const artifact of originals) {
    for (const peer of peers.filter(({ scope }) => !bytesEqual(scope.sender, artifact.envelope.from))) {
      await expect(peer.receiver.receive(artifact)).resolves.toMatchObject({
        status: "accepted", chainResult: { status: "accepted", persistenceStatus: "stored" },
      });
      peer.messages.push(artifact);
    }
  }
}

async function expectStoredPeer(peer: Peer) {
  const game = bytesToHex(GAME_ID);
  const sender = bytesToHex(peer.scope.sender);
  const own = peer.messages.filter(({ envelope }) => bytesEqual(envelope.from, peer.scope.sender));
  expect(await peer.store.loadTranscript(GAME_ID)).toEqual(peer.messages.map((artifact, index) => ({
    arrival: index + 1, artifact, authored: bytesEqual(artifact.envelope.from, peer.scope.sender),
  })));
  expect(await peer.authored.readAuthoredHead(GAME_ID, peer.scope.sender)).toEqual(own.at(-1) ?? null);
  const stored = await databaseContents(peer.options);
  expect(stored).toEqual({
    [GAMES_STORE]: [{ game, gameSecret: encodeRistrettoScalar(peer.key!), ...(peer.beacon === null ? {} : {
      setupBeaconSecret: { version: 1, round: SETUP_ROUND, sender: peer.scope.sender, roster: ROSTER, secret: peer.beacon.secret },
    }) }],
    [IDENTITY_STORE]: [],
    [AUTHORED_HEADS_STORE]: own.length === 0 ? [] : [{ game, sender, bytes: own.at(-1)!.canonicalBytes }],
    [TRANSCRIPTS_STORE]: peer.messages.map(({ envelope, canonicalBytes }, index) => ({
      arrival: index + 1, game, sender: bytesToHex(envelope.from), seq: envelope.seq,
      bytes: canonicalBytes, authored: bytesEqual(envelope.from, peer.scope.sender),
    })),
  });
  return stored;
}

async function databaseContents(options: IndexedDbStoreOptions): Promise<Record<string, Record<string, unknown>[]>> {
  const database = await openP2pCardsDatabase(options);
  try {
    return await new Promise((resolve, reject) => {
      const names = Array.from(database.objectStoreNames);
      const transaction = database.transaction(names, "readonly");
      const requests = names.map((name) => [name, transaction.objectStore(name).getAll()] as const);
      transaction.oncomplete = () => resolve(Object.fromEntries(requests.map(([name, request]) => [name, request.result])));
      transaction.onabort = () => reject(transaction.error);
      transaction.onerror = () => reject(transaction.error);
    });
  } finally { database.close(); }
}

function forbidden(): never { throw new Error("Recovery/replay must not generate secrets, proofs, signatures, or writes"); }

function forbidRegeneration() {
  return [
    // Protocol RNG, not the native curve library's internal verification blinding.
    vi.spyOn(protocolRandom, "randomBytes").mockImplementation(forbidden),
    vi.spyOn(deck, "createGameKeyShare").mockImplementation(forbidden),
    vi.spyOn(IndexedDbGameSecretStore.prototype, "getOrCreateGameSecret").mockImplementation(forbidden),
    vi.spyOn(IndexedDbSetupBeaconSecretStore.prototype, "getOrCreateSetupBeaconSecret").mockImplementation(forbidden),
  ];
}

function forbidAuthoredWrites() {
  return [
    vi.spyOn(protocol, "signEnvelope").mockImplementation(forbidden),
    vi.spyOn(PersistentEnvelopeAuthor.prototype, "author").mockImplementation(forbidden),
    vi.spyOn(IndexedDbAuthoredEnvelopeStore.prototype, "appendNext").mockImplementation(forbidden),
    ...(["add", "put", "delete", "clear"] as const).map((method) =>
      vi.spyOn(IDBObjectStore.prototype, method).mockImplementation(forbidden)),
  ];
}
