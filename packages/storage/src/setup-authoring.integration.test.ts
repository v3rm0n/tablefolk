import {
  bytesEqual, bytesToHex, deriveEd25519PublicKey, encodeRistrettoScalar, importEd25519SecretKey,
  RistrettoPoint, scalarFromBigInt, sha256, type RistrettoScalar,
} from "@p2pcards/crypto";
import * as deck from "@p2pcards/deck";
import {
  PersistentSetupReceiver, SetupEnvelopeCoordinator, type PersistentSetupSnapshot,
} from "@p2pcards/engine";
import { PersistentSaskuRoundReceiver } from "@p2pcards/game-sasku";
import * as protocol from "@p2pcards/protocol";
import {
  beaconCommitment, decodeAndVerifyEnvelope, parseGameId, parseIdentityPublicKey, parseRandomSecret, snapshotSetupBeaconScope,
  type EnvelopeArtifact, type IdentityPublicKey,
} from "@p2pcards/protocol";
import { SASKU_DECK_SPEC } from "@p2pcards/rules-sasku";
import {
  PersistentEnvelopeAuthor, PersistentSessionReceiver, SessionChainRegistry,
  orderEnvelopeTranscript, recoverSessionChains, replayAuthoredHistory,
} from "@p2pcards/session";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
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

const IDENTITIES = [91, 92, 93, 94].map((fill) => {
  const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(fill));
  return { secretKey, publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)) };
});
const ROSTER = IDENTITIES.map(({ publicKey }) => publicKey);
const GAME_ID = parseGameId(new Uint8Array(16).fill(0x64));
const ROUND = 0;
const KEYS = ROSTER.map((_, seat) => scalarFromBigInt(BigInt(11 + seat)));
const PUBLIC_KEYS = KEYS.map((key) => bytesToHex(RistrettoPoint.base().multiply(key).toBytes()));
const BEACON_SECRETS = ROSTER.map((_, seat) => parseRandomSecret(new Uint8Array(32).fill(seat)));
const COMMITMENTS = BEACON_SECRETS.map((secret, seat) => beaconCommitment(GAME_ID, ROUND, seat, secret));
const AGGREGATE = RistrettoPoint.base().multiply(scalarFromBigInt(KEYS.reduce((sum, key) => sum + key, 0n)));
const SEED = sha256(...BEACON_SECRETS);
const TYPES = ["KEY_SHARE", "RAND_COMMIT", "RAND_REVEAL"] as const;
const STATES = ["keys", "rand_commit", "rand_reveal", "complete"] as const;
type SetupType = typeof TYPES[number];
type ReadonlyPubKey = Readonly<IdentityPublicKey>;
type Peer = ReturnType<typeof createPeer>;

afterEach(() => vi.restoreAllMocks());

describe("four-peer setup authoring with native IndexedDB history (direct fixture phase barriers)", () => {
  it("authors 12 originals, restores a committed beacon without generation, and hands off the completed core", async () => {
    const peers = createPeers();
    const createProof = deck.createGameKeyShare;
    const proof = vi.spyOn(deck, "createGameKeyShare").mockImplementation((context, key, source) => {
      const peer = peers[KEYS.indexOf(key)]!;
      // Observe the real transaction's completion, not a mocked secret-store return value.
      expect(peer.io.gameCommits).toBe(1);
      expect(peer.keySource.fill).toHaveBeenCalledTimes(1);
      expect(context).toEqual({ gameId: GAME_ID, round: ROUND, phase: "setup.keys" });
      return createProof(context, key, source);
    });
    const commitment = protocol.beaconCommitment;
    vi.spyOn(protocol, "beaconCommitment").mockImplementation((game, round, seat, secret) => {
      expect(peers[seat]!.io.gameCommits).toBe(2);
      return commitment(game, round, seat, secret);
    });
    const signEnvelope = protocol.signEnvelope;
    const sign = vi.spyOn(protocol, "signEnvelope").mockImplementation((envelope, secretKey) => {
      const peer = peers[seatOf(envelope.from)]!;
      expect(peer.io.gameCommits).toBe(envelope.type === "KEY_SHARE" ? 1 : 2);
      expect(peer.keySource.fill).toHaveBeenCalledTimes(2);
      expect(peer.receiver.snapshot.state).toBe(STATES[TYPES.indexOf(envelope.type as SetupType)]);
      expect(secretKey).toEqual(IDENTITIES[peer.seat]!.secretKey);
      expect(envelope.game).toEqual(peer.receiver.gameId);
      return signEnvelope(envelope, secretKey);
    });

    const first = peers[0]!;
    first.io.access = "none";
    try {
      await expect(submit(first, "RAND_COMMIT")).rejects.toMatchObject({ code: "wrong_phase" });
      await expect(submit(first, "RAND_REVEAL")).rejects.toMatchObject({ code: "wrong_phase" });
    } finally { first.io.access = "all"; }
    expect(first.keySource.fill).not.toHaveBeenCalled();
    expect(first.beaconSource.fill).not.toHaveBeenCalled();

    await phase(peers, "KEY_SHARE");
    const keyRows = await Promise.all(peers.map(expectStoredPeer));
    await phase(peers, "RAND_COMMIT");
    for (const peer of peers) {
      const stored = await expectStoredPeer(peer);
      expect(stored[GAMES_STORE]).toEqual([{
        ...keyRows[peer.seat]![GAMES_STORE]![0],
        setupBeaconSecret: { version: 1, round: ROUND, sender: peer.scope.sender, roster: ROSTER, secret: BEACON_SECRETS[peer.seat] },
      }]);
    }

    const before = first.receiver.snapshot;
    const heads = first.chains.heads();
    await reopenAndRecover(first);
    expect(first.receiver.snapshot).toEqual(before);
    expect(first.chains.heads()).toEqual(heads);
    expect(proof).toHaveBeenCalledTimes(4);
    expect(sign).toHaveBeenCalledTimes(8);
    const loadBeacon = vi.spyOn(first.beaconStore, "loadSetupBeaconSecret");
    const noCreate = [
      vi.spyOn(first.keyStore, "getOrCreateGameSecret").mockImplementation(forbidden),
      vi.spyOn(first.keyStore, "loadGameSecret").mockImplementation(forbidden),
      vi.spyOn(first.beaconStore, "getOrCreateSetupBeaconSecret").mockImplementation(forbidden),
    ];
    try {
      await phase(peers, "RAND_REVEAL");
      expect(loadBeacon).toHaveBeenCalledExactlyOnceWith(first.scope);
      expect(loadBeacon.mock.settledResults[0]).toEqual({ type: "fulfilled", value: new Uint8Array(32) });
      for (const spy of noCreate) expect(spy).not.toHaveBeenCalled();
    } finally { for (const spy of noCreate) spy.mockRestore(); }
    expect(proof).toHaveBeenCalledTimes(4);
    expect(sign).toHaveBeenCalledTimes(12);
    await expectCompleted(peers);

    const duplicate = first.receiver.receive(first.messages[0]!);
    expect(() => first.receiver.getCompletedSetup()).toThrow(expect.objectContaining({ code: "setup_incomplete" }));
    await expect(duplicate).resolves.toMatchObject({ status: "duplicate" });
    await first.receiver.whenIdle();

    // Explicitly trusted fixture deck, schedule, and dealer: no shuffle provenance or production dealer policy.
    const table = new deck.CardPointTable(SASKU_DECK_SPEC);
    const testDeck = Array.from({ length: table.size }, (_, pos) =>
      deck.maskCard(table.pointAt(pos), scalarFromBigInt(BigInt(101 + pos)), AGGREGATE));
    const schedule = [0, 1, 2, 3].map((to) => ({ to, count: 9 }));
    for (const peer of peers) {
      await peer.receiver.whenIdle();
      const setup = peer.receiver.getCompletedSetup();
      expect(setup).toBeInstanceOf(SetupEnvelopeCoordinator);
      expect(peer.receiver.getCompletedSetup()).toBe(setup);
      peer.receiver.close();
      const game = new PersistentSaskuRoundReceiver({
        setup, round: 1, deck: testDeck, schedule, dealer: 3, session: peer.chains, sessionReceiver: peer.sessionReceiver,
      });
      try {
        expect(game.isBoundTo(peer.chains)).toBe(true);
        expect(game.snapshot.hand).toMatchObject({ dealer: 3 });
        expect(game.snapshot.ledger).toEqual({
          phase: "round.1.deal.0", dealIndex: 0, actionIndex: 0, revealed: {},
          deal: { to: 0, positions: [0, 1, 2, 3, 4, 5, 6, 7, 8], pendingSenders: [1, 2, 3] },
        });
        const key = await peer.keyStore.loadGameSecret(GAME_ID);
        expect(key).toBe(KEYS[peer.seat]);
        expect(game.readPrivateHand(peer.scope.sender, key!)).toBeNull();
        expect(Array.from({ length: 36 }, (_, pos) => game.ownerAt(pos)))
          .toEqual([0, 1, 2, 3].flatMap((seat) => Array<number>(9).fill(seat)));
      } finally { game.close(); }
    }
  }, 15_000);

  it.each(TYPES)("recovers an authored-but-unapplied %s without signing or consuming randomness again", async (type) => {
    const peers = createPeers();
    const sign = vi.spyOn(protocol, "signEnvelope");
    const proof = vi.spyOn(deck, "createGameKeyShare");
    const random = vi.spyOn(protocolRandom, "randomBytes");
    const rank = TYPES.indexOf(type);
    for (const earlier of TYPES.slice(0, rank)) await phase(peers, earlier);
    const peer = peers[0]!;
    const before = peer.receiver.snapshot;
    const heads = peer.chains.heads();
    const previous = await peer.authored.readAuthoredHead(GAME_ID, peer.scope.sender);
    const diskFailure = new Error(`Local ${type} receipt failed after the native append committed`);
    const returned = vi.fn();
    const receipt = vi.spyOn(peer.store, "persistAcceptedEnvelope").mockImplementationOnce(async (artifact) => {
      expect(await peer.authored.readAuthoredHead(GAME_ID, peer.scope.sender)).toEqual(artifact);
      const records = await peer.store.loadTranscript(GAME_ID);
      expect(records).toHaveLength(peer.messages.length + 1);
      expect(records.at(-1)).toEqual({ arrival: records.length, artifact, authored: true });
      expect(peer.receiver.snapshot).toBe(before);
      expect(peer.chains.heads()).toEqual(heads);
      throw diskFailure;
    });
    await expect(submit(peer, type).then(returned)).rejects.toMatchObject({ code: "recovery_required", cause: diskFailure });
    expect(returned).not.toHaveBeenCalled();
    expect(receipt).toHaveBeenCalledTimes(1);
    receipt.mockRestore();
    expect(peer.receiver.failure).toMatchObject({ code: "recovery_required", cause: diskFailure });
    expect(peer.receiver.snapshot).toBe(before);
    expect(peer.chains.heads()).toEqual(heads);
    expect(peer.receiver.pendingBytes).toBe(0);
    expect(peer.receiver.pendingEnvelopes).toBe(0);
    const original = (await peer.authored.readAuthoredHead(GAME_ID, peer.scope.sender))!;
    expect(original.envelope).toMatchObject({
      type, from: peer.scope.sender, seq: (previous?.envelope.seq ?? -1) + 1, prev: previous?.hash ?? new Uint8Array(32),
    });
    peer.messages.push(original);
    const stored = await expectStoredPeer(peer);
    const counts = [sign.mock.calls.length, proof.mock.calls.length, random.mock.calls.length];
    const draws = [peer.keySource.fill.mock.calls.length, peer.beaconSource.fill.mock.calls.length];
    peer.io.access = "none";
    try {
      for (const next of TYPES) await expect(submit(peer, next)).rejects.toBe(peer.receiver.failure);
      await expect(peer.receiver.receive(original)).rejects.toBe(peer.receiver.failure);
      expect(() => peer.receiver.getCompletedSetup()).toThrow(peer.receiver.failure!);
    } finally { peer.io.access = "all"; }

    // Replacing just the owner is insufficient: the native head is ahead of this unrestored registry.
    const unrestored = new PersistentSetupReceiver({
      round: ROUND, self: peer.scope.sender, session: peer.chains, sessionReceiver: peer.sessionReceiver,
    });
    const readHead = vi.spyOn(peer.author, "readHead");
    const untouched = [
      vi.spyOn(peer.keyStore, "getOrCreateGameSecret").mockImplementation(forbidden),
      vi.spyOn(peer.beaconStore, "getOrCreateSetupBeaconSecret").mockImplementation(forbidden),
      vi.spyOn(peer.beaconStore, "loadSetupBeaconSecret").mockImplementation(forbidden),
      vi.spyOn(peer.author, "author").mockImplementation(forbidden),
    ];
    peer.io.access = "readonly";
    try {
      await expect(submit(peer, type, unrestored)).rejects.toMatchObject({ code: "recovery_required" });
      expect(readHead).toHaveBeenCalledTimes(1);
      expect(unrestored.failure).toMatchObject({ code: "recovery_required" });
      for (const spy of untouched) expect(spy).not.toHaveBeenCalled();
    } finally {
      unrestored.close();
      readHead.mockRestore();
      for (const spy of untouched) spy.mockRestore();
      peer.io.access = "all";
    }

    await reopenAndRecover(peer);
    expect(peer.receiver.snapshot).toEqual({
      ...before, pendingSenders: before.pendingSenders.filter((seat) => seat !== peer.seat),
      ...(type === "KEY_SHARE" ? { publicKeys: [PUBLIC_KEYS[0], null, null, null] } : {}),
      ...(type === "RAND_COMMIT" ? { commitments: [bytesToHex(COMMITMENTS[0]!), null, null, null] } : {}),
    });
    const consumed = peer.receiver.snapshot;
    const noAccess = [
      vi.spyOn(peer.author, "readHead").mockImplementation(forbidden),
      vi.spyOn(peer.author, "author").mockImplementation(forbidden),
      vi.spyOn(peer.authored, "appendNext").mockImplementation(forbidden),
      vi.spyOn(peer.keyStore, "getOrCreateGameSecret").mockImplementation(forbidden),
      vi.spyOn(peer.beaconStore, "getOrCreateSetupBeaconSecret").mockImplementation(forbidden),
      vi.spyOn(peer.beaconStore, "loadSetupBeaconSecret").mockImplementation(forbidden),
    ];
    peer.io.access = "none";
    try {
      await expect(submit(peer, type)).rejects.toMatchObject({ code: "already_contributed" });
      await expect(submit(peer, type, peer.receiver, before)).rejects.toMatchObject({ code: "stale_setup" });
      for (const spy of noAccess) expect(spy).not.toHaveBeenCalled();
    } finally { peer.io.access = "readonly"; }

    const replayed: Uint8Array[] = [];
    try {
      await expect(replayAuthoredHistory(peer.authored, GAME_ID, peer.scope.sender, async (bytes) => {
        replayed.push(bytes);
        for (const recipient of peers.slice(1)) await deliver(recipient, decodeAndVerifyEnvelope(bytes));
      })).resolves.toMatchObject({
        status: "replayed", submittedCount: rank + 1, checkpoint: { seq: original.envelope.seq, hash: original.hash },
      });
      expect(replayed).toEqual(peer.messages.filter(({ envelope }) => seatOf(envelope.from) === peer.seat)
        .map(({ canonicalBytes }) => canonicalBytes));
      expect(replayed.at(-1)).toEqual(original.canonicalBytes);
      expect(peer.receiver.snapshot).toBe(consumed);
      expect(await databaseContents(peer.options)).toEqual(stored);
      expect(await peer.authored.readAuthoredHead(GAME_ID, peer.scope.sender)).toEqual(original);
      for (const recipient of peers) {
        expect(recipient.receiver.snapshot).toEqual(consumed);
        expect(recipient.chains.heads()).toEqual(peer.chains.heads());
      }
      for (const spy of noAccess) expect(spy).not.toHaveBeenCalled();
      expect([sign.mock.calls.length, proof.mock.calls.length, random.mock.calls.length]).toEqual(counts);
      expect([peer.keySource.fill.mock.calls.length, peer.beaconSource.fill.mock.calls.length]).toEqual(draws);
    } finally {
      for (const spy of noAccess) spy.mockRestore();
      peer.io.access = "all";
    }
    await phase(peers, type, original);
    for (const later of TYPES.slice(rank + 1)) await phase(peers, later);
    expect(sign).toHaveBeenCalledTimes(12);
    expect(proof).toHaveBeenCalledTimes(4);
    await expectCompleted(peers);
  }, 15_000);

  it.each(["missing", "mismatched"] as const)("does not regenerate a %s beacon preimage after restart", async (damage) => {
    const peers = createPeers();
    await phase(peers, "KEY_SHARE");
    await phase(peers, "RAND_COMMIT");
    const peer = peers[0]!;
    const pristine = await expectStoredPeer(peer);
    const { setupBeaconSecret, ...withoutBeacon } = pristine[GAMES_STORE]![0]!;
    const record = damage === "missing" ? withoutBeacon : {
      ...withoutBeacon, setupBeaconSecret: { ...setupBeaconSecret as Record<string, unknown>, secret: new Uint8Array(32).fill(0xff) },
    };
    // Fault injection only in this peer's fresh fake database, preserving its key and authored history.
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
    await reopenAndRecover(peer);
    const before = peer.receiver.snapshot;
    const checkpoint = await peer.authored.readAuthoredHead(GAME_ID, peer.scope.sender);
    const load = vi.spyOn(peer.beaconStore, "loadSetupBeaconSecret");
    const forbiddenCalls = [
      vi.spyOn(peer.keyStore, "getOrCreateGameSecret").mockImplementation(forbidden),
      vi.spyOn(peer.keyStore, "loadGameSecret").mockImplementation(forbidden),
      vi.spyOn(peer.beaconStore, "getOrCreateSetupBeaconSecret").mockImplementation(forbidden),
      vi.spyOn(peer.author, "author").mockImplementation(forbidden),
      vi.spyOn(peer.authored, "appendNext").mockImplementation(forbidden),
      vi.spyOn(peer.store, "persistAcceptedEnvelope").mockImplementation(forbidden),
      vi.spyOn(protocol, "signEnvelope").mockImplementation(forbidden),
      vi.spyOn(deck, "createGameKeyShare").mockImplementation(forbidden),
      vi.spyOn(protocolRandom, "randomBytes").mockImplementation(forbidden),
    ];
    peer.io.access = "readonly";
    await expect(submit(peer, "RAND_REVEAL")).rejects.toMatchObject({
      name: "LocalBeaconSecretError", code: damage === "missing" ? "missing_secret" : "commitment_mismatch",
    });
    expect(load).toHaveBeenCalledExactlyOnceWith(peer.scope);
    expect(peer.receiver.snapshot).toBe(before);
    expect(peer.receiver.snapshot.state).toBe("rand_reveal");
    expect(peer.receiver.snapshot.seed).toBeNull();
    expect(peer.receiver.pendingEnvelopes).toBe(0);
    expect(peer.receiver.pendingBytes).toBe(0);
    expect(await peer.authored.readAuthoredHead(GAME_ID, peer.scope.sender)).toEqual(checkpoint);
    expect(await databaseContents(peer.options)).toEqual(damaged);
    for (const recipient of peers) {
      expect((await recipient.store.loadTranscript(GAME_ID)).map(({ artifact }) => artifact.envelope.type))
        .toEqual(["KEY_SHARE", "KEY_SHARE", "KEY_SHARE", "KEY_SHARE", "RAND_COMMIT", "RAND_COMMIT", "RAND_COMMIT", "RAND_COMMIT"]);
      expect(recipient.keySource.fill).toHaveBeenCalledTimes(2);
      expect(recipient.beaconSource.fill).toHaveBeenCalledTimes(1);
    }
    for (const spy of forbiddenCalls) expect(spy).not.toHaveBeenCalled();
  }, 15_000);

  it("extends four native lobby WITNESS prefixes: 12 setup originals plus 4 prefixes, not setup genesis", async () => {
    const peers = createPeers();
    const sign = vi.spyOn(protocol, "signEnvelope");
    const prefixes: EnvelopeArtifact[] = [];
    // Caller-validated housekeeping fixture, not JOIN/bootstrap or a lobby agreement protocol.
    for (const peer of peers) {
      const prefix = await peer.author.author({ round: ROUND, phase: "lobby", type: "WITNESS", body: { heads: [] } });
      await expect(peer.sessionReceiver.receive(prefix)).resolves.toMatchObject({ status: "accepted", persistenceStatus: "duplicate" });
      peer.messages.push(prefix);
      prefixes.push(prefix);
    }
    for (const prefix of prefixes) {
      for (const peer of peers.filter(({ seat }) => seat !== seatOf(prefix.envelope.from))) {
        await expect(peer.sessionReceiver.receive(prefix)).resolves.toMatchObject({ status: "accepted", persistenceStatus: "stored" });
        peer.messages.push(prefix);
      }
    }
    for (const peer of peers) {
      await reopenAndRecover(peer);
      expect(peer.receiver.snapshot.state).toBe("keys");
      expect(peer.receiver.snapshot.pendingSenders).toEqual([0, 1, 2, 3]);
      expect(peer.keySource.fill).not.toHaveBeenCalled();
      expect(peer.beaconSource.fill).not.toHaveBeenCalled();
    }
    for (const type of TYPES) await phase(peers, type);
    for (const peer of peers) {
      const ownKey = peer.messages.find(({ envelope }) => envelope.type === "KEY_SHARE" && seatOf(envelope.from) === peer.seat)!;
      expect(ownKey.envelope).toMatchObject({ seq: 1, prev: prefixes[peer.seat]!.hash });
    }
    expect(sign).toHaveBeenCalledTimes(16);
    await expectCompleted(peers, 4);
  }, 15_000);
});

function createPeers(): Peer[] {
  const peers = ROSTER.map((_, seat) => createPeer(seat));
  expect(new Set(peers.map(({ options }) => options.factory)).size).toBe(4);
  expect(new Set(peers.map(({ options }) => options.databaseName)).size).toBe(4);
  return peers;
}

function createPeer(seat: number) {
  const factory = new IDBFactory();
  const options = { factory, databaseName: `setup-authoring-peer-${seat}`, keyRange: IDBKeyRange };
  const io = { access: "all" as "all" | "readonly" | "none", transactions: [] as IDBTransaction[], gameCommits: 0 };
  const open = factory.open.bind(factory);
  const opening = vi.spyOn(factory, "open").mockImplementation((...args) => {
    expect(io.access).not.toBe("none");
    const request = open(...args);
    request.addEventListener("success", () => {
      const database = request.result;
      const transact = database.transaction.bind(database);
      vi.spyOn(database, "transaction").mockImplementation((...args) => {
        expect(io.access).not.toBe("none");
        if (io.access === "readonly") expect(args[1] ?? "readonly").toBe("readonly");
        const transaction = transact(...args);
        io.transactions.push(transaction);
        if (transaction.mode === "readwrite" && transaction.objectStoreNames.contains(GAMES_STORE)) {
          transaction.addEventListener("complete", () => { io.gameCommits += 1; });
        }
        return transaction;
      });
    });
    return request;
  });
  const store = new IndexedDbSessionStore(options);
  const authored = new IndexedDbAuthoredEnvelopeStore(options);
  const keyStore = new IndexedDbGameSecretStore(options);
  const beaconStore = new IndexedDbSetupBeaconSecretStore(options);
  const author = new PersistentEnvelopeAuthor(GAME_ID, IDENTITIES[seat]!.secretKey, authored);
  const chains = new SessionChainRegistry(GAME_ID, ROSTER);
  const sessionReceiver = new PersistentSessionReceiver(chains, store);
  const scope = snapshotSetupBeaconScope({ gameId: GAME_ID, round: ROUND, roster: ROSTER, sender: ROSTER[seat]! });
  let keyDraws = 0;
  const peer = {
    seat, options, io, opening, store, authored, keyStore, beaconStore, author, chains, sessionReceiver, scope,
    receiver: new PersistentSetupReceiver({ round: ROUND, self: scope.sender, session: chains, sessionReceiver }),
    key: null as RistrettoScalar | null,
    messages: [] as EnvelopeArtifact[],
    keySource: { fill: vi.fn((target: Uint8Array) => {
      const value = [11 + seat, 31 + seat][keyDraws++];
      if (value === undefined) throw new Error("Key scalar or proof nonce was regenerated");
      target.fill(0);
      target[0] = value;
    }) },
    beaconSource: { fill: vi.fn((target: Uint8Array) => {
      expect(target).toHaveLength(32);
      target.set(BEACON_SECRETS[seat]!);
    }) },
  };
  expect(author.sender).toEqual(peer.receiver.self);
  expect(author.gameId).toEqual(peer.receiver.gameId);
  expect(peer.receiver.roster).toEqual(ROSTER);
  expect(peer.receiver.isBoundTo(chains)).toBe(true);
  expectProgress(peer);
  onTestFinished(() => closePeer(peer));
  return peer;
}

function submit(peer: Peer, type: SetupType, receiver = peer.receiver, snapshot = receiver.snapshot) {
  switch (type) {
    case "KEY_SHARE": return receiver.authorKeyShare(peer.author, peer.keyStore, snapshot, peer.keySource);
    case "RAND_COMMIT": return receiver.authorRandCommit(peer.author, peer.beaconStore, snapshot, peer.beaconSource);
    case "RAND_REVEAL": return receiver.authorRandReveal(peer.author, peer.beaconStore, snapshot);
  }
}

async function phase(peers: readonly Peer[], type: SetupType, recovered?: EnvelopeArtifact) {
  const rank = TYPES.indexOf(type);
  const originals: EnvelopeArtifact[] = [];
  for (const peer of peers) {
    expect(peer.receiver.snapshot.state).toBe(STATES[rank]);
    if (recovered !== undefined && seatOf(recovered.envelope.from) === peer.seat) {
      originals.push(recovered);
      continue;
    }
    const before = peer.receiver.snapshot;
    const previous = peer.messages.filter(({ envelope }) => seatOf(envelope.from) === peer.seat).at(-1);
    const pending = submit(peer, type);
    expect(peer.receiver.snapshot).toBe(before);
    const result = await pending;
    expect(result).toMatchObject({ status: "accepted", chainResult: { status: "accepted", persistenceStatus: "duplicate" } });
    if (result.status === "rejected") throw new Error("Local setup authoring was rejected");
    expect(result.snapshot).toBe(peer.receiver.snapshot);
    const artifact = result.received;
    expect(artifact.envelope).toMatchObject({
      type, game: GAME_ID, round: ROUND, from: peer.scope.sender, phase: type === "KEY_SHARE" ? "setup.keys" : "setup.rand",
      seq: (previous?.envelope.seq ?? -1) + 1, prev: previous?.hash ?? new Uint8Array(32),
    });
    if (type === "KEY_SHARE") {
      const share = deck.decodeGameKeyShareBody(artifact.envelope.body);
      expect(bytesToHex(share.H.toBytes())).toBe(PUBLIC_KEYS[peer.seat]);
      expect(artifact.envelope.body).toEqual(deck.encodeGameKeyShareBody(share));
    } else {
      expect(artifact.envelope.body).toEqual(type === "RAND_COMMIT"
        ? { cm: COMMITMENTS[peer.seat] } : { s: BEACON_SECRETS[peer.seat] });
    }
    peer.messages.push(artifact);
    originals.push(artifact);
    expectProgress(peer);
  }
  // Local production calls cannot cross the phase barrier while other seats are still missing.
  for (const peer of peers) expect(peer.receiver.snapshot.state).toBe(STATES[rank]);
  for (const seat of [2, 0, 3, 1]) {
    const artifact = originals[seat]!;
    for (const recipient of peers.filter((peer) => peer.seat !== seat)) await deliver(recipient, artifact);
  }
  for (const peer of peers) {
    await peer.receiver.whenIdle();
    expectProgress(peer);
    expect(peer.receiver.snapshot.state).toBe(STATES[rank + 1]);
    expect(peer.receiver.snapshot).toEqual(peers[0]!.receiver.snapshot);
    expect(peer.chains.heads()).toEqual(peers[0]!.chains.heads());
  }
}

async function deliver(peer: Peer, artifact: EnvelopeArtifact) {
  const duplicate = peer.messages.some((message) => bytesEqual(message.canonicalBytes, artifact.canonicalBytes));
  const before = peer.receiver.snapshot;
  const receiving = peer.receiver.receive(artifact);
  expect(peer.receiver.snapshot).toBe(before);
  await expect(receiving).resolves.toMatchObject({
    status: duplicate ? "duplicate" : "accepted",
    chainResult: { status: duplicate ? "duplicate" : "accepted", persistenceStatus: duplicate ? "duplicate" : "stored" },
  });
  if (!duplicate) peer.messages.push(artifact);
  else expect(peer.receiver.snapshot).toBe(before);
  expectProgress(peer);
}

function expectProgress(peer: Peer) {
  const senders = TYPES.map((type) => peer.messages.filter(({ envelope }) => envelope.type === type).map(({ envelope }) => seatOf(envelope.from)));
  const incomplete = senders.findIndex((seats) => seats.length < 4);
  const rank = incomplete === -1 ? 3 : incomplete;
  const expected: PersistentSetupSnapshot = {
    state: STATES[rank]!, pendingSenders: rank === 3 ? [] : [0, 1, 2, 3].filter((seat) => !senders[rank]!.includes(seat)),
    publicKeys: PUBLIC_KEYS.map((key, seat) => senders[0]!.includes(seat) ? key : null),
    commitments: COMMITMENTS.map((cm, seat) => senders[1]!.includes(seat) ? bytesToHex(cm) : null),
    aggregateKey: rank > 0 ? bytesToHex(AGGREGATE.toBytes()) : null, seed: rank === 3 ? bytesToHex(SEED) : null,
  };
  const snapshot = peer.receiver.snapshot;
  expect(snapshot).toEqual(expected);
  expect(Reflect.ownKeys(peer.receiver)).toEqual([]);
  expect(Object.entries(Object.getOwnPropertyDescriptors(Object.getPrototypeOf(peer.receiver)))
    .filter(([, descriptor]) => descriptor.get !== undefined).map(([name]) => name).sort())
    .toEqual(["closed", "failure", "gameId", "pendingBytes", "pendingEnvelopes", "roster", "round", "self", "snapshot"]);
  expect(Object.keys(snapshot).sort()).toEqual(["aggregateKey", "commitments", "pendingSenders", "publicKeys", "seed", "state"]);
  // Assert public field meanings rather than secret substrings (the zero preimage also occurs in public byte fields).
  for (const value of [snapshot, snapshot.publicKeys, snapshot.commitments, snapshot.pendingSenders]) expect(Object.isFrozen(value)).toBe(true);
  for (const value of [...snapshot.publicKeys, ...snapshot.commitments, snapshot.aggregateKey, snapshot.seed]) {
    if (value !== null) expect(value).toMatch(/^[0-9a-f]{64}$/);
  }
  expect(Reflect.set(snapshot, "s", BEACON_SECRETS[peer.seat])).toBe(false);
  expect(Reflect.set(snapshot.publicKeys, "0", "ff")).toBe(false);
  expect(snapshot).not.toHaveProperty("x");
  expect(snapshot).not.toHaveProperty("s");
  if (rank < 3) expect(() => peer.receiver.getCompletedSetup()).toThrow(expect.objectContaining({ code: "setup_incomplete" }));
}

async function reopenAndRecover(peer: Peer) {
  const stored = await databaseContents(peer.options);
  const checkpoint = await peer.authored.readAuthoredHead(GAME_ID, peer.scope.sender);
  const draws = [peer.keySource.fill.mock.calls.length, peer.beaconSource.fill.mock.calls.length];
  await closePeer(peer);
  peer.key = null;
  peer.io.access = "readonly";
  peer.store = new IndexedDbSessionStore(peer.options);
  peer.authored = new IndexedDbAuthoredEnvelopeStore(peer.options);
  peer.keyStore = new IndexedDbGameSecretStore(peer.options);
  peer.beaconStore = new IndexedDbSetupBeaconSecretStore(peer.options);
  peer.author = new PersistentEnvelopeAuthor(GAME_ID, IDENTITIES[peer.seat]!.secretKey, peer.authored);
  const loadKey = vi.spyOn(peer.keyStore, "loadGameSecret");
  const forbiddenCalls = [
    vi.spyOn(peer.keyStore, "getOrCreateGameSecret").mockImplementation(forbidden),
    vi.spyOn(peer.beaconStore, "getOrCreateSetupBeaconSecret").mockImplementation(forbidden),
    vi.spyOn(peer.beaconStore, "loadSetupBeaconSecret").mockImplementation(forbidden),
    vi.spyOn(peer.author, "author").mockImplementation(forbidden),
    vi.spyOn(peer.authored, "appendNext").mockImplementation(forbidden),
    vi.spyOn(peer.store, "persistAcceptedEnvelope").mockImplementation(forbidden),
  ];
  try {
    peer.key = await peer.keyStore.loadGameSecret(GAME_ID);
    expect(peer.key).toBe(peer.messages.some(({ envelope }) => envelope.type === "KEY_SHARE" && seatOf(envelope.from) === peer.seat)
      ? KEYS[peer.seat] : null);
    const records = await peer.store.loadTranscript(GAME_ID);
    expect(records.map(({ artifact }) => artifact.canonicalBytes)).toEqual(peer.messages.map(({ canonicalBytes }) => canonicalBytes));
    // Include every actual durable row, especially native-authored rows whose local receipt never completed.
    peer.chains = recoverSessionChains(GAME_ID, ROSTER, records.map(({ artifact }) => artifact).reverse()).registry;
    peer.sessionReceiver = new PersistentSessionReceiver(peer.chains, peer.store);
    const receipt = vi.spyOn(peer.sessionReceiver, "receive").mockImplementation(forbidden);
    const heads = peer.chains.heads();
    const transactionCount = peer.io.transactions.length;
    const openCount = peer.opening.mock.calls.length;
    peer.io.access = "none";
    try {
      peer.receiver = new PersistentSetupReceiver({
        round: ROUND, self: peer.scope.sender, session: peer.chains, sessionReceiver: peer.sessionReceiver,
      });
      expect(peer.io.transactions).toHaveLength(transactionCount);
      expect(peer.opening).toHaveBeenCalledTimes(openCount);
      expect(receipt).not.toHaveBeenCalled();
    } finally {
      receipt.mockRestore();
      peer.io.access = "readonly";
    }
    expect(peer.chains.heads()).toEqual(heads);
    expect(peer.receiver.failure).toBeNull();
    expect(peer.receiver.closed).toBe(false);
    expectProgress(peer);
    expect(await peer.authored.readAuthoredHead(GAME_ID, peer.scope.sender)).toEqual(checkpoint);
    expect(await databaseContents(peer.options)).toEqual(stored);
    expect(loadKey).toHaveBeenCalledExactlyOnceWith(GAME_ID);
    expect([peer.keySource.fill.mock.calls.length, peer.beaconSource.fill.mock.calls.length]).toEqual(draws);
    for (const spy of forbiddenCalls) expect(spy).not.toHaveBeenCalled();
  } finally {
    loadKey.mockRestore();
    for (const spy of forbiddenCalls) spy.mockRestore();
    peer.io.access = "all";
  }
}

async function expectCompleted(peers: readonly Peer[], prefixCount = 0) {
  const originals = peers.flatMap((peer) => peer.messages.filter(({ envelope }) => seatOf(envelope.from) === peer.seat));
  expect(originals).toHaveLength(12 + prefixCount);
  expect(originals.filter(({ envelope }) => TYPES.includes(envelope.type as SetupType))).toHaveLength(12);
  const canonical = orderEnvelopeTranscript(GAME_ID, originals).map(({ canonicalBytes }) => canonicalBytes);
  expect(new Set(canonical.map(bytesToHex)).size).toBe(12 + prefixCount);
  expect(SEED).not.toEqual(sha256(...[2, 0, 3, 1].map((seat) => BEACON_SECRETS[seat]!)));
  for (const peer of peers) {
    await peer.receiver.whenIdle();
    expectProgress(peer);
    expect(peer.receiver.snapshot.state).toBe("complete");
    expect(peer.receiver.getCompletedSetup().seed).toEqual(SEED);
    expect(peer.receiver.getCompletedSetup().aggregateKey!.toBytes()).toEqual(AGGREGATE.toBytes());
    expect(peer.receiver.failure).toBeNull();
    expect(peer.receiver.pendingEnvelopes).toBe(0);
    expect(peer.receiver.pendingBytes).toBe(0);
    const records = await peer.store.loadCanonicalEnvelopeTranscript(GAME_ID);
    expect(records.map(({ artifact }) => artifact.canonicalBytes)).toEqual(canonical);
    const setup = records.filter(({ artifact }) => TYPES.includes(artifact.envelope.type as SetupType));
    expect(setup.filter(({ authored }) => authored).map(({ artifact }) => artifact.envelope.type)).toEqual(TYPES);
    expect(setup.filter(({ authored }) => !authored)).toHaveLength(9);
    expect(records.filter(({ authored }) => authored)).toHaveLength(prefixCount === 0 ? 3 : 4);
    expect(records.filter(({ authored }) => !authored)).toHaveLength(prefixCount === 0 ? 9 : 12);
    expect(peer.keySource.fill).toHaveBeenCalledTimes(2);
    expect(peer.beaconSource.fill).toHaveBeenCalledTimes(1);
    await expectStoredPeer(peer);
  }
}

async function expectStoredPeer(peer: Peer) {
  const game = bytesToHex(GAME_ID);
  const sender = bytesToHex(peer.scope.sender);
  const own = peer.messages.filter(({ envelope }) => seatOf(envelope.from) === peer.seat);
  const key = own.some(({ envelope }) => envelope.type === "KEY_SHARE");
  const beacon = own.some(({ envelope }) => envelope.type === "RAND_COMMIT");
  expect(own.map(({ envelope }) => envelope.seq)).toEqual(own.map((_, index) => index));
  expect(await peer.store.loadTranscript(GAME_ID)).toEqual(peer.messages.map((artifact, index) => ({
    arrival: index + 1, artifact, authored: seatOf(artifact.envelope.from) === peer.seat,
  })));
  expect(await peer.authored.readAuthoredHead(GAME_ID, peer.scope.sender)).toEqual(own.at(-1) ?? null);
  const stored = await databaseContents(peer.options);
  expect(stored).toEqual({
    [GAMES_STORE]: key ? [{ game, gameSecret: encodeRistrettoScalar(KEYS[peer.seat]!), ...(beacon ? {
      setupBeaconSecret: { version: 1, round: ROUND, sender: peer.scope.sender, roster: ROSTER, secret: BEACON_SECRETS[peer.seat] },
    } : {}) }] : [],
    [IDENTITY_STORE]: [],
    [AUTHORED_HEADS_STORE]: own.length === 0 ? [] : [{ game, sender, bytes: own.at(-1)!.canonicalBytes }],
    [TRANSCRIPTS_STORE]: peer.messages.map(({ envelope, canonicalBytes }, index) => ({
      arrival: index + 1, game, sender: bytesToHex(envelope.from), seq: envelope.seq,
      bytes: canonicalBytes, authored: seatOf(envelope.from) === peer.seat,
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

async function closePeer(peer: Peer) {
  peer.receiver.close();
  await peer.receiver.whenIdle();
  await Promise.all([peer.store.close(), peer.authored.close(), peer.keyStore.close(), peer.beaconStore.close()]);
}

function seatOf(sender: ReadonlyPubKey): number {
  const seat = ROSTER.findIndex((identity) => bytesEqual(identity, sender));
  if (seat === -1) throw new Error("Fixture sender is outside the roster");
  return seat;
}

function forbidden(): never { throw new Error("Recovery or a consumed obligation must not generate, sign, or persist"); }
