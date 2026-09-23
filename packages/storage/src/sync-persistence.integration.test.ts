import {
  bytesEqual,
  bytesToHex,
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  negateRistrettoScalar,
  scalarFromBigInt,
  type RandomSource,
  type RistrettoScalar,
} from "@p2pcards/crypto";
import { createGameKeyShare, encodeGameKeyShareBody } from "@p2pcards/deck";
import { PersistentSetupReceiver, recoverSetup } from "@p2pcards/engine";
import {
  encodeRandRevealBody,
  encodeSyncResponseBody,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  parseRandomSecret,
  signEnvelope,
  type EnvelopeArtifact,
  type ProofContext,
} from "@p2pcards/protocol";
import {
  PersistentSessionReceiver,
  PersistentSyncReceiver,
  SessionChainRegistry,
  recoverSessionChains,
  type AcceptedEnvelopeStore,
} from "@p2pcards/session";
import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it } from "vitest";

import { IndexedDbSessionStore } from "./indexeddb-session-store";

const ALICE = identity(91);
const BOB = identity(92);
const CAROL = identity(93);
const ROSTER = [ALICE.publicKey, BOB.publicKey, CAROL.publicKey];
const GAME = parseGameId(new Uint8Array(16).fill(0x43));
const ROUND = 3;
const ZERO = parseHash256(new Uint8Array(32));
const CONTEXT: ProofContext = { gameId: GAME, round: ROUND, phase: "setup.keys" };
const ALICE_KEY = keyEnvelope(ALICE, scalarFromBigInt(7n));
const BOB_KEY = keyEnvelope(BOB, scalarFromBigInt(8n));
const CAROL_KEY = keyEnvelope(CAROL, scalarFromBigInt(9n));
const REQUEST = { from: BOB.publicKey, fromSeq: 0, toSeq: 0 };

describe("durable setup synchronization integration", () => {
  it("receives a missing key through IndexedDB and recovers the same chains and setup", async () => {
    const factory = new IDBFactory();
    const store = new IndexedDbSessionStore({ factory, databaseName: "range-recovery" });
    const live = await setup(store);
    const outer = response([BOB_KEY]);
    await expect(live.ranges.receiveResponse(outer, REQUEST)).resolves.toEqual({
      status: "range_received", outerStatus: "accepted", receipts: ["accepted"],
    });
    await expect(live.ranges.receiveResponse(outer, REQUEST)).resolves.toEqual({
      status: "range_received", outerStatus: "duplicate", receipts: ["duplicate"],
    });
    expect(live.receiver.snapshot.publicKeys[1]).not.toBeNull();
    const expectedHeads = live.registry.heads();
    const expectedState = live.receiver.snapshot.state;
    const expectedKey = live.receiver.snapshot.aggregateKey;
    await store.close();

    const resumed = new IndexedDbSessionStore({ factory, databaseName: "range-recovery" });
    const records = await resumed.loadTranscript(GAME);
    expect(records).toHaveLength(4);
    const artifacts = records.map(({ artifact }) => artifact);
    const recoveredChains = recoverSessionChains(GAME, ROSTER, [...artifacts].reverse());
    const recoveredSetup = recoverSetup(GAME, ROUND, ROSTER, [...artifacts].reverse());
    expect(recoveredChains.registry.heads()).toEqual(expectedHeads);
    expect(recoveredSetup.setupEnvelopeCount).toBe(3);
    expect(recoveredSetup.coordinator.state).toBe(expectedState);
    expect(bytesToHex(recoveredSetup.coordinator.aggregateKey!.toBytes())).toBe(expectedKey);
    await resumed.close();
  });

  it("does not accept a semantically malformed nested key as a standalone record", async () => {
    const store = new IndexedDbSessionStore({ factory: new IDBFactory(), databaseName: "invalid-range-key" });
    const live = await setup(store);
    const malformed = signEnvelope({ ...BOB_KEY.envelope, body: {} }, BOB.secretKey);
    await expect(live.ranges.receiveResponse(response([malformed]), REQUEST)).resolves.toMatchObject({
      status: "stopped", stage: "history", index: 0, reason: "malformed_body",
      outerStatus: "accepted", receipts: [],
    });
    expect(live.receiver.snapshot.publicKeys[1]).toBeNull();
    expect(live.registry.heads().some(({ from }) => bytesEqual(from, BOB.publicKey))).toBe(false);
    const records = await store.loadTranscript(GAME);
    expect(records).toHaveLength(3);
    expect(records.some(({ artifact }) => bytesEqual(artifact.envelope.from, BOB.publicKey))).toBe(false);
    await store.close();
  });

  it("keeps a valid durable prefix but stops before a premature historical reveal", async () => {
    const store = new IndexedDbSessionStore({ factory: new IDBFactory(), databaseName: "partial-range" });
    const live = await setup(store);
    // Deliberately signed but semantically invalid: no randomness commitments have been accepted.
    const premature = signEnvelope({
      v: 1, game: GAME, from: BOB.publicKey, seq: 1, prev: BOB_KEY.hash,
      round: ROUND, phase: "setup.rand", type: "RAND_REVEAL",
      body: encodeRandRevealBody({ s: parseRandomSecret(new Uint8Array(32).fill(5)) }),
    }, BOB.secretKey);
    const outer = response([BOB_KEY, premature]);
    const request = { ...REQUEST, toSeq: 1 };
    await expect(live.ranges.receiveResponse(outer, request)).resolves.toMatchObject({
      status: "stopped", stage: "history", index: 1, outerStatus: "accepted", receipts: ["accepted"],
    });
    await expect(live.ranges.receiveResponse(outer, request)).resolves.toMatchObject({
      status: "stopped", stage: "history", index: 1, outerStatus: "duplicate", receipts: ["duplicate"],
    });
    expect(live.registry.heads().find(({ from }) => bytesEqual(from, BOB.publicKey))?.seq).toBe(0);
    expect(live.receiver.snapshot.seed).toBeNull();
    expect(await store.loadTranscript(GAME)).toHaveLength(4);
    await store.close();
  });

  it("distinguishes a durably accepted aggregate-identity failure from successful range receipt", async () => {
    const store = new IndexedDbSessionStore({ factory: new IDBFactory(), databaseName: "terminal-range" });
    const live = await setup(store);
    const cancellingKey = keyEnvelope(BOB, negateRistrettoScalar(scalarFromBigInt(16n)));
    await expect(live.ranges.receiveResponse(response([cancellingKey]), REQUEST)).resolves.toEqual({
      status: "stopped", stage: "history", index: 0, reason: "terminal_history_failure",
      outerStatus: "accepted", receipts: ["failed"],
    });
    expect(live.receiver.snapshot.state).toBe("failed");
    expect(live.registry.heads().find(({ from }) => bytesEqual(from, BOB.publicKey))?.seq).toBe(0);
    const transcript = (await store.loadTranscript(GAME)).map(({ artifact }) => artifact);
    expect(transcript).toHaveLength(4);
    expect(recoverSetup(GAME, ROUND, ROSTER, transcript).coordinator.state).toBe("failed");
    await store.close();
  });

  it("waits for the outer transaction before applying history and handles failed history storage", async () => {
    const store = new IndexedDbSessionStore({ factory: new IDBFactory(), databaseName: "delayed-range" });
    const started = deferred();
    const release = deferred();
    let failHistory = true;
    const wrapped: AcceptedEnvelopeStore = {
      async persistAcceptedEnvelope(artifact) {
        if (artifact.envelope.type === "SYNC_RESP") {
          started.resolve();
          await release.promise;
        }
        if (bytesEqual(artifact.envelope.from, BOB.publicKey) && failHistory) {
          failHistory = false;
          throw new Error("history storage unavailable");
        }
        return store.persistAcceptedEnvelope(artifact);
      },
    };
    const live = await setup(wrapped);
    const outer = response([BOB_KEY]);
    const receiving = live.ranges.receiveResponse(outer, REQUEST);
    await started.promise;
    expect(await store.loadTranscript(GAME)).toHaveLength(2);
    expect(live.receiver.snapshot.publicKeys[1]).toBeNull();
    release.resolve();
    await expect(receiving).resolves.toMatchObject({
      status: "failed", stage: "history", index: 0, outerStatus: "accepted", receipts: [],
      error: expect.objectContaining({ message: "history storage unavailable" }),
    });
    expect(live.receiver.snapshot.publicKeys[1]).toBeNull();
    expect(await store.loadTranscript(GAME)).toHaveLength(3);
    await expect(live.ranges.receiveResponse(outer, REQUEST)).resolves.toMatchObject({
      status: "range_received", outerStatus: "duplicate", receipts: ["accepted"],
    });
    expect(live.receiver.snapshot.publicKeys[1]).not.toBeNull();
    await store.close();
  });

  it("does not bootstrap a gapped outer from its own valid nested predecessor", async () => {
    const store = new IndexedDbSessionStore({ factory: new IDBFactory(), databaseName: "outer-self-gap" });
    const registry = new SessionChainRegistry(GAME, ROSTER);
    const controls = new PersistentSessionReceiver(registry, store);
    const receiver = new PersistentSetupReceiver({ round: ROUND, self: ALICE.publicKey, session: registry, sessionReceiver: controls });
    const ranges = new PersistentSyncReceiver(registry, controls, receiver);
    await expect(ranges.receiveResponse(response([ALICE_KEY]), { from: ALICE.publicKey, fromSeq: 0, toSeq: 0 })).resolves.toMatchObject({
      status: "stopped", stage: "outer", reason: "gap", outerStatus: null, receipts: [],
    });
    expect(await store.loadTranscript(GAME)).toEqual([]);
    expect(receiver.snapshot.publicKeys[0]).toBeNull();
    await store.close();
  });
});

async function setup(store: AcceptedEnvelopeStore) {
  const registry = new SessionChainRegistry(GAME, ROSTER);
  const controls = new PersistentSessionReceiver(registry, store);
  const receiver = new PersistentSetupReceiver({ round: ROUND, self: ALICE.publicKey, session: registry, sessionReceiver: controls });
  await receiver.receive(ALICE_KEY);
  await receiver.receive(CAROL_KEY);
  return { registry, receiver, ranges: new PersistentSyncReceiver(registry, controls, receiver) };
}

function response(envelopes: readonly EnvelopeArtifact[]): EnvelopeArtifact {
  return signEnvelope({
    v: 1, game: GAME, from: ALICE.publicKey, seq: 1, prev: ALICE_KEY.hash,
    round: ROUND, phase: "setup.keys", type: "SYNC_RESP", body: encodeSyncResponseBody({ envelopes }),
  }, ALICE.secretKey);
}

function identity(fill: number) {
  const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(fill));
  return { secretKey, publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)) };
}

function keyEnvelope(author: ReturnType<typeof identity>, secret: RistrettoScalar): EnvelopeArtifact {
  const source: RandomSource = { fill: (target) => { target.fill(0); target[0] = 97; } };
  const body = encodeGameKeyShareBody(createGameKeyShare(CONTEXT, secret, source));
  return signEnvelope({
    v: 1, game: GAME, from: author.publicKey, seq: 0, prev: ZERO,
    round: ROUND, phase: "setup.keys", type: "KEY_SHARE", body,
  }, author.secretKey);
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((complete) => { resolve = complete; });
  return { promise, resolve };
}
