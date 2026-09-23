import {
  bytesEqual,
  bytesToHex,
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  type Ed25519SecretKey,
} from "@p2pcards/crypto";
import {
  decodeAndVerifyEnvelope,
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

import { SessionChainRegistry } from "./chain-registry";
import {
  PersistentSessionReceiver,
  PersistentSessionReceiverError,
  type AcceptedEnvelopePersistenceOutcome,
  type AcceptedEnvelopeStore,
} from "./persistent-receiver";

interface TestIdentity {
  readonly secretKey: Ed25519SecretKey;
  readonly publicKey: IdentityPublicKey;
}

const ALICE = identity(21);
const BOB = identity(22);
const CAROL = identity(23);
const MALLORY = identity(24);
const GAME_ID = parseGameId(new Uint8Array(16).fill(0x31));
const OTHER_GAME_ID = parseGameId(new Uint8Array(16).fill(0x32));
const ZERO_HASH = parseHash256(new Uint8Array(32));

describe("persistent session receiver", () => {
  it("does not advance a chain until durable persistence resolves", async () => {
    const registry = sessionRegistry();
    const store = new MemoryAcceptedEnvelopeStore();
    const gate = deferred<void>();
    const started = deferred<void>();
    store.beforeCommit = async () => {
      started.resolve();
      await gate.promise;
    };
    const receiver = new PersistentSessionReceiver(registry, store);
    const first = envelope(ALICE, 0, ZERO_HASH, "first");

    const pending = receiver.receive(first);
    await started.promise;
    expect(registry.heads()).toEqual([]);

    gate.resolve();
    await expect(pending).resolves.toMatchObject({
      status: "accepted",
      persistenceStatus: "stored",
      chainResult: { status: "accepted" },
    });
    expect(registry.heads()).toEqual([
      expect.objectContaining({ from: ALICE.publicKey, seq: 0, hash: first.hash }),
    ]);
  });

  it("leaves memory unchanged on storage failure and keeps the queue usable", async () => {
    const registry = sessionRegistry();
    const store = new MemoryAcceptedEnvelopeStore();
    const receiver = new PersistentSessionReceiver(registry, store);
    const first = envelope(ALICE, 0, ZERO_HASH, "first");
    store.failNext = true;

    await expect(receiver.receive(first)).rejects.toThrow("storage failure");
    expect(registry.heads()).toEqual([]);
    await expect(receiver.receive(first)).resolves.toMatchObject({ status: "accepted" });
    expect(registry.heads()).toEqual([expect.objectContaining({ seq: 0 })]);
  });

  it("serializes concurrent receives in invocation order", async () => {
    const registry = sessionRegistry();
    const store = new MemoryAcceptedEnvelopeStore();
    const firstGate = deferred<void>();
    let calls = 0;
    store.beforeCommit = async () => {
      calls += 1;
      if (calls === 1) {
        await firstGate.promise;
      }
    };
    const receiver = new PersistentSessionReceiver(registry, store);
    const first = envelope(ALICE, 0, ZERO_HASH, "first");
    const second = envelope(ALICE, 1, first.hash, "second");

    const firstPending = receiver.receive(first);
    const secondPending = receiver.receive(second);
    await Promise.resolve();
    expect(store.calls.map(({ envelope }) => envelope.seq)).toEqual([0]);
    expect(registry.heads()).toEqual([]);

    firstGate.resolve();
    await expect(Promise.all([firstPending, secondPending])).resolves.toMatchObject([
      { status: "accepted" },
      { status: "accepted" },
    ]);
    expect(store.calls.map(({ envelope }) => envelope.seq)).toEqual([0, 1]);
    expect(registry.heads()).toEqual([expect.objectContaining({ seq: 1, hash: second.hash })]);
  });

  it("does not persist chain-invalid or non-roster artifacts", async () => {
    const registry = sessionRegistry();
    const store = new MemoryAcceptedEnvelopeStore();
    const receiver = new PersistentSessionReceiver(registry, store);
    const gap = envelope(ALICE, 2, ZERO_HASH, "gap");
    const outsider = envelope(MALLORY, 0, ZERO_HASH, "outsider");
    const wrongGame = envelope(ALICE, 0, ZERO_HASH, "wrong game", OTHER_GAME_ID);

    await expect(receiver.receive(gap)).resolves.toMatchObject({
      status: "rejected",
      reason: "gap",
    });
    await expect(receiver.receive(outsider)).resolves.toMatchObject({
      status: "rejected",
      reason: "unknown_sender",
    });
    await expect(receiver.receive(wrongGame)).resolves.toMatchObject({
      status: "rejected",
      reason: "wrong_game",
    });
    expect(store.calls).toEqual([]);
    expect(registry.heads()).toEqual([]);
  });

  it("repairs a missing durable duplicate without advancing the chain twice", async () => {
    const registry = sessionRegistry();
    const store = new MemoryAcceptedEnvelopeStore();
    const first = envelope(ALICE, 0, ZERO_HASH, "first");
    registry.ingest(first);
    const receiver = new PersistentSessionReceiver(registry, store);

    await expect(receiver.receive(first)).resolves.toMatchObject({
      status: "duplicate",
      persistenceStatus: "stored",
      chainResult: { status: "duplicate" },
    });
    expect(store.records).toHaveLength(1);
    expect(registry.heads()).toEqual([expect.objectContaining({ seq: 0, hash: first.hash })]);
  });

  it("accepts a durable duplicate when disk is ahead of recovered memory", async () => {
    const registry = sessionRegistry();
    const store = new MemoryAcceptedEnvelopeStore();
    const first = envelope(ALICE, 0, ZERO_HASH, "first");
    store.seed(first);
    const receiver = new PersistentSessionReceiver(registry, store);

    await expect(receiver.receive(first)).resolves.toMatchObject({
      status: "accepted",
      persistenceStatus: "duplicate",
    });
    expect(registry.heads()).toEqual([expect.objectContaining({ seq: 0, hash: first.hash })]);
  });

  it("fails closed on a conflicting durable sender sequence", async () => {
    const registry = sessionRegistry();
    const store = new MemoryAcceptedEnvelopeStore();
    const first = envelope(ALICE, 0, ZERO_HASH, "first");
    const conflict = envelope(ALICE, 0, ZERO_HASH, "conflict");
    store.seed(conflict);
    const receiver = new PersistentSessionReceiver(registry, store);

    await expect(receiver.receive(first)).resolves.toMatchObject({
      status: "rejected",
      reason: "durable_conflict",
      existing: conflict,
      received: first,
    });
    expect(registry.heads()).toEqual([]);
  });

  it("rejects a store that reports a different artifact as committed", async () => {
    const registry = sessionRegistry();
    const first = envelope(ALICE, 0, ZERO_HASH, "first");
    const different = envelope(ALICE, 0, ZERO_HASH, "different");
    const store: AcceptedEnvelopeStore = {
      async persistAcceptedEnvelope() {
        return { status: "stored", record: { artifact: different } };
      },
    };
    const receiver = new PersistentSessionReceiver(registry, store);

    await expect(receiver.receive(first)).rejects.toThrow(PersistentSessionReceiverError);
    expect(registry.heads()).toEqual([]);
  });

  it("rejects a store that reports a conflict for another candidate", async () => {
    const registry = sessionRegistry();
    const first = envelope(ALICE, 0, ZERO_HASH, "first");
    const existing = envelope(ALICE, 0, ZERO_HASH, "existing");
    const unrelated = envelope(BOB, 0, ZERO_HASH, "unrelated");
    const store: AcceptedEnvelopeStore = {
      async persistAcceptedEnvelope() {
        return {
          status: "conflict",
          existing: { artifact: existing },
          received: unrelated,
        };
      },
    };
    const receiver = new PersistentSessionReceiver(registry, store);

    await expect(receiver.receive(first)).rejects.toThrow(/different candidate/);
    expect(registry.heads()).toEqual([]);
  });

  it("snapshots caller-owned artifact bytes before entering the receive queue", async () => {
    const registry = sessionRegistry();
    const store = new MemoryAcceptedEnvelopeStore();
    const gate = deferred<void>();
    store.beforeCommit = () => gate.promise;
    const receiver = new PersistentSessionReceiver(registry, store);
    const first = envelope(ALICE, 0, ZERO_HASH, "stable");
    const expectedHash = first.hash.slice();

    const pending = receiver.receive(first);
    first.canonicalBytes.fill(0xff);
    first.hash.fill(0xff);
    gate.resolve();
    const result = await pending;

    expect(result).toMatchObject({ status: "accepted" });
    expect(registry.heads()[0]?.hash).toEqual(expectedHash);
    expect(store.records[0]?.hash).toEqual(expectedHash);
  });

  it("rejects invalid construction inputs", () => {
    const registry = sessionRegistry();
    const store = new MemoryAcceptedEnvelopeStore();
    expect(() => new PersistentSessionReceiver({} as SessionChainRegistry, store)).toThrow(
      TypeError,
    );
    expect(() => new PersistentSessionReceiver(registry, {} as AcceptedEnvelopeStore)).toThrow(
      TypeError,
    );
  });
});

class MemoryAcceptedEnvelopeStore implements AcceptedEnvelopeStore {
  readonly records: EnvelopeArtifact[] = [];
  readonly calls: EnvelopeArtifact[] = [];
  failNext = false;
  beforeCommit: (() => Promise<void>) | null = null;

  seed(candidate: EnvelopeArtifact): void {
    this.records.push(decodeAndVerifyEnvelope(candidate.canonicalBytes));
  }

  async persistAcceptedEnvelope(
    received: EnvelopeArtifact,
  ): Promise<AcceptedEnvelopePersistenceOutcome> {
    const snapshot = decodeAndVerifyEnvelope(received.canonicalBytes);
    this.calls.push(snapshot);
    if (this.beforeCommit !== null) {
      await this.beforeCommit();
    }
    if (this.failNext) {
      this.failNext = false;
      throw new Error("storage failure");
    }

    const existing = this.records.find(
      ({ envelope }) =>
        bytesToHex(envelope.game) === bytesToHex(snapshot.envelope.game) &&
        bytesToHex(envelope.from) === bytesToHex(snapshot.envelope.from) &&
        envelope.seq === snapshot.envelope.seq,
    );
    if (existing !== undefined) {
      return bytesEqual(existing.canonicalBytes, snapshot.canonicalBytes)
        ? { status: "duplicate", record: { artifact: existing } }
        : { status: "conflict", existing: { artifact: existing }, received: snapshot };
    }
    this.records.push(snapshot);
    return { status: "stored", record: { artifact: snapshot } };
  }
}

function sessionRegistry(): SessionChainRegistry {
  return new SessionChainRegistry(GAME_ID, [
    ALICE.publicKey,
    BOB.publicKey,
    CAROL.publicKey,
  ]);
}

function identity(fill: number): TestIdentity {
  const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(fill));
  return {
    secretKey,
    publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)),
  };
}

function envelope(
  author: TestIdentity,
  seq: number,
  prev: Hash256,
  marker: string,
  game = GAME_ID,
): EnvelopeArtifact {
  const value: UnsignedEnvelope = {
    v: 1,
    game,
    from: author.publicKey,
    seq,
    prev,
    round: 1,
    phase: "round.1.play.0",
    type: "ACTION",
    body: { marker },
  };
  return signEnvelope(value, author.secretKey);
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
