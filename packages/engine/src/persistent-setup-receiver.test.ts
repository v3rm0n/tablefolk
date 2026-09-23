import { bytesToHex, RISTRETTO_SCALAR_ORDER, scalarFromBigInt, sha256 } from "@p2pcards/crypto";
import { createGameKeyShare, encodeGameKeyShareBody } from "@p2pcards/deck";
import {
  beaconCommitment, decodeAndVerifyEnvelope, encodeRandCommitBody, encodeRandRevealBody, parseHash256, signEnvelope,
  type EnvelopeArtifact,
} from "@p2pcards/protocol";
import { PersistentSessionReceiver, SessionChainRegistry } from "@p2pcards/session";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  MAX_SETUP_ENVELOPE_BYTES, PersistentSetupReceiver, PersistentSetupReceiverError,
} from "./persistent-setup-receiver";
import { deferred, deterministicSource, persistentSetupFixture } from "./persistent-setup.test-fixture";
import { SetupEnvelopeCoordinator } from "./setup-envelope-coordinator";

type Fixture = ReturnType<typeof persistentSetupFixture>;

afterEach(() => vi.restoreAllMocks());

describe("persistent setup receiver", () => {
  it("does not mutate setup or chains until durable receipt resolves and captures input bytes", async () => {
    const c = persistentSetupFixture();
    const gate = deferred();
    const started = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (artifact) => {
      started.resolve();
      await gate.promise;
      return persist(artifact);
    });
    const key = await keyEnvelope(c, 1);
    const original = decodeAndVerifyEnvelope(key.canonicalBytes);
    const before = c.receiver.snapshot;
    const pending = c.receiver.receive(key);
    key.canonicalBytes.fill(0xff);
    key.hash.fill(0xff);
    try {
      await started.promise;
      expect(c.receiver.snapshot).toBe(before);
      expect(c.receiver.snapshot.publicKeys[1]).toBeNull();
      expect(c.registry.heads()).toEqual([]);
      expect(c.receiver.pendingEnvelopes).toBe(1);
      expect(c.receiver.pendingBytes).toBe(original.canonicalBytes.length);
    } finally { gate.resolve(); }
    await expect(pending).resolves.toMatchObject({
      status: "accepted", chainResult: { status: "accepted", persistenceStatus: "stored", received: original },
      transition: { status: "accepted", seat: 1 }, snapshot: { publicKeys: [null, bytesToHex(c.shares[1]!.H.toBytes()), null] },
    });
    await c.receiver.whenIdle();
    expect(c.receiver.pendingEnvelopes).toBe(0);
    expect(c.receiver.pendingBytes).toBe(0);
    expect(write.mock.calls[0]![0].hash).toEqual(original.hash);
    expect(c.registry.classify(original).status).toBe("duplicate");
  });

  it("does not send semantically rejected setup traffic to durable receipt", async () => {
    const c = persistentSetupFixture();
    const key = await keyEnvelope(c, 1);
    const wrongPhase = signEnvelope({ ...key.envelope, phase: "setup.rand" }, c.identities[1]!.secretKey);
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope");
    const before = c.receiver.snapshot;
    await expect(c.receiver.receive(wrongPhase)).resolves.toMatchObject({ status: "rejected", reason: "wrong_phase" });
    expect(write).not.toHaveBeenCalled();
    expect(c.receiver.snapshot).toBe(before);
    expect(c.registry.heads()).toEqual([]);
  });

  it("preserves semantic state on a real chain gap, then accepts the original after its native predecessor", async () => {
    const c = persistentSetupFixture();
    const predecessor = await c.authors[1]!.author({ round: c.round, phase: "setup.keys", type: "WITNESS", body: { heads: [] } });
    const key = await keyEnvelope(c, 1);
    const before = c.receiver.snapshot;
    await expect(c.receiver.receive(key)).resolves.toMatchObject({
      status: "rejected", reason: "chain_rejected", chainResult: { status: "rejected", reason: "gap" },
      classification: { status: "accepted" },
    });
    expect(c.receiver.snapshot).toBe(before);
    expect(c.store.artifacts()).toEqual([]);
    await c.durable.receive(predecessor);
    await expect(c.receiver.receive(key)).resolves.toMatchObject({ status: "accepted" });
    expect(c.receiver.snapshot.publicKeys[1]).toBe(bytesToHex(c.shares[1]!.H.toBytes()));
  });

  it("preserves semantic state on a durable equal-sequence conflict", async () => {
    const c = persistentSetupFixture();
    const key = await keyEnvelope(c, 1);
    const conflict = signEnvelope({ ...key.envelope, type: "WITNESS", body: { heads: [] } }, c.identities[1]!.secretKey);
    await c.store.persistAcceptedEnvelope(conflict);
    const before = c.receiver.snapshot;
    await expect(c.receiver.receive(key)).resolves.toMatchObject({
      status: "rejected", reason: "chain_rejected", chainResult: { status: "rejected", reason: "durable_conflict" },
    });
    expect(c.receiver.snapshot).toBe(before);
    expect(c.receiver.failure).toBeNull();
    expect(c.registry.heads()).toEqual([]);
  });

  it("leaves setup unchanged on persistence failure and keeps the queue usable", async () => {
    const c = persistentSetupFixture();
    const key = await keyEnvelope(c, 1);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockRejectedValueOnce(new Error("durable failure"));
    const before = c.receiver.snapshot;
    await expect(c.receiver.receive(key)).rejects.toThrow("durable failure");
    expect(c.receiver.snapshot).toBe(before);
    expect(c.registry.heads()).toEqual([]);
    expect(c.receiver.failure).toBeNull();
    expect(c.receiver.pendingEnvelopes).toBe(0);
    expect(c.receiver.pendingBytes).toBe(0);
    await expect(c.receiver.receive(key)).resolves.toMatchObject({ status: "accepted" });
    expect(c.receiver.snapshot.publicKeys[1]).toBe(bytesToHex(c.shares[1]!.H.toBytes()));
  });

  it("serializes concurrent semantic classification in invocation order", async () => {
    const c = persistentSetupFixture();
    const keys = await Promise.all([keyEnvelope(c, 0), keyEnvelope(c, 1)]);
    const gate = deferred();
    const started = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (artifact) => {
      started.resolve();
      await gate.promise;
      return persist(artifact);
    });
    const before = c.receiver.snapshot;
    const pending = Promise.all(keys.map((key) => c.receiver.receive(key)));
    try {
      await started.promise;
      expect(write).toHaveBeenCalledTimes(1);
      expect(c.receiver.snapshot).toBe(before);
      expect(c.receiver.pendingEnvelopes).toBe(2);
    } finally { gate.resolve(); }
    await expect(pending).resolves.toMatchObject([
      { status: "accepted", snapshot: { pendingSenders: [1, 2] } },
      { status: "accepted", snapshot: { pendingSenders: [2] } },
    ]);
    expect(write.mock.calls.map(([artifact]) => artifact.hash)).toEqual(keys.map(({ hash }) => hash));
    expect(c.receiver.snapshot.publicKeys).toEqual([bytesToHex(c.shares[0]!.H.toBytes()), bytesToHex(c.shares[1]!.H.toBytes()), null]);
  });

  it("durably accepts the final share before committing aggregate-key failure", async () => {
    const c = persistentSetupFixture();
    const cancelling = [1n, 2n, RISTRETTO_SCALAR_ORDER - 3n].map((secret, seat) =>
      createGameKeyShare({ gameId: c.gameId, round: c.round, phase: "setup.keys" }, scalarFromBigInt(secret), deterministicSource(BigInt(seat + 91))));
    const keys = await Promise.all(cancelling.map((share, seat) => keyEnvelope(c, seat, share)));
    await c.receiver.receive(keys[0]!);
    await c.receiver.receive(keys[1]!);
    const gate = deferred();
    const started = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (artifact) => {
      started.resolve();
      await gate.promise;
      return persist(artifact);
    });
    const before = c.receiver.snapshot;
    const pending = c.receiver.receive(keys[2]!);
    try {
      await started.promise;
      expect(c.receiver.snapshot).toBe(before);
      expect(c.receiver.snapshot.state).toBe("keys");
    } finally { gate.resolve(); }
    await expect(pending).resolves.toMatchObject({
      status: "failed", chainResult: { status: "accepted", persistenceStatus: "stored" },
      transition: { status: "failed", reason: "aggregate_key_is_identity" }, snapshot: { state: "failed" },
    });
    expect(c.receiver.snapshot.publicKeys[2]).toBe(bytesToHex(cancelling[2]!.H.toBytes()));
    expect(c.registry.classify(keys[2]!).status).toBe("duplicate");
    expect(c.receiver.failure).toBeNull();
    expect(() => c.receiver.getCompletedSetup()).toThrow(expect.objectContaining({ code: "setup_failed" }));
    expect(new PersistentSetupReceiver(c.options).snapshot).toEqual(c.receiver.snapshot);
  });

  it("hydrates accepted history read-only at construction and treats manual replay as duplicate", async () => {
    const c = persistentSetupFixture();
    const key = await keyEnvelope(c, 0);
    await c.durable.receive(key);
    const heads = c.registry.heads();
    const records = c.store.artifacts();
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope");
    const append = vi.spyOn(c.store, "appendNext");
    const read = vi.spyOn(c.store, "readAuthoredHead");
    const receiver = new PersistentSetupReceiver(c.options);
    expect(receiver.snapshot.publicKeys[0]).toBe(bytesToHex(c.shares[0]!.H.toBytes()));
    expect(receiver.snapshot.pendingSenders).toEqual([1, 2]);
    expect(c.registry.heads()).toEqual(heads);
    expect(c.store.artifacts()).toEqual(records);
    for (const spy of [write, append, read]) expect(spy).not.toHaveBeenCalled();
    const before = receiver.snapshot;
    await expect(receiver.receive(key)).resolves.toMatchObject({
      status: "duplicate", transition: { status: "duplicate" },
      chainResult: { status: "duplicate", persistenceStatus: "duplicate" },
    });
    expect(receiver.snapshot).toBe(before);
    expect(c.registry.heads()).toEqual(heads);
    expect(c.store.artifacts()).toEqual(records);
  });

  it("exposes only frozen public progress and detaches receipt bytes from state and one another", async () => {
    const c = persistentSetupFixture();
    const key = await keyEnvelope(c, 0);
    const result = await c.receiver.receive(key);
    if (result.status === "rejected") throw new Error("Expected accepted fixture key");
    const snapshot = c.receiver.snapshot;
    expect(result.snapshot).toBe(snapshot);
    expect(Reflect.ownKeys(c.receiver)).toEqual([]);
    expect(Object.keys(snapshot).sort()).toEqual(["aggregateKey", "commitments", "pendingSenders", "publicKeys", "seed", "state"]);
    for (const value of [snapshot, snapshot.publicKeys, snapshot.commitments, snapshot.pendingSenders]) expect(Object.isFrozen(value)).toBe(true);
    expect(snapshot).not.toHaveProperty("x");
    expect(snapshot).not.toHaveProperty("s");
    expect(Reflect.set(snapshot.publicKeys, "0", "ff")).toBe(false);
    result.received.canonicalBytes.fill(0xff);
    result.received.hash.fill(0xff);
    expect(result.chainResult.received).toEqual(key);
    expect(result.transition.received).toEqual(key);
    result.chainResult.received.canonicalBytes.fill(0xff);
    result.transition.received.envelope.from.fill(0xff);
    expect(c.registry.readRange(c.self, 0, 0)).toEqual({ status: "complete", envelopes: [key] });
    expect(await c.author.readHead()).toEqual(key);
    expect(c.receiver.snapshot).toBe(snapshot);
    await expect(c.receiver.receive(key)).resolves.toMatchObject({ status: "duplicate" });
    expect(c.receiver.snapshot).toBe(snapshot);
  });

  it("requires native bound dependencies, a roster identity, a valid round and positive limits", () => {
    const c = persistentSetupFixture();
    const other = new SessionChainRegistry(c.gameId, c.roster);
    expect(c.receiver.isBoundTo(c.registry)).toBe(true);
    expect(c.receiver.isBoundTo(other)).toBe(false);
    for (const options of [
      { ...c.options, session: {} as SessionChainRegistry },
      { ...c.options, sessionReceiver: { receive: c.durable.receive.bind(c.durable) } as PersistentSessionReceiver },
      { ...c.options, sessionReceiver: new PersistentSessionReceiver(other, c.store) },
      { ...c.options, self: c.identities[3]!.publicKey },
    ]) expect(() => new PersistentSetupReceiver(options)).toThrow(TypeError);
    for (const round of [-1, -0, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => new PersistentSetupReceiver({ ...c.options, round })).toThrow(RangeError);
    }
    for (const limit of [0, -1, 0.5, NaN, Infinity]) {
      expect(() => new PersistentSetupReceiver({ ...c.options, maxPendingEnvelopes: limit })).toThrow(RangeError);
      expect(() => new PersistentSetupReceiver({ ...c.options, maxPendingBytes: limit })).toThrow(RangeError);
    }
    c.receiver.gameId.fill(0xff);
    c.receiver.self.fill(0xff);
    c.receiver.roster[0]!.fill(0xff);
    expect(c.receiver.gameId).toEqual(c.gameId);
    expect(c.receiver.self).toEqual(c.self);
    expect(c.receiver.roster).toEqual(c.roster);
    expect(c.receiver.round).toBe(c.round);
    expect(c.receiver.closed).toBe(false);
    expect(c.receiver.failure).toBeNull();
    expect(() => c.receiver.getCompletedSetup()).toThrow(expect.objectContaining({ code: "setup_incomplete" }));
  });

  it("rejects corrupt, empty and oversized artifacts with coded errors without consuming capacity", async () => {
    const c = persistentSetupFixture();
    const key = await keyEnvelope(c, 1);
    const corrupt = decodeAndVerifyEnvelope(key.canonicalBytes);
    const last = corrupt.canonicalBytes.length - 1;
    corrupt.canonicalBytes[last] = corrupt.canonicalBytes[last]! ^ 1;
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope");
    for (const artifact of [corrupt, { canonicalBytes: new Uint8Array() }, { canonicalBytes: new Uint8Array(MAX_SETUP_ENVELOPE_BYTES + 1) }]) {
      await expect(c.receiver.receive(artifact as EnvelopeArtifact)).rejects.toMatchObject({ name: "PersistentSetupReceiverError", code: "invalid_envelope" });
      expect(c.receiver.pendingEnvelopes).toBe(0);
      expect(c.receiver.pendingBytes).toBe(0);
    }
    expect(write).not.toHaveBeenCalled();
    expect(c.receiver.failure).toBeNull();
    await expect(c.receiver.receive(key)).resolves.toMatchObject({ status: "accepted" });
  });

  it.each(["envelopes", "bytes"] as const)("bounds pending %s and releases capacity after drain", async (kind) => {
    const c = persistentSetupFixture({ maxPendingEnvelopes: kind === "envelopes" ? 1 : 32 });
    const keys = await Promise.all([keyEnvelope(c, 0), keyEnvelope(c, 1)]);
    const receiver = kind === "bytes" ? new PersistentSetupReceiver({ ...c.options, maxPendingBytes: keys[0]!.canonicalBytes.length }) : c.receiver;
    const gate = deferred();
    const started = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (artifact) => {
      started.resolve();
      await gate.promise;
      return persist(artifact);
    });
    const pending = receiver.receive(keys[0]!);
    try {
      await started.promise;
      await expect(receiver.receive(keys[1]!)).rejects.toMatchObject({ code: "queue_limit" });
      expect(receiver.pendingEnvelopes).toBe(1);
      expect(receiver.pendingBytes).toBe(keys[0]!.canonicalBytes.length);
    } finally { gate.resolve(); }
    await pending;
    await receiver.whenIdle();
    expect(receiver.pendingEnvelopes).toBe(0);
    expect(receiver.pendingBytes).toBe(0);
    await expect(receiver.receive(keys[1]!)).resolves.toMatchObject({ status: "accepted" });
  });

  it("closes queued admission while allowing an in-flight durable receipt to finish", async () => {
    const c = persistentSetupFixture();
    const keys = await Promise.all([keyEnvelope(c, 0), keyEnvelope(c, 1)]);
    const gate = deferred();
    const started = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (artifact) => {
      started.resolve();
      await gate.promise;
      return persist(artifact);
    });
    const active = c.receiver.receive(keys[0]!);
    const queued = expect(c.receiver.receive(keys[1]!)).rejects.toMatchObject({ code: "closed" });
    const idle = vi.fn();
    const draining = c.receiver.whenIdle().then(idle);
    try {
      await started.promise;
      c.receiver.close();
      c.receiver.close();
      await queued;
      expect(c.receiver.closed).toBe(true);
      expect(c.receiver.pendingEnvelopes).toBe(1);
      expect(idle).not.toHaveBeenCalled();
      await expect(c.receiver.receive(keys[1]!)).rejects.toMatchObject({ code: "closed" });
    } finally { gate.resolve(); }
    await expect(active).resolves.toMatchObject({ status: "accepted" });
    await draining;
    expect(write).toHaveBeenCalledTimes(1);
    expect(c.receiver.pendingBytes).toBe(0);
    expect(c.receiver.snapshot.pendingSenders).toEqual([1, 2]);
    expect(c.receiver.failure).toBeNull();
  });

  it("fails closed and rejects queued work when private setup classification throws", async () => {
    const c = persistentSetupFixture();
    const keys = await Promise.all([keyEnvelope(c, 1), keyEnvelope(c, 2)]);
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope");
    const before = c.receiver.snapshot;
    const heads = c.registry.heads();
    const cause = new Error("Unexpected setup classification failure");
    let queued!: ReturnType<PersistentSetupReceiver["receive"]>;
    const classify = vi.spyOn(SetupEnvelopeCoordinator.prototype, "classify").mockImplementationOnce((received) => {
      expect(received).toEqual(keys[0]);
      expect(received.canonicalBytes).not.toBe(keys[0]!.canonicalBytes);
      // Classification is synchronous; admit the second operation before the first triggers terminal failure.
      queued = c.receiver.receive(keys[1]!);
      expect(c.receiver.pendingEnvelopes).toBe(2);
      expect(c.receiver.pendingBytes).toBe(keys[0]!.canonicalBytes.length + keys[1]!.canonicalBytes.length);
      throw cause;
    });
    const first = c.receiver.receive(keys[0]!);
    const idle = c.receiver.whenIdle();
    await expect(Promise.allSettled([first, queued])).resolves.toMatchObject([
      { status: "rejected", reason: { code: "recovery_required" } },
      { status: "rejected", reason: { code: "recovery_required" } },
    ]);
    expect(c.receiver.failure).toBeInstanceOf(PersistentSetupReceiverError);
    expect(c.receiver.failure?.cause).toBe(cause);
    await expect(first).rejects.toBe(c.receiver.failure);
    await expect(queued).rejects.toBe(c.receiver.failure);
    await expect(idle).resolves.toBeUndefined();
    await expect(c.receiver.receive(keys[0]!)).rejects.toBe(c.receiver.failure);
    expect(() => c.receiver.getCompletedSetup()).toThrow(c.receiver.failure!);
    expect(classify).toHaveBeenCalledTimes(1);
    expect(write).not.toHaveBeenCalled();
    expect(c.store.artifacts()).toEqual([]);
    expect(c.registry.heads()).toEqual(heads);
    expect(c.receiver.snapshot).toBe(before);
    expect(c.receiver.pendingEnvelopes).toBe(0);
    expect(c.receiver.pendingBytes).toBe(0);
  });

  it("fails closed and rejects queued work when durable receipt violates its artifact invariant", async () => {
    const c = persistentSetupFixture();
    const keys = await Promise.all([keyEnvelope(c, 1), keyEnvelope(c, 2)]);
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope").mockResolvedValueOnce({ status: "stored", record: { artifact: keys[1]! } });
    const before = c.receiver.snapshot;
    const first = c.receiver.receive(keys[0]!);
    const queued = c.receiver.receive(keys[1]!);
    await expect(Promise.allSettled([first, queued])).resolves.toMatchObject([
      { status: "rejected", reason: { code: "recovery_required" } },
      { status: "rejected", reason: { code: "recovery_required" } },
    ]);
    expect(c.receiver.failure).toBeInstanceOf(PersistentSetupReceiverError);
    await expect(first).rejects.toBe(c.receiver.failure);
    await expect(queued).rejects.toBe(c.receiver.failure);
    await expect(c.receiver.receive(keys[0]!)).rejects.toBe(c.receiver.failure);
    expect(() => c.receiver.getCompletedSetup()).toThrow(c.receiver.failure!);
    expect(c.receiver.snapshot).toBe(before);
    expect(c.registry.heads()).toEqual([]);
    expect(c.receiver.pendingEnvelopes).toBe(0);
    expect(c.receiver.pendingBytes).toBe(0);
    expect(write).toHaveBeenCalledTimes(1);
  });

  it("hands off only completed idle setup, including after close and read-only restoration", async () => {
    const c = persistentSetupFixture();
    const originals = await completeSetup(c);
    const setup = c.receiver.getCompletedSetup();
    expect(setup).toBeInstanceOf(SetupEnvelopeCoordinator);
    expect(setup.state).toBe("complete");
    expect(setup.seed).toEqual(sha256(...c.beaconSecrets));
    expect(c.receiver.snapshot.seed).toBe(bytesToHex(setup.seed!));
    const duplicate = c.receiver.receive(originals[0]!);
    expect(() => c.receiver.getCompletedSetup()).toThrow(expect.objectContaining({ code: "setup_incomplete" }));
    await duplicate;
    c.receiver.close();
    expect(c.receiver.getCompletedSetup()).toBe(setup);
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope");
    const restored = new PersistentSetupReceiver(c.options);
    expect(restored.snapshot).toEqual(c.receiver.snapshot);
    expect(restored.getCompletedSetup()).not.toBe(setup);
    expect(restored.getCompletedSetup().seed).toEqual(setup.seed);
    expect(write).not.toHaveBeenCalled();
    const records = c.store.artifacts();
    expect(records.filter(({ authored }) => authored).map(({ artifact }) => artifact.envelope.type)).toEqual(["KEY_SHARE", "RAND_COMMIT", "RAND_REVEAL"]);
    expect(records.filter(({ authored }) => !authored)).toHaveLength(6);
    expect(await c.store.readAuthoredHead(c.gameId, c.roster[1]!)).toBeNull();
  });
});

function keyEnvelope(c: Fixture, seat: number, share = c.shares[seat]!) {
  return c.authors[seat]!.author({ round: c.round, phase: "setup.keys", type: "KEY_SHARE", body: encodeGameKeyShareBody(share) });
}

async function completeSetup(c: Fixture) {
  const originals: EnvelopeArtifact[] = [];
  for (const type of ["KEY_SHARE", "RAND_COMMIT", "RAND_REVEAL"] as const) {
    for (let seat = 0; seat < c.roster.length; seat += 1) {
      const artifact = type === "KEY_SHARE" ? await keyEnvelope(c, seat) : await c.authors[seat]!.author({
        round: c.round, phase: "setup.rand", type, body: type === "RAND_COMMIT"
          ? encodeRandCommitBody({ cm: parseHash256(beaconCommitment(c.gameId, c.round, seat, c.beaconSecrets[seat]!)) })
          : encodeRandRevealBody({ s: c.beaconSecrets[seat]! }),
      });
      await expect(c.receiver.receive(artifact)).resolves.toMatchObject({ status: "accepted" });
      originals.push(artifact);
    }
  }
  return originals;
}
