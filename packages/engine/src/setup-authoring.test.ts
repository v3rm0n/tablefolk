import { bytesToHex, RISTRETTO_SCALAR_ORDER, RistrettoPoint, scalarFromBigInt, sha256, type RandomSource, type RistrettoScalar } from "@p2pcards/crypto";
import * as deck from "@p2pcards/deck";
import { decodeGameKeyShareBody, encodeGameKeyShareBody, verifyGameKeyShare } from "@p2pcards/deck";
import type { CborMap } from "@p2pcards/encoding";
import * as protocol from "@p2pcards/protocol";
import {
  beaconCommitment, decodeAndVerifyEnvelope, decodeRandCommitBody, decodeRandRevealBody,
  encodeRandCommitBody, encodeRandRevealBody, parseGameId, parseHash256, parseRandomSecret,
  type EnvelopeArtifact, type GameId, type RandomSecret, type SetupBeaconScope,
} from "@p2pcards/protocol";
import { PersistentEnvelopeAuthor, PersistentSessionReceiver, SessionChainRegistry } from "@p2pcards/session";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as protocolRandom from "../../crypto/src/random";
import type { SetupBeaconSecretReader } from "./local-beacon-contribution";
import {
  DEFAULT_MAX_PENDING_SETUP_BYTES, DEFAULT_MAX_PENDING_SETUP_ENVELOPES, MAX_SETUP_ENVELOPE_BYTES,
  PersistentSetupReceiver, type PersistentSetupSnapshot,
} from "./persistent-setup-receiver";
import { deferred, MemoryStore, persistentSetupFixture } from "./persistent-setup.test-fixture";
import { SetupEnvelopeCoordinator } from "./setup-envelope-coordinator";

type Fixture = ReturnType<typeof persistentSetupFixture>;
type Secrets = ReturnType<typeof secretStores>;
const TYPES = ["KEY_SHARE", "RAND_COMMIT", "RAND_REVEAL"] as const;
type SetupType = typeof TYPES[number];

afterEach(() => vi.restoreAllMocks());

describe("persistent setup authoring admission", () => {
  it("completes 3 through 8 seats with one local owner and original native remote artifacts", async () => {
    for (let seats = 3; seats <= 8; seats += 1) {
      const c = persistentSetupFixture({ seats, selfSeat: seats - 2, round: seats });
      const secrets = secretStores(c);
      const originals: EnvelopeArtifact[] = [];
      const author = vi.spyOn(c.author, "author");
      const rng = vi.spyOn(c.source, "fill");
      for (const type of TYPES) {
        for (let seat = 0; seat < seats; seat += 1) {
          const remote = seat === c.selfSeat ? null : await native(c, seat, type);
          const result = remote === null ? await local(c, secrets, type) : await c.receiver.receive(remote);
          expect(result).toMatchObject({
            status: "accepted", transition: { seat }, chainResult: {
              status: "accepted", persistenceStatus: remote === null ? "duplicate" : "stored",
            },
          });
          if (result.status === "rejected") throw new Error("Fixture contribution rejected");
          const original = await c.authors[seat]!.readHead();
          expect(result.received).toEqual(original);
          expect(result.received.envelope).toMatchObject({
            game: c.gameId, from: c.roster[seat], round: c.round, type,
            phase: type === "KEY_SHARE" ? "setup.keys" : "setup.rand", seq: TYPES.indexOf(type),
          });
          expect(result.received.envelope.prev).toEqual(type === "KEY_SHARE"
            ? new Uint8Array(32) : originals[originals.length - seats]!.hash);
          expect(c.registry.classify(result.received).status).toBe("duplicate");
          expect(result.snapshot).toBe(c.receiver.snapshot);
          const view = c.receiver.snapshot;
          expect(Object.keys(view).sort()).toEqual(["aggregateKey", "commitments", "pendingSenders", "publicKeys", "seed", "state"]);
          for (const value of [view, view.pendingSenders, view.publicKeys, view.commitments]) expect(Object.isFrozen(value)).toBe(true);
          for (const value of [...view.publicKeys, ...view.commitments, view.aggregateKey, view.seed]) {
            if (value !== null) expect(value).toMatch(/^[0-9a-f]{64}$/);
          }
          if (type === "KEY_SHARE") {
            const share = decodeGameKeyShareBody(result.received.envelope.body);
            expect(verifyGameKeyShare({ gameId: c.gameId, round: c.round, phase: "setup.keys" }, share)).toBe(true);
            expect(share.H.toBytes()).toEqual(c.shares[seat]!.H.toBytes());
          } else if (type === "RAND_COMMIT") {
            expect(decodeRandCommitBody(result.received.envelope.body).cm).toEqual(beaconCommitment(c.gameId, c.round, seat, c.beaconSecrets[seat]!));
          } else expect(decodeRandRevealBody(result.received.envelope.body).s).toEqual(c.beaconSecrets[seat]);
          originals.push(decodeAndVerifyEnvelope(result.received.canonicalBytes));
        }
      }
      await c.receiver.whenIdle();
      expect(c.receiver.snapshot).toMatchObject({
        state: "complete", pendingSenders: [], seed: bytesToHex(sha256(...c.beaconSecrets)),
        aggregateKey: bytesToHex(RistrettoPoint.base().multiply(scalarFromBigInt(BigInt(seats * (seats + 1) / 2))).toBytes()),
      });
      expect(author).toHaveBeenCalledTimes(3);
      expect(rng).toHaveBeenCalledTimes(1);
      expect(secrets.keys.getOrCreateGameSecret).toHaveBeenCalledExactlyOnceWith(c.gameId, expect.any(Function));
      expect(secrets.beacon.getOrCreateSetupBeaconSecret).toHaveBeenCalledExactlyOnceWith(scope(c), expect.any(Function));
      expect(secrets.beacon.loadSetupBeaconSecret).toHaveBeenCalledExactlyOnceWith(scope(c));
      expect(c.store.artifacts().filter(({ authored }) => authored)).toHaveLength(3);
      expect(c.store.artifacts().filter(({ authored }) => !authored)).toHaveLength(3 * (seats - 1));
      expect(await c.store.readAuthoredHead(c.gameId, c.roster[(c.selfSeat + 1) % seats]!)).toBeNull();
      const completed = c.receiver.getCompletedSetup();
      expect(completed).toBeInstanceOf(SetupEnvelopeCoordinator);
      expect(completed.seed).toEqual(sha256(...c.beaconSecrets));
      const before = c.receiver.snapshot;
      const original = originals.find(({ envelope }) => envelope.type === "KEY_SHARE" && bytesToHex(envelope.from) === bytesToHex(c.self))!;
      await expect(c.receiver.receive(original)).resolves.toMatchObject({ status: "duplicate" });
      expect(c.receiver.snapshot).toBe(before);
      expect(c.receiver.failure).toBeNull();
    }
  }, 20_000);

  it("rejects early reveals before even reading the native head or secret-reader property", async () => {
    for (const phase of ["keys", "rand_commit"] as const) {
      vi.restoreAllMocks();
      const c = persistentSetupFixture();
      if (phase === "rand_commit") {
        await advanceTo(c, "RAND_COMMIT");
        await c.receiver.receive(await native(c, c.selfSeat, "RAND_COMMIT"));
      }
      const secrets = secretStores(c);
      const trace = observe(c);
      const access = vi.fn(() => secrets.beacon.loadSetupBeaconSecret);
      const reader = Object.defineProperty({}, "loadSetupBeaconSecret", { get: access }) as SetupBeaconSecretReader;
      const before = c.receiver.snapshot;
      await expect(c.receiver.authorRandReveal(c.author, reader, before)).rejects.toMatchObject({ code: "wrong_phase" });
      for (const spy of [access, ...Object.values(trace), ...Object.values(secrets.beacon)]) expect(spy).not.toHaveBeenCalled();
      expect(c.receiver.snapshot).toBe(before);
      expect(c.receiver.failure).toBeNull();
      expect(c.receiver.pendingBytes).toBe(0);
    }
  });

  it("never prepares another PoP for an accepted local key, including a reconstructed owner", async () => {
    const c = persistentSetupFixture();
    const original = await native(c, c.selfSeat, "KEY_SHARE");
    await c.receiver.receive(original);
    c.receiver.close();
    c.receiver = new PersistentSetupReceiver(c.options);
    const secrets = secretStores(c);
    const trace = observe(c);
    const before = c.receiver.snapshot;
    await expect(local(c, secrets, "KEY_SHARE")).rejects.toMatchObject({ code: "already_contributed" });
    expect(secrets.keys.getOrCreateGameSecret).not.toHaveBeenCalled();
    for (const spy of Object.values(trace)) expect(spy).not.toHaveBeenCalled();
    await expect(c.receiver.receive(original)).resolves.toMatchObject({ status: "duplicate" });
    expect(c.receiver.snapshot).toBe(before);
    expect(c.receiver.failure).toBeNull();
  });

  it("does not draw fresh commitment entropy or load an already consumed reveal", async () => {
    for (const type of ["RAND_COMMIT", "RAND_REVEAL"] as const) {
      vi.restoreAllMocks();
      const c = persistentSetupFixture({ selfSeat: 1 });
      await advanceTo(c, type);
      const original = await native(c, c.selfSeat, type);
      await c.receiver.receive(original);
      const secrets = secretStores(c);
      const trace = observe(c);
      const before = c.receiver.snapshot;
      await expect(local(c, secrets, type)).rejects.toMatchObject({ code: "already_contributed" });
      for (const spy of [...Object.values(trace), ...Object.values(secrets.beacon)]) expect(spy).not.toHaveBeenCalled();
      await expect(c.receiver.receive(original)).resolves.toMatchObject({ status: "duplicate" });
      expect(c.receiver.snapshot).toBe(before);
      expect(c.receiver.failure).toBeNull();
    }
  });

  it("requires the exact cached snapshot, not a copy, an equal foreign view, or a stale same-phase view", async () => {
    for (const type of TYPES) {
      vi.restoreAllMocks();
      const c = persistentSetupFixture();
      await advanceTo(c, type);
      const before = c.receiver.snapshot;
      const other = new PersistentSetupReceiver(c.options);
      expect(other.snapshot).toEqual(before);
      expect(other.snapshot).not.toBe(before);
      other.close();
      const secrets = secretStores(c);
      const incoming = await native(c, 1, type);
      const trace = observe(c);
      for (const expected of [{ ...before }, other.snapshot]) {
        await expect(local(c, secrets, type, expected)).rejects.toMatchObject({ code: "stale_setup" });
      }
      await c.receiver.receive(incoming);
      expect(c.receiver.snapshot.state).toBe(before.state);
      await expect(local(c, secrets, type, before)).rejects.toMatchObject({ code: "stale_setup" });
      for (const spy of [trace.head, trace.author, trace.proof, trace.rng, trace.sign,
        secrets.keys.getOrCreateGameSecret, ...Object.values(secrets.beacon)]) expect(spy).not.toHaveBeenCalled();
      expect(c.receiver.failure).toBeNull();
      expect(c.receiver.pendingEnvelopes).toBe(0);
      expect(c.receiver.pendingBytes).toBe(0);
      await expect(local(c, secrets, type)).resolves.toMatchObject({ status: "accepted" });
    }
  });

  it("requires a native author for this game and this owner's identity for every author API", async () => {
    const c = persistentSetupFixture({ selfSeat: 1 });
    const secrets = secretStores(c);
    const wrongGame = new PersistentEnvelopeAuthor(parseGameId(new Uint8Array(16).fill(0x42)), c.identities[1]!.secretKey, new MemoryStore());
    const stranger = new PersistentEnvelopeAuthor(c.gameId, c.identities[3]!.secretKey, new MemoryStore());
    const fake = { gameId: c.gameId, sender: c.self, author: vi.fn(), readHead: vi.fn() };
    const trace = observe(c);
    const reads = vi.spyOn(PersistentEnvelopeAuthor.prototype, "readHead");
    for (const author of [c.authors[0]!, wrongGame, stranger, fake as unknown as PersistentEnvelopeAuthor]) {
      const view = c.receiver.snapshot;
      await expect(c.receiver.authorKeyShare(author, secrets.keys, view, c.source)).rejects.toMatchObject({ code: "unexpected_author" });
      await expect(c.receiver.authorRandCommit(author, secrets.beacon, view, c.source)).rejects.toMatchObject({ code: "unexpected_author" });
      await expect(c.receiver.authorRandReveal(author, secrets.beacon, view)).rejects.toMatchObject({ code: "unexpected_author" });
    }
    for (const spy of [reads, fake.author, fake.readHead, ...Object.values(trace),
      secrets.keys.getOrCreateGameSecret, ...Object.values(secrets.beacon)]) expect(spy).not.toHaveBeenCalled();
    expect(c.receiver.failure).toBeNull();
    expect(c.receiver.pendingBytes).toBe(0);
  });

  it("allows another peer's queued same-phase receipt ahead of local preparation and native beforeSign", async () => {
    for (const type of TYPES) {
      vi.restoreAllMocks();
      const c = persistentSetupFixture();
      await advanceTo(c, type);
      const incoming = await native(c, 1, type);
      const secrets = secretStores(c);
      const before = c.receiver.snapshot;
      const gate = deferred();
      const entered = deferred();
      const persist = c.store.persistAcceptedEnvelope.bind(c.store);
      vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (artifact) => {
        entered.resolve(); await gate.promise; return persist(artifact);
      });
      const nativeAuthor = c.author.author.bind(c.author);
      const guard = vi.fn();
      vi.spyOn(c.author, "author").mockImplementationOnce((content, beforeSign) => nativeAuthor(content, (head) => {
        guard();
        expect(c.receiver.snapshot).not.toBe(before);
        expect(c.receiver.snapshot.state).toBe(before.state);
        expect(c.receiver.snapshot.pendingSenders).toEqual([0, 2]);
        expect(c.registry.classify(incoming).status).toBe("duplicate");
        return beforeSign!(head);
      }));
      const received = c.receiver.receive(incoming);
      const pending = local(c, secrets, type, before);
      try {
        await entered.promise;
        for (const spy of [secrets.keys.getOrCreateGameSecret, ...Object.values(secrets.beacon)]) expect(spy).not.toHaveBeenCalled();
        expect(c.receiver.pendingBytes).toBe(incoming.canonicalBytes.length + MAX_SETUP_ENVELOPE_BYTES);
      } finally { gate.resolve(); }
      await expect(received).resolves.toMatchObject({ status: "accepted" });
      await expect(pending).resolves.toMatchObject({ status: "accepted", received: { envelope: { type } } });
      expect(guard).toHaveBeenCalledOnce();
      expect(c.receiver.snapshot.pendingSenders).toEqual([2]);
      expect(c.receiver.failure).toBeNull();
    }
  });

  it("does not retarget duplicate local requests or prematurely queued next-phase work", async () => {
    for (const type of TYPES) {
      for (const last of [false, true]) {
        vi.restoreAllMocks();
        const c = persistentSetupFixture();
        await advanceTo(c, type);
        if (last) for (const seat of [1, 2]) await c.receiver.receive(await native(c, seat, type));
        const secrets = secretStores(c);
        const trace = observe(c);
        const before = c.receiver.snapshot;
        const first = local(c, secrets, type, before);
        const duplicate = expect(local(c, secrets, type, before)).rejects.toMatchObject({ code: last ? "stale_setup" : "already_contributed" });
        const next = type === "RAND_REVEAL" ? Promise.resolve() : expect(local(c, secrets,
          type === "KEY_SHARE" ? "RAND_COMMIT" : "RAND_REVEAL", before)).rejects.toMatchObject({ code: "wrong_phase" });
        await expect(first).resolves.toMatchObject({ status: "accepted" });
        await Promise.all([duplicate, next]);
        for (const spy of [trace.head, trace.author, trace.append, trace.receipt, trace.sign]) expect(spy).toHaveBeenCalledOnce();
        expect(secrets.keys.getOrCreateGameSecret).toHaveBeenCalledTimes(type === "KEY_SHARE" ? 1 : 0);
        expect(secrets.beacon.getOrCreateSetupBeaconSecret).toHaveBeenCalledTimes(type === "RAND_COMMIT" ? 1 : 0);
        expect(secrets.beacon.loadSetupBeaconSecret).toHaveBeenCalledTimes(type === "RAND_REVEAL" ? 1 : 0);
        expect(trace.rng).toHaveBeenCalledTimes(type === "KEY_SHARE" ? 1 : 0);
        expect(c.receiver.failure).toBeNull();
        expect(c.receiver.pendingBytes).toBe(0);
      }
    }
  });

  it("rejects private work when an original local contribution is received ahead of its queued request", async () => {
    for (const type of TYPES) {
      vi.restoreAllMocks();
      const c = persistentSetupFixture();
      await advanceTo(c, type);
      const original = await native(c, c.selfSeat, type);
      const secrets = secretStores(c);
      const trace = observe(c);
      const before = c.receiver.snapshot;
      const received = c.receiver.receive(original);
      const queued = expect(local(c, secrets, type, before)).rejects.toMatchObject({ code: "already_contributed" });
      await expect(received).resolves.toMatchObject({ status: "accepted" });
      await queued;
      for (const spy of [trace.head, trace.author, trace.proof, trace.rng, trace.sign,
        secrets.keys.getOrCreateGameSecret, ...Object.values(secrets.beacon)]) expect(spy).not.toHaveBeenCalled();
      expect(c.receiver.failure).toBeNull();
      expect(c.receiver.snapshot.pendingSenders).toEqual([1, 2]);
    }
  });
});

describe("persistent setup private-work boundaries", () => {
  it("waits for fresh secret commit before proof/hash, and for append plus receipt before publishing", async () => {
    for (const type of ["KEY_SHARE", "RAND_COMMIT"] as const) {
      vi.restoreAllMocks();
      const c = persistentSetupFixture();
      await advanceTo(c, type);
      const secrets = secretStores(c, true);
      const append = c.store.appendNext.bind(c.store);
      const trace = observe(c);
      const secretGate = deferred();
      const selected = deferred();
      if (type === "KEY_SHARE") secrets.keys.getOrCreateGameSecret.mockImplementationOnce(async (game, create) => {
        const secret = create(); selected.resolve(); await secretGate.promise;
        secrets.gameSecrets.set(bytesToHex(game), secret); return secret;
      });
      else secrets.beacon.getOrCreateSetupBeaconSecret.mockImplementationOnce(async (requested, create) => {
        const secret = create(); selected.resolve(); await secretGate.promise;
        secrets.beaconSecrets.set(scopeKey(requested), parseRandomSecret(secret)); return parseRandomSecret(secret);
      });
      const appendGate = deferred();
      const appended = deferred();
      trace.append.mockImplementationOnce(async (...args) => {
        await append(...args); appended.resolve(); await appendGate.promise;
      });
      const receiptGate = deferred();
      const receiving = deferred();
      const persist = c.store.persistAcceptedEnvelope.bind(c.store);
      vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (artifact) => {
        receiving.resolve(); await receiptGate.promise; return persist(artifact);
      });
      const before = c.receiver.snapshot;
      const published = vi.fn();
      const pending = local(c, secrets, type);
      void pending.then(published, () => undefined);
      try {
        await selected.promise;
        expect(trace.rng).toHaveBeenCalledOnce();
        for (const spy of [trace.proof, trace.commitment, trace.sign, trace.author, published]) expect(spy).not.toHaveBeenCalled();
        expect(c.receiver.snapshot).toBe(before);
        expect(secrets.gameSecrets.size + secrets.beaconSecrets.size).toBe(0);
        secretGate.resolve();
        await appended.promise;
        expect(trace.sign).toHaveBeenCalledOnce();
        expect(trace.receipt).not.toHaveBeenCalled();
        expect(published).not.toHaveBeenCalled();
        expect(c.receiver.snapshot).toBe(before);
        appendGate.resolve();
        await receiving.promise;
        expect(c.receiver.snapshot).toBe(before);
        expect(published).not.toHaveBeenCalled();
        expect(c.receiver.pendingBytes).toBe(MAX_SETUP_ENVELOPE_BYTES);
      } finally { secretGate.resolve(); appendGate.resolve(); receiptGate.resolve(); }
      const result = await pending;
      expect(result).toMatchObject({ status: "accepted", chainResult: { persistenceStatus: "duplicate" } });
      expect(result.received).toEqual(await c.author.readHead());
      expect(c.registry.classify(result.received).status).toBe("duplicate");
      expect(trace.rng).toHaveBeenCalledTimes(type === "KEY_SHARE" ? 2 : 1);
      expect(published).toHaveBeenCalledOnce();
      expect(c.receiver.pendingBytes).toBe(0);
    }
  });

  it("rejects a native authored head ahead of the accepted prefix before key/beacon access or RNG", async () => {
    for (const type of TYPES) {
      vi.restoreAllMocks();
      const c = persistentSetupFixture();
      await advanceTo(c, type);
      const ahead = await c.author.author({ round: c.round, phase: "setup.keys", type: "WITNESS", body: { heads: [] } });
      const secrets = secretStores(c, true);
      const trace = observe(c);
      const before = c.receiver.snapshot;
      await expect(local(c, secrets, type)).rejects.toMatchObject({ code: "recovery_required" });
      expect(trace.head).toHaveBeenCalledExactlyOnceWith(c.gameId, c.self);
      for (const spy of [trace.author, trace.proof, trace.commitment, trace.rng, trace.sign, trace.append,
        secrets.keys.getOrCreateGameSecret, ...Object.values(secrets.beacon)]) expect(spy).not.toHaveBeenCalled();
      expect(c.receiver.snapshot).toBe(before);
      expect(c.store.artifacts()).toContainEqual({ artifact: ahead, authored: true });
      await expect(local(c, secrets, type)).rejects.toBe(c.receiver.failure);
      expect(trace.head).toHaveBeenCalledOnce();
    }
  });

  it("requires native readAuthoredHead support and the original accepted predecessor bytes", async () => {
    for (const mode of ["unsupported", "accepted-only", "different-bytes"] as const) {
      vi.restoreAllMocks();
      const c = persistentSetupFixture();
      let author = c.author;
      if (mode === "unsupported") {
        author = new PersistentEnvelopeAuthor(c.gameId, c.identities[0]!.secretKey, { appendNext: c.store.appendNext.bind(c.store) });
      } else {
        const predecessor = await c.author.author({ round: c.round, phase: "setup.keys", type: "WITNESS", body: { heads: [] } });
        await c.durable.receive(predecessor);
        if (mode === "accepted-only") author = new PersistentEnvelopeAuthor(c.gameId, c.identities[0]!.secretKey, new MemoryStore());
        else {
          const substitute = protocol.signEnvelope({ ...predecessor.envelope, round: c.round + 1 }, c.identities[0]!.secretKey);
          vi.spyOn(c.registry, "readRange").mockReturnValueOnce({ status: "complete", envelopes: [substitute] });
        }
      }
      const secrets = secretStores(c);
      const trace = observe(c);
      const before = c.receiver.snapshot;
      await expect(c.receiver.authorKeyShare(author, secrets.keys, before, c.source)).rejects.toMatchObject({ code: "recovery_required" });
      for (const spy of [secrets.keys.getOrCreateGameSecret, trace.proof, trace.rng, trace.sign, trace.append]) expect(spy).not.toHaveBeenCalled();
      expect(c.receiver.snapshot).toBe(before);
      expect(c.receiver.pendingBytes).toBe(0);
    }
  });

  it("rechecks the native head before signing but permits matching housekeeping advancement during preparation", async () => {
    for (const accepted of [false, true]) {
      vi.restoreAllMocks();
      const c = persistentSetupFixture();
      const secrets = secretStores(c);
      const gate = deferred();
      const entered = deferred();
      secrets.keys.getOrCreateGameSecret.mockImplementationOnce(async () => {
        entered.resolve(); await gate.promise; return c.keys[0]!;
      });
      const before = c.receiver.snapshot;
      const pending = local(c, secrets, "KEY_SHARE");
      await entered.promise;
      const housekeeping = await c.author.author({ round: c.round, phase: "setup.keys", type: "WITNESS", body: { heads: [] } });
      if (accepted) await c.durable.receive(housekeeping);
      const sign = vi.spyOn(protocol, "signEnvelope");
      expect(c.receiver.snapshot).toBe(before);
      gate.resolve();
      if (accepted) {
        await expect(pending).resolves.toMatchObject({ status: "accepted", received: { envelope: { seq: 1, prev: housekeeping.hash } } });
        expect(sign).toHaveBeenCalledOnce();
        expect(c.receiver.failure).toBeNull();
      } else {
        await expect(pending).rejects.toMatchObject({ code: "recovery_required" });
        expect(sign).not.toHaveBeenCalled();
        expect(c.receiver.snapshot).toBe(before);
        expect(await c.author.readHead()).toEqual(housekeeping);
      }
      expect(secrets.keys.getOrCreateGameSecret).toHaveBeenCalledOnce();
    }
  });

  it("does not enter private preparation when close occurs during the native head read", async () => {
    for (const type of TYPES) {
      vi.restoreAllMocks();
      const c = persistentSetupFixture();
      await advanceTo(c, type);
      const secrets = secretStores(c);
      const read = c.store.readAuthoredHead.bind(c.store);
      const trace = observe(c);
      const gate = deferred();
      const entered = deferred();
      trace.head.mockImplementationOnce(async (...args) => {
        entered.resolve(); await gate.promise; return read(...args);
      });
      const before = c.receiver.snapshot;
      const pending = expect(local(c, secrets, type)).rejects.toMatchObject({ code: "closed" });
      try { await entered.promise; c.receiver.close(); }
      finally { gate.resolve(); }
      await pending;
      for (const spy of [trace.proof, trace.commitment, trace.rng, trace.sign, trace.author, trace.append,
        secrets.keys.getOrCreateGameSecret, ...Object.values(secrets.beacon)]) expect(spy).not.toHaveBeenCalled();
      expect(c.receiver.snapshot).toBe(before);
      expect(c.receiver.failure).toBeNull();
      await c.receiver.whenIdle();
      expect(c.receiver.pendingBytes).toBe(0);
    }
  });

  it("checks close after awaited key/beacon load or commit, leaving submitted secrets safely unused", async () => {
    for (const mode of ["key-load", "key-create", "commit-load", "commit-create", "reveal-load"] as const) {
      vi.restoreAllMocks();
      const type = mode.startsWith("key") ? "KEY_SHARE" : mode.startsWith("commit") ? "RAND_COMMIT" : "RAND_REVEAL";
      const c = persistentSetupFixture();
      await advanceTo(c, type);
      const created = mode.endsWith("create");
      const secrets = secretStores(c, created);
      const trace = observe(c);
      const gate = deferred();
      const entered = deferred();
      if (type === "KEY_SHARE") secrets.keys.getOrCreateGameSecret.mockImplementationOnce(async (game, create) => {
        const selected = created ? create() : c.keys[0]!;
        entered.resolve(); await gate.promise;
        secrets.gameSecrets.set(bytesToHex(game), selected); return selected;
      });
      else if (type === "RAND_COMMIT") secrets.beacon.getOrCreateSetupBeaconSecret.mockImplementationOnce(async (requested, create) => {
        const selected = created ? create() : c.beaconSecrets[0]!;
        entered.resolve(); await gate.promise;
        secrets.beaconSecrets.set(scopeKey(requested), parseRandomSecret(selected)); return selected;
      });
      else secrets.beacon.loadSetupBeaconSecret.mockImplementationOnce(async () => {
        entered.resolve(); await gate.promise; return c.beaconSecrets[0]!;
      });
      const before = c.receiver.snapshot;
      const records = c.store.artifacts();
      const pending = expect(local(c, secrets, type)).rejects.toMatchObject({ code: "closed" });
      try {
        await entered.promise;
        c.receiver.close();
        expect(c.receiver.pendingEnvelopes).toBe(1);
      } finally { gate.resolve(); }
      await pending;
      for (const spy of [trace.proof, trace.commitment, trace.author, trace.sign, trace.append, trace.receipt]) expect(spy).not.toHaveBeenCalled();
      expect(trace.rng).toHaveBeenCalledTimes(created ? 1 : 0);
      expect(type === "KEY_SHARE" ? secrets.gameSecrets.size : secrets.beaconSecrets.size).toBe(1);
      expect(c.store.artifacts()).toEqual(records);
      expect(c.receiver.snapshot).toBe(before);
      expect(c.receiver.failure).toBeNull();
      expect(c.receiver.pendingBytes).toBe(0);
    }
  });

  it("checks close inside a delayed secret creator before its first entropy draw", async () => {
    for (const type of ["KEY_SHARE", "RAND_COMMIT"] as const) {
      vi.restoreAllMocks();
      const c = persistentSetupFixture();
      await advanceTo(c, type);
      const secrets = secretStores(c, true);
      const gate = deferred();
      const entered = deferred();
      if (type === "KEY_SHARE") secrets.keys.getOrCreateGameSecret.mockImplementationOnce(async (_game, create) => {
        entered.resolve(); await gate.promise; return create();
      });
      else secrets.beacon.getOrCreateSetupBeaconSecret.mockImplementationOnce(async (_scope, create) => {
        entered.resolve(); await gate.promise; return create();
      });
      const trace = observe(c);
      const pending = expect(local(c, secrets, type)).rejects.toMatchObject({ code: "closed" });
      try { await entered.promise; c.receiver.close(); }
      finally { gate.resolve(); }
      await pending;
      for (const spy of [trace.proof, trace.commitment, trace.rng, trace.random, trace.sign, trace.append]) expect(spy).not.toHaveBeenCalled();
      expect(secrets.gameSecrets.size + secrets.beaconSecrets.size).toBe(0);
      expect(c.receiver.failure).toBeNull();
    }
  });

  it("stops reentrant RNG retirement even on a rejected zero secret or PoP nonce draw", async () => {
    for (const stage of ["key-secret", "key-nonce", "beacon-secret"] as const) {
      for (const zero of [false, true]) {
        vi.restoreAllMocks();
        const c = persistentSetupFixture();
        const type = stage === "beacon-secret" ? "RAND_COMMIT" : "KEY_SHARE";
        await advanceTo(c, type);
        const secrets = secretStores(c, stage !== "key-nonce");
        const trace = observe(c);
        let cancelled: Promise<void> | undefined;
        const source = { fill: vi.fn((target: Uint8Array) => {
          if (source.fill.mock.calls.length > 1) throw new Error("Retired setup retried its RNG draw");
          cancelled = expect(local(c, secrets, type)).rejects.toMatchObject({ code: "closed" });
          c.receiver.close();
          target.fill(0); if (!zero) target[0] = 7;
        }) };
        const before = c.receiver.snapshot;
        await expect(local(c, secrets, type, before, source)).rejects.toMatchObject({ code: "closed" });
        await cancelled;
        expect(source.fill).toHaveBeenCalledOnce();
        expect(trace.proof).toHaveBeenCalledTimes(stage === "key-nonce" ? 1 : 0);
        for (const spy of [trace.commitment, trace.author, trace.sign, trace.append, trace.receipt]) expect(spy).not.toHaveBeenCalled();
        expect(c.receiver.snapshot).toBe(before);
        expect(c.receiver.failure).toBeNull();
        expect(c.receiver.pendingBytes).toBe(0);
      }
    }
  });

  it("allows retry after ordinary pre-permission head, secret, entropy, or append I/O errors", async () => {
    for (const boundary of ["head", "secret", "entropy", "append"] as const) {
      vi.restoreAllMocks();
      const c = persistentSetupFixture();
      const secrets = secretStores(c);
      const trace = observe(c);
      const error = new Error(`Unavailable ${boundary}`);
      if (boundary === "head") trace.head.mockRejectedValueOnce(error);
      if (boundary === "secret") secrets.keys.getOrCreateGameSecret.mockRejectedValueOnce(error);
      if (boundary === "entropy") trace.rng.mockImplementationOnce(() => { throw error; });
      if (boundary === "append") trace.append.mockRejectedValueOnce(error);
      const before = c.receiver.snapshot;
      await expect(local(c, secrets, "KEY_SHARE")).rejects.toBe(error);
      expect(trace.sign).not.toHaveBeenCalled();
      expect(c.receiver.snapshot).toBe(before);
      expect(c.receiver.failure).toBeNull();
      expect(c.store.artifacts()).toEqual([]);
      expect(c.receiver.pendingBytes).toBe(0);
      await expect(local(c, secrets, "KEY_SHARE", before)).resolves.toMatchObject({ status: "accepted" });
      expect(trace.sign).toHaveBeenCalledOnce();
      if (boundary === "append") {
        const first = decodeGameKeyShareBody(trace.author.mock.calls[0]![0].body);
        const retried = decodeGameKeyShareBody(trace.author.mock.calls[1]![0].body);
        expect(retried.H.toBytes()).toEqual(first.H.toBytes());
        expect(retried.pop.R.toBytes()).not.toEqual(first.pop.R.toBytes());
      }
    }
  });

  it("rejects substituted or multiply-created private store results without exposing a partial contribution", async () => {
    for (const type of ["KEY_SHARE", "RAND_COMMIT"] as const) {
      for (const mode of ["substitution", "repeated-creator"] as const) {
        vi.restoreAllMocks();
        const c = persistentSetupFixture();
        await advanceTo(c, type);
        const secrets = secretStores(c, true);
        if (type === "KEY_SHARE") secrets.keys.getOrCreateGameSecret.mockImplementationOnce(async (_game, create) => {
          const selected = create();
          if (mode === "substitution") return scalarFromBigInt(999n);
          try { create(); } catch { /* An invalid store swallows the second invocation. */ }
          return selected;
        });
        else secrets.beacon.getOrCreateSetupBeaconSecret.mockImplementationOnce(async (_scope, create) => {
          const selected = create();
          if (mode === "substitution") return selected.fill(0xff);
          try { create(); } catch { /* An invalid store swallows the second invocation. */ }
          return selected;
        });
        const trace = observe(c);
        const before = c.receiver.snapshot;
        const records = c.store.artifacts();
        const pending = local(c, secrets, type);
        if (type === "KEY_SHARE") await expect(pending).rejects.toBeInstanceOf(TypeError);
        else await expect(pending).rejects.toMatchObject({ code: "invalid_store_result" });
        for (const spy of [trace.proof, trace.commitment, trace.author, trace.sign, trace.append, trace.receipt]) expect(spy).not.toHaveBeenCalled();
        expect(trace.rng).toHaveBeenCalledOnce();
        expect(c.receiver.snapshot).toBe(before);
        expect(c.store.artifacts()).toEqual(records);
        expect(c.receiver.failure).toBeNull();
      }
    }
  });

  it("loads reveals against the actual accepted local commitment, without replacing missing or mismatched secrets", async () => {
    for (const mode of ["missing", "other-sender", "malformed"] as const) {
      vi.restoreAllMocks();
      const c = persistentSetupFixture({ selfSeat: 1 });
      await advanceTo(c, "RAND_REVEAL");
      const secrets = secretStores(c);
      const selected = mode === "missing" ? null : mode === "other-sender" ? c.beaconSecrets[0]! : new Uint8Array(31) as RandomSecret;
      secrets.beacon.loadSetupBeaconSecret.mockResolvedValueOnce(selected);
      const trace = observe(c);
      const before = c.receiver.snapshot;
      const records = c.store.artifacts();
      expect(Reflect.set(before.commitments, "1", bytesToHex(beaconCommitment(c.gameId, c.round, 1, c.beaconSecrets[0]!)))).toBe(false);
      await expect(local(c, secrets, "RAND_REVEAL")).rejects.toMatchObject({
        code: mode === "missing" ? "missing_secret" : mode === "other-sender" ? "commitment_mismatch" : "invalid_store_result",
      });
      expect(secrets.beacon.loadSetupBeaconSecret).toHaveBeenCalledExactlyOnceWith(scope(c));
      for (const spy of [trace.rng, trace.random, trace.proof, trace.author, trace.sign, trace.append,
        secrets.keys.getOrCreateGameSecret, secrets.beacon.getOrCreateSetupBeaconSecret]) expect(spy).not.toHaveBeenCalled();
      expect(c.store.artifacts()).toEqual(records);
      expect(c.receiver.snapshot).toBe(before);
      expect(c.receiver.failure).toBeNull();
      await expect(local(c, secrets, "RAND_REVEAL")).resolves.toMatchObject({ status: "accepted", received: { envelope: { body: { s: c.beaconSecrets[1] } } } });
      expect(secrets.beacon.loadSetupBeaconSecret).toHaveBeenCalledTimes(2);
      expect(secrets.beacon.getOrCreateSetupBeaconSecret).not.toHaveBeenCalled();
      expect(trace.random).not.toHaveBeenCalled();
    }
  });
});

describe("persistent setup signing, receipt and lifetime", () => {
  it("commits and publishes canonical key A when an ingest wrapper substitutes valid key B only in the decoded body", async () => {
    const c = persistentSetupFixture();
    const secrets = secretStores(c);
    const replacement = await native(c, 1, "KEY_SHARE");
    const context = { gameId: c.gameId, round: c.round, phase: "setup.keys" };
    const shareB = decodeGameKeyShareBody(replacement.envelope.body);
    expect(verifyGameKeyShare(context, shareB)).toBe(true);
    const ingest = SetupEnvelopeCoordinator.prototype.ingest;
    let original!: EnvelopeArtifact;
    const wrapper = vi.spyOn(SetupEnvelopeCoordinator.prototype, "ingest").mockImplementationOnce(function (this: SetupEnvelopeCoordinator, candidate) {
      original = decodeAndVerifyEnvelope(candidate.canonicalBytes);
      const shareA = decodeGameKeyShareBody(original.envelope.body);
      expect(verifyGameKeyShare(context, shareA)).toBe(true);
      expect(shareA.H.toBytes()).toEqual(c.shares[0]!.H.toBytes());
      expect(shareA.H.equals(shareB.H)).toBe(false);
      Object.assign(candidate.envelope.body as CborMap, replacement.envelope.body);
      expect(decodeGameKeyShareBody(candidate.envelope.body).H.toBytes()).toEqual(shareB.H.toBytes());
      expect(verifyGameKeyShare(context, decodeGameKeyShareBody(candidate.envelope.body))).toBe(true);
      expect(candidate.canonicalBytes).toEqual(original.canonicalBytes);
      return ingest.call(this, candidate);
    });

    const result = await local(c, secrets, "KEY_SHARE");
    expect(wrapper).toHaveBeenCalledOnce();
    expect(result).toMatchObject({ status: "accepted", transition: { seat: 0 }, chainResult: { persistenceStatus: "duplicate" } });
    if (result.status === "rejected") throw new Error("Canonical key A was rejected");
    for (const received of [result.received, result.transition.received, result.chainResult.received]) expect(received).toEqual(original);
    expect(result.snapshot).toBe(c.receiver.snapshot);
    expect(c.receiver.snapshot.publicKeys).toEqual([bytesToHex(c.shares[0]!.H.toBytes()), null, null]);
    expect(c.receiver.snapshot.pendingSenders).toEqual([1, 2]);
    expect(c.store.artifacts()).toEqual([{ artifact: original, authored: true }]);
    expect(await c.author.readHead()).toEqual(original);
    expect(c.registry.readRange(c.self, 0, 0)).toEqual({ status: "complete", envelopes: [original] });
    await expect(c.receiver.receive(original)).resolves.toMatchObject({ status: "duplicate" });
    expect(c.receiver.failure).toBeNull();
    expect(c.receiver.pendingBytes).toBe(0);
  });

  it("rejects a canonical bad key proof before persistence even when classify sees a substituted valid decoded proof", async () => {
    const c = persistentSetupFixture();
    const context = { gameId: c.gameId, round: c.round, phase: "setup.keys" };
    const otherContext = { ...context, round: c.round + 1 };
    const misplaced = deck.createGameKeyShare(otherContext, c.keys[1]!, c.source);
    expect(verifyGameKeyShare(otherContext, misplaced)).toBe(true);
    expect(verifyGameKeyShare(context, misplaced)).toBe(false);
    expect(verifyGameKeyShare(context, c.shares[1]!)).toBe(true);
    const original = await c.authors[1]!.author({
      round: c.round, phase: "setup.keys", type: "KEY_SHARE", body: encodeGameKeyShareBody(misplaced),
    });
    const classify = SetupEnvelopeCoordinator.prototype.classify;
    const wrapper = vi.spyOn(SetupEnvelopeCoordinator.prototype, "classify").mockImplementationOnce(function (this: SetupEnvelopeCoordinator, candidate) {
      expect(candidate).toEqual(original);
      Object.assign(candidate.envelope.body as CborMap, encodeGameKeyShareBody(c.shares[1]!));
      expect(verifyGameKeyShare(context, decodeGameKeyShareBody(candidate.envelope.body))).toBe(true);
      expect(candidate.canonicalBytes).toEqual(original.canonicalBytes);
      return classify.call(this, candidate);
    });
    const ingest = vi.spyOn(SetupEnvelopeCoordinator.prototype, "ingest");
    const receive = vi.spyOn(c.durable, "receive");
    const persist = vi.spyOn(c.store, "persistAcceptedEnvelope");
    const before = c.receiver.snapshot;

    const result = await c.receiver.receive(original);
    expect(result).toMatchObject({ status: "rejected", reason: "invalid_key_proof", state: "keys", seat: 1 });
    expect(result.received).toEqual(original);
    expect(verifyGameKeyShare(context, decodeGameKeyShareBody(result.received.envelope.body))).toBe(false);
    expect(wrapper).toHaveBeenCalledOnce();
    for (const spy of [ingest, receive, persist]) expect(spy).not.toHaveBeenCalled();
    expect(c.receiver.snapshot).toBe(before);
    expect(c.receiver.snapshot.publicKeys).toEqual([null, null, null]);
    expect(c.registry.heads()).toEqual([]);
    expect(c.store.artifacts()).toEqual([]);
    expect(c.receiver.failure).toBeNull();
    expect(c.receiver.pendingBytes).toBe(0);
  });

  it("cancels queued work on close, blocks pre-sign work, and finishes an already signed append and receipt", async () => {
    for (const boundary of ["before-sign", "after-sign", "receipt"] as const) {
      vi.restoreAllMocks();
      const c = persistentSetupFixture();
      const secrets = secretStores(c);
      const remote = await native(c, 1, "KEY_SHARE");
      const append = c.store.appendNext.bind(c.store);
      const read = c.store.readAuthoredHead.bind(c.store);
      const persist = c.store.persistAcceptedEnvelope.bind(c.store);
      const trace = observe(c);
      const gate = deferred();
      const entered = deferred();
      if (boundary === "receipt") vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (artifact) => {
        entered.resolve(); await gate.promise; return persist(artifact);
      });
      else trace.append.mockImplementationOnce(async (game, sender, create) => {
        const artifact = boundary === "after-sign" ? create(await read(game, sender)) : null;
        entered.resolve(); await gate.promise;
        await append(game, sender, artifact === null ? create : () => artifact);
      });
      const before = c.receiver.snapshot;
      const published = vi.fn();
      const pending = local(c, secrets, "KEY_SHARE");
      void pending.then(published, () => undefined);
      const queuedReceive = expect(c.receiver.receive(remote)).rejects.toMatchObject({ code: "closed" });
      const queuedAuthor = expect(local(c, secrets, "KEY_SHARE")).rejects.toMatchObject({ code: "closed" });
      const idle = vi.fn();
      const drained = c.receiver.whenIdle().then(idle);
      try {
        await entered.promise;
        c.receiver.close();
        await Promise.all([queuedReceive, queuedAuthor]);
        expect(trace.sign).toHaveBeenCalledTimes(boundary === "before-sign" ? 0 : 1);
        expect(published).not.toHaveBeenCalled();
        expect(idle).not.toHaveBeenCalled();
        expect(c.receiver.snapshot).toBe(before);
        expect(c.receiver.pendingEnvelopes).toBe(1);
        expect(c.receiver.pendingBytes).toBe(MAX_SETUP_ENVELOPE_BYTES);
        if (boundary !== "receipt") expect(c.store.artifacts()).toEqual([]);
      } finally { gate.resolve(); }
      if (boundary === "before-sign") {
        await expect(pending).rejects.toMatchObject({ code: "closed" });
        expect(trace.receipt).not.toHaveBeenCalled();
        expect(trace.sign).not.toHaveBeenCalled();
        expect(c.receiver.snapshot).toBe(before);
      } else {
        await expect(pending).resolves.toMatchObject({ status: "accepted", chainResult: { persistenceStatus: "duplicate" } });
        expect(trace.receipt).toHaveBeenCalledOnce();
        expect(published).toHaveBeenCalledOnce();
        expect(c.receiver.snapshot.pendingSenders).toEqual([1, 2]);
      }
      await drained;
      expect(c.receiver.failure).toBeNull();
      expect(c.receiver.pendingEnvelopes).toBe(0);
      expect(c.receiver.pendingBytes).toBe(0);
      await expect(local(c, secrets, "KEY_SHARE")).rejects.toMatchObject({ code: "closed" });
    }
  });

  it("correlates exact unsigned content against mutated author arguments and substituted signed return values", async () => {
    for (const type of TYPES) {
      for (const target of ["argument", "returned"] as const) {
        vi.restoreAllMocks();
        const c = persistentSetupFixture();
        await advanceTo(c, type);
        const secrets = secretStores(c);
        const author = c.author.author.bind(c.author);
        const trace = observe(c);
        let committed: EnvelopeArtifact | undefined;
        trace.author.mockImplementationOnce(async (content, guard) => {
          if (target === "argument") {
            const field = type === "KEY_SHARE" ? "H_i" : type === "RAND_COMMIT" ? "cm" : "s";
            ((content.body as CborMap)[field] as Uint8Array).fill(0xff);
          }
          committed = await author(content, guard);
          return target === "argument" ? committed : protocol.signEnvelope({ ...committed.envelope, round: c.round + 1 }, c.identities[c.selfSeat]!.secretKey);
        });
        const before = c.receiver.snapshot;
        const published = vi.fn();
        const pending = local(c, secrets, type);
        void pending.then(published, () => undefined);
        await expect(pending).rejects.toMatchObject({ code: "invalid_receipt" });
        expect(trace.receipt).not.toHaveBeenCalled();
        expect(published).not.toHaveBeenCalled();
        expect(c.receiver.snapshot).toBe(before);
        expect(c.store.artifacts()).toContainEqual({ artifact: committed, authored: true });
        expect(c.receiver.pendingBytes).toBe(0);
        await expect(local(c, secrets, type)).rejects.toBe(c.receiver.failure);
        expect(trace.author).toHaveBeenCalledOnce();
      }
    }
  });

  it("does not publish or partly apply authored work when store or durable receipt bytes are substituted", async () => {
    for (const boundary of ["store", "receipt"] as const) {
      vi.restoreAllMocks();
      const c = persistentSetupFixture();
      const secrets = secretStores(c);
      const persist = c.store.persistAcceptedEnvelope.bind(c.store);
      const receive = c.durable.receive.bind(c.durable);
      const trace = observe(c);
      if (boundary === "store") vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (artifact) => ({
        status: "duplicate", record: { artifact: protocol.signEnvelope({ ...artifact.envelope, round: c.round + 1 }, c.identities[0]!.secretKey) },
      }));
      else trace.receipt.mockImplementationOnce(async (artifact) => {
        const receipt = await receive(artifact);
        return { ...receipt, received: protocol.signEnvelope({ ...artifact.envelope, round: c.round + 1 }, c.identities[0]!.secretKey) };
      });
      const before = c.receiver.snapshot;
      const published = vi.fn();
      const pending = local(c, secrets, "KEY_SHARE");
      void pending.then(published, () => undefined);
      await expect(pending).rejects.toMatchObject({ code: boundary === "store" ? "recovery_required" : "invalid_receipt" });
      expect(published).not.toHaveBeenCalled();
      expect(c.receiver.snapshot).toBe(before);
      const original = await c.author.readHead();
      expect(original).not.toBeNull();
      expect(c.store.artifacts()).toEqual([{ artifact: original, authored: true }]);
      await expect(local(c, secrets, "KEY_SHARE")).rejects.toBe(c.receiver.failure);
      await expect(c.receiver.receive(original!)).rejects.toBe(c.receiver.failure);
      expect(() => c.receiver.getCompletedSetup()).toThrow(c.receiver.failure!);
      expect(c.registry.heads()).toHaveLength(boundary === "store" ? 0 : 1);
      expect((await persist(original!)).status).toBe("duplicate");
      expect(trace.author).toHaveBeenCalledOnce();
    }
  });

  it("makes every post-permission append/receipt error terminal and reconstructs only the actual durable prefix", async () => {
    for (const boundary of ["signed-only", "append-committed", "receipt"] as const) {
      vi.restoreAllMocks();
      const c = persistentSetupFixture();
      const secrets = secretStores(c);
      const append = c.store.appendNext.bind(c.store);
      const error = new Error(`Failed ${boundary}`);
      const trace = observe(c);
      if (boundary === "receipt") vi.spyOn(c.store, "persistAcceptedEnvelope").mockRejectedValueOnce(error);
      else trace.append.mockImplementationOnce(async (...args) => {
        if (boundary === "append-committed") await append(...args);
        else args[2](null);
        throw error;
      });
      const before = c.receiver.snapshot;
      const published = vi.fn();
      const active = local(c, secrets, "KEY_SHARE");
      void active.then(published, () => undefined);
      const queued = local(c, secrets, "KEY_SHARE");
      await expect(Promise.allSettled([active, queued])).resolves.toMatchObject([
        { status: "rejected", reason: { code: "recovery_required", cause: error } },
        { status: "rejected", reason: { code: "recovery_required", cause: error } },
      ]);
      await expect(active).rejects.toBe(c.receiver.failure);
      await expect(queued).rejects.toBe(c.receiver.failure);
      expect(trace.sign).toHaveBeenCalledOnce();
      expect(secrets.keys.getOrCreateGameSecret).toHaveBeenCalledOnce();
      expect(published).not.toHaveBeenCalled();
      expect(c.receiver.snapshot).toBe(before);
      expect(c.registry.heads()).toEqual([]);
      expect(c.receiver.pendingBytes).toBe(0);
      for (const type of TYPES) await expect(local(c, secrets, type)).rejects.toBe(c.receiver.failure);
      expect(c.store.artifacts()).toHaveLength(boundary === "signed-only" ? 0 : 1);
      c.receiver.close();
      const session = new SessionChainRegistry(c.gameId, c.roster);
      const durable = new PersistentSessionReceiver(session, c.store);
      for (const { artifact } of c.store.artifacts()) await durable.receive(artifact);
      const writes = vi.spyOn(c.store, "persistAcceptedEnvelope");
      writes.mockClear(); trace.head.mockClear(); trace.append.mockClear();
      const restored = new PersistentSetupReceiver({ ...c.options, session, sessionReceiver: durable });
      for (const spy of [writes, trace.head, trace.append]) expect(spy).not.toHaveBeenCalled();
      expect(restored.failure).toBeNull();
      expect(restored.snapshot.pendingSenders).toEqual(boundary === "signed-only" ? [0, 1, 2] : [1, 2]);
      if (boundary === "signed-only") {
        await expect(restored.authorKeyShare(c.author, secrets.keys, restored.snapshot, c.source)).resolves.toMatchObject({ status: "accepted" });
      } else {
        await expect(restored.authorKeyShare(c.author, secrets.keys, restored.snapshot, c.source)).rejects.toMatchObject({ code: "already_contributed" });
        for (const seat of [1, 2]) await restored.receive(await native(c, seat, "KEY_SHARE"));
        await expect(restored.authorRandCommit(c.author, secrets.beacon, restored.snapshot, c.source)).resolves.toMatchObject({ status: "accepted" });
      }
      expect(c.receiver.snapshot).toBe(before);
    }
  });

  it("latches native append invariants rather than treating missing or repeated create calls as retryable I/O", async () => {
    for (const mode of ["missing", "repeated"] as const) {
      vi.restoreAllMocks();
      const c = persistentSetupFixture();
      const secrets = secretStores(c);
      const trace = observe(c);
      trace.append.mockImplementationOnce(async (_game, _sender, create) => {
        if (mode === "repeated") {
          create(null);
          try { create(null); } catch { /* The native author must remember a swallowed invariant violation. */ }
        }
      });
      const before = c.receiver.snapshot;
      await expect(local(c, secrets, "KEY_SHARE")).rejects.toMatchObject({ code: "recovery_required", cause: { name: "AuthoredEnvelopeStoreError" } });
      expect(trace.sign).toHaveBeenCalledTimes(mode === "missing" ? 0 : 1);
      expect(trace.receipt).not.toHaveBeenCalled();
      expect(c.receiver.snapshot).toBe(before);
      expect(c.store.artifacts()).toEqual([]);
      await expect(local(c, secrets, "KEY_SHARE")).rejects.toBe(c.receiver.failure);
      expect(trace.append).toHaveBeenCalledOnce();
    }
  });

  it("shares the default 32-operation and 1 MiB limits between receipt and 64 KiB author reservations", async () => {
    expect(DEFAULT_MAX_PENDING_SETUP_ENVELOPES).toBe(32);
    expect(DEFAULT_MAX_PENDING_SETUP_BYTES).toBe(1024 * 1024);
    expect(MAX_SETUP_ENVELOPE_BYTES).toBe(64 * 1024);
    for (const quota of ["count", "bytes"] as const) {
      vi.restoreAllMocks();
      const c = persistentSetupFixture();
      const secrets = secretStores(c);
      const incoming = await native(c, 1, "KEY_SHARE");
      const read = c.store.readAuthoredHead.bind(c.store);
      const gate = deferred();
      const entered = deferred();
      vi.spyOn(c.store, "readAuthoredHead").mockImplementationOnce(async (...args) => {
        entered.resolve(); await gate.promise; return read(...args);
      });
      const active = expect(local(c, secrets, "KEY_SHARE")).rejects.toMatchObject({ code: "closed" });
      const queued: Promise<void>[] = [];
      const capacity = quota === "count" ? 32 : 16;
      try {
        await entered.promise;
        for (let index = 1; index < capacity; index += 1) {
          queued.push(expect(quota === "count" ? c.receiver.receive(incoming) : local(c, secrets, "KEY_SHARE")).rejects.toMatchObject({ code: "closed" }));
        }
        expect(c.receiver.pendingEnvelopes).toBe(capacity);
        expect(c.receiver.pendingBytes).toBe(quota === "count"
          ? MAX_SETUP_ENVELOPE_BYTES + 31 * incoming.canonicalBytes.length : DEFAULT_MAX_PENDING_SETUP_BYTES);
        await expect(c.receiver.receive(incoming)).rejects.toMatchObject({ code: "queue_limit" });
        for (const type of TYPES) await expect(local(c, secrets, type)).rejects.toMatchObject({ code: "queue_limit" });
        expect(secrets.keys.getOrCreateGameSecret).not.toHaveBeenCalled();
        c.receiver.close();
        await Promise.all(queued);
        expect(c.receiver.pendingBytes).toBe(MAX_SETUP_ENVELOPE_BYTES);
      } finally { c.receiver.close(); gate.resolve(); }
      await active;
      await c.receiver.whenIdle();
      expect(c.receiver.pendingEnvelopes).toBe(0);
      expect(c.receiver.pendingBytes).toBe(0);
    }
  });

  it("uses idle as completion rather than readiness and hands off only the actual completed idle core, even after close", async () => {
    const c = persistentSetupFixture();
    const secrets = secretStores(c);
    await c.receiver.whenIdle();
    expect(c.receiver.snapshot.state).toBe("keys");
    expect(() => c.receiver.getCompletedSetup()).toThrow(expect.objectContaining({ code: "setup_incomplete" }));
    await advanceTo(c, "RAND_REVEAL");
    const originals: EnvelopeArtifact[] = [];
    for (const seat of [1, 2]) {
      const original = await native(c, seat, "RAND_REVEAL");
      originals.push(original); await c.receiver.receive(original);
    }
    const gate = deferred();
    const entered = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementation(async (artifact) => {
      if (bytesToHex(artifact.envelope.from) !== bytesToHex(c.self)) { entered.resolve(); await gate.promise; }
      return persist(artifact);
    });
    const last = local(c, secrets, "RAND_REVEAL");
    const duplicate = c.receiver.receive(originals[0]!);
    const idle = vi.fn();
    const drained = c.receiver.whenIdle().then(idle);
    try {
      await expect(last).resolves.toMatchObject({ status: "accepted", snapshot: { state: "complete" } });
      await entered.promise;
      expect(c.receiver.snapshot.state).toBe("complete");
      expect(idle).not.toHaveBeenCalled();
      expect(() => c.receiver.getCompletedSetup()).toThrow(expect.objectContaining({ code: "setup_incomplete" }));
    } finally { gate.resolve(); }
    await duplicate; await drained;
    const completed = c.receiver.getCompletedSetup();
    expect(completed).toBeInstanceOf(SetupEnvelopeCoordinator);
    expect(c.receiver.getCompletedSetup()).toBe(completed);
    const seed = completed.seed!;
    seed.fill(0xff);
    completed.commitmentAt(0)!.fill(0xff);
    completed.roster[0]!.fill(0xff);
    expect(completed.seed).toEqual(sha256(...c.beaconSecrets));
    expect(completed.commitmentAt(0)).toEqual(beaconCommitment(c.gameId, c.round, 0, c.beaconSecrets[0]!));
    expect(completed.ingest(originals[0]!)).toMatchObject({ status: "duplicate", state: "complete" });
    const changed = protocol.signEnvelope({ ...originals[0]!.envelope, body: encodeRandRevealBody({ s: parseRandomSecret(new Uint8Array(32).fill(99)) }) }, c.identities[1]!.secretKey);
    expect(completed.ingest(changed)).toMatchObject({ status: "rejected", state: "complete" });
    c.receiver.close();
    expect(c.receiver.getCompletedSetup()).toBe(completed);
    expect(c.receiver.failure).toBeNull();
    expect(new PersistentSetupReceiver(c.options).getCompletedSetup().seed).toEqual(completed.seed);
  });

  it("returns the durably accepted original final key on collective identity failure, never a generic receiver failure or handoff", async () => {
    const c = persistentSetupFixture({ selfSeat: 2 });
    for (const seat of [0, 1]) await c.receiver.receive(await native(c, seat, "KEY_SHARE"));
    const secrets = secretStores(c);
    secrets.gameSecrets.set(bytesToHex(c.gameId), scalarFromBigInt(RISTRETTO_SCALAR_ORDER - 3n));
    const result = await local(c, secrets, "KEY_SHARE");
    expect(result).toMatchObject({
      status: "failed", transition: { status: "failed", reason: "aggregate_key_is_identity", seat: 2 },
      chainResult: { status: "accepted", persistenceStatus: "duplicate" },
      snapshot: { state: "failed", pendingSenders: [], aggregateKey: null, seed: null },
    });
    const share = decodeGameKeyShareBody(result.received.envelope.body);
    expect(verifyGameKeyShare({ gameId: c.gameId, round: c.round, phase: "setup.keys" }, share)).toBe(true);
    expect(result.received).toEqual(await c.author.readHead());
    expect(c.store.artifacts()).toContainEqual({ artifact: result.received, authored: true });
    expect(c.registry.classify(result.received).status).toBe("duplicate");
    expect(c.receiver.snapshot.publicKeys[2]).toBe(bytesToHex(share.H.toBytes()));
    expect(c.receiver.failure).toBeNull();
    for (const type of TYPES) await expect(local(c, secrets, type)).rejects.toMatchObject({ code: "setup_failed" });
    expect(secrets.keys.getOrCreateGameSecret).toHaveBeenCalledOnce();
    expect(() => c.receiver.getCompletedSetup()).toThrow(expect.objectContaining({ code: "setup_failed" }));
    c.receiver.close();
    expect(() => c.receiver.getCompletedSetup()).toThrow(expect.objectContaining({ code: "setup_failed" }));
    const restored = new PersistentSetupReceiver(c.options);
    expect(restored.snapshot).toEqual(c.receiver.snapshot);
    expect(restored.failure).toBeNull();
    expect(() => restored.getCompletedSetup()).toThrow(expect.objectContaining({ code: "setup_failed" }));
  });
});

function scope(c: Fixture): SetupBeaconScope {
  return { gameId: c.gameId, round: c.round, roster: c.roster, sender: c.self };
}

function scopeKey(value: SetupBeaconScope): string {
  return JSON.stringify([bytesToHex(value.gameId), value.round, value.roster.map(bytesToHex), bytesToHex(value.sender)]);
}

function secretStores(c: Fixture, fresh = false) {
  // CipherKeys is keyed by game only: each instance belongs to one identity, never to all fixture seats.
  const gameSecrets = new Map<string, RistrettoScalar>();
  const beaconSecrets = new Map<string, RandomSecret>();
  if (!fresh) {
    gameSecrets.set(bytesToHex(c.gameId), c.keys[c.selfSeat]!);
    beaconSecrets.set(scopeKey(scope(c)), parseRandomSecret(c.beaconSecrets[c.selfSeat]!));
  }
  const keys = { getOrCreateGameSecret: vi.fn(async (game: GameId, create: () => RistrettoScalar) => {
    const key = bytesToHex(game);
    const selected = gameSecrets.get(key) ?? create();
    gameSecrets.set(key, selected); return selected;
  }) };
  const beacon = {
    getOrCreateSetupBeaconSecret: vi.fn(async (requested: SetupBeaconScope, create: () => RandomSecret) => {
      const key = scopeKey(requested);
      const selected = beaconSecrets.get(key) ?? create();
      beaconSecrets.set(key, parseRandomSecret(selected)); return parseRandomSecret(selected);
    }),
    loadSetupBeaconSecret: vi.fn(async (requested: SetupBeaconScope): Promise<RandomSecret | null> => {
      const selected = beaconSecrets.get(scopeKey(requested));
      return selected === undefined ? null : parseRandomSecret(selected);
    }),
  };
  return { keys, beacon, gameSecrets, beaconSecrets };
}

function local(c: Fixture, secrets: Secrets, type: SetupType, expected: PersistentSetupSnapshot = c.receiver.snapshot, source: RandomSource = c.source) {
  if (type === "KEY_SHARE") return c.receiver.authorKeyShare(c.author, secrets.keys, expected, source);
  if (type === "RAND_COMMIT") return c.receiver.authorRandCommit(c.author, secrets.beacon, expected, source);
  return c.receiver.authorRandReveal(c.author, secrets.beacon, expected);
}

function native(c: Fixture, seat: number, type: SetupType) {
  return c.authors[seat]!.author({
    round: c.round, phase: type === "KEY_SHARE" ? "setup.keys" : "setup.rand", type,
    body: type === "KEY_SHARE" ? encodeGameKeyShareBody(c.shares[seat]!) : type === "RAND_COMMIT"
      ? encodeRandCommitBody({ cm: parseHash256(beaconCommitment(c.gameId, c.round, seat, c.beaconSecrets[seat]!)) })
      : encodeRandRevealBody({ s: c.beaconSecrets[seat]! }),
  });
}

async function advanceTo(c: Fixture, type: SetupType) {
  for (const previous of TYPES.slice(0, TYPES.indexOf(type))) {
    for (let seat = 0; seat < c.roster.length; seat += 1) {
      await expect(c.receiver.receive(await native(c, seat, previous))).resolves.toMatchObject({ status: "accepted" });
    }
  }
}

function observe(c: Fixture) {
  return {
    head: vi.spyOn(c.store, "readAuthoredHead"), author: vi.spyOn(c.author, "author"),
    append: vi.spyOn(c.store, "appendNext"), receipt: vi.spyOn(c.durable, "receive"),
    proof: vi.spyOn(deck, "createGameKeyShare"), commitment: vi.spyOn(protocol, "beaconCommitment"),
    rng: vi.spyOn(c.source, "fill"), random: vi.spyOn(protocolRandom, "randomBytes"), sign: vi.spyOn(protocol, "signEnvelope"),
  };
}
