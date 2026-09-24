import { bytesToHex, RistrettoPoint } from "@p2pcards/crypto";
import { createProvenDecryptionShare, encodeAuditDiscloseBody } from "@p2pcards/deck";
import { PersistentSessionReceiver, PersistentSessionReceiverError, SessionChainRegistry, recoverSessionChains, type AcceptedEnvelopeStore } from "@p2pcards/session";
import { decodeAndVerifyEnvelope, parseGameId, parseHash256, signEnvelope, type EnvelopeArtifact, type UnsignedEnvelope } from "@p2pcards/protocol";
import {
  SASKU_DECK_SPEC, SaskuHandController, SaskuPublicHandController, auditSaskuHand, legalSaskuCards, parseSaskuCard, saskuBidStrength,
  type SaskuCardId, type SaskuHandAuditResult,
} from "@p2pcards/rules-sasku";
import { describe, expect, it, vi } from "vitest";

import { roundRevealFixture } from "../../engine/src/round-reveal.test-fixture";
import {
  PersistentSaskuRoundReceiver,
  type PersistentSaskuRoundOptions,
} from "./persistent-round-receiver";

describe("persistent Sasku round receiver", () => {
  it("requires the correct four-seat session binding and exactly nine scheduled cards for each player", async () => {
    const c = await context();
    const reordered = new SessionChainRegistry(c.f.gameId, [...c.f.roster].reverse());
    const otherGame = new SessionChainRegistry(parseGameId(new Uint8Array(16).fill(1)), c.f.roster);
    const otherSameScope = new SessionChainRegistry(c.f.gameId, c.f.roster);
    for (const changes of [
      { session: otherSameScope },
      { session: reordered, sessionReceiver: new PersistentSessionReceiver(reordered, c.store) },
      { session: otherGame, sessionReceiver: new PersistentSessionReceiver(otherGame, c.store) },
      { schedule: [{ to: 0, count: 9 }] },
      { schedule: [{ to: 0, count: 10 }, { to: 1, count: 8 }, { to: 2, count: 9 }, { to: 3, count: 9 }] },
      { dealer: 4 }, { dealer: -0 }, { maxPendingEnvelopes: 0 }, { maxPendingBytes: NaN },
    ]) expect(() => new PersistentSaskuRoundReceiver({ ...c.options, ...changes } as PersistentSaskuRoundOptions)).toThrow();
    const smaller = roundRevealFixture();
    expect(() => new PersistentSaskuRoundReceiver({ ...c.options, setup: smaller.setup })).toThrow(/four-seat/);
    expect(c.game.ownerAt(0)).toBe(0);
    expect(c.game.ownerAt(35)).toBe(3);
    expect(() => c.game.ownerAt(36)).toThrow(RangeError);
    expect(c.game).not.toHaveProperty("ledger");
    expect(c.game).not.toHaveProperty("hand");
    expect(c.game.snapshot.history).toEqual([]);
  });

  it("serializes concurrent deal validation and publishes a stable cached snapshot only after durability", async () => {
    const c = await context();
    const gate = deferred();
    const entered = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (received) => {
      entered.resolve(); await gate.promise; return persist(received);
    });
    const first = c.f.deal(0, 1);
    const second = c.f.deal(0, 2);
    const before = c.game.snapshot;
    const a = c.game.receive(first);
    const b = c.game.receive(second);
    await entered.promise;
    expect(write).toHaveBeenCalledTimes(1);
    expect(c.game.pendingEnvelopes).toBe(2);
    expect(c.game.pendingBytes).toBe(first.canonicalBytes.length + second.canonicalBytes.length);
    expect(c.game.snapshot).toBe(before);
    gate.resolve();
    await expect(Promise.all([a, b])).resolves.toMatchObject([{ status: "accepted" }, { status: "accepted" }]);
    expect(c.game.snapshot.ledger.deal?.pendingSenders).toEqual([3]);
    expect(c.game.snapshot).not.toBe(before);
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
    const cached = c.game.snapshot;
    await expect(c.game.receive(first)).resolves.toMatchObject({ status: "duplicate", chainStatus: "duplicate" });
    expect(c.game.snapshot).toBe(cached);
  });

  it("classifies queued actions against the newly committed turn rather than an earlier snapshot", async () => {
    const c = await context({}, true);
    const gate = deferred();
    const entered = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (received) => {
      entered.resolve(); await gate.promise; return persist(received);
    });
    const opening = c.f.action(0, [], 0, "diamonds");
    const play = c.f.action(0, [0], 1);
    const a = c.game.receive(opening);
    const b = c.game.receive(play);
    await entered.promise;
    expect(c.game.snapshot.hand.phase).toBe("bidding");
    expect(c.game.snapshot.history).toEqual([]);
    gate.resolve();
    const results = await Promise.all([a, b]);
    expect(results.map(({ status }) => status)).toEqual(["accepted", "accepted"]);
    expect(c.game.snapshot.ledger.actionIndex).toBe(2);
    expect(c.game.snapshot.hand.trick).toEqual([{ seat: 0, card: c.f.cards[0] }]);
    expect(c.game.snapshot.hand.turn).toBe(1);
    expect(c.game.snapshot.history).toHaveLength(2);
    const snapshot = c.game.snapshot;
    await c.game.receive(opening);
    await c.game.receive(play);
    expect(c.game.snapshot).toBe(snapshot);
  });

  it("snapshots admitted bytes before queueing and does not expose buffers retained by the session", async () => {
    const c = await context();
    const gate = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (received) => {
      await gate.promise; return persist(received);
    });
    const first = c.f.deal(0, 1);
    const second = c.f.deal(0, 2);
    const firstBytes = first.canonicalBytes.slice();
    const secondBytes = second.canonicalBytes.slice();
    const a = c.game.receive(first);
    const b = c.game.receive(second);
    first.canonicalBytes.fill(0xff); first.hash.fill(0xff);
    second.canonicalBytes.fill(0xee); second.hash.fill(0xee);
    gate.resolve();
    const results = await Promise.all([a, b]);
    for (const result of results) {
      result.received.canonicalBytes.fill(0xdd);
      result.received.hash.fill(0xcc);
      result.received.envelope.from.fill(0xbb);
    }
    await expect(c.game.receive(decodeAndVerifyEnvelope(firstBytes))).resolves.toMatchObject({ status: "duplicate" });
    await expect(c.game.receive(decodeAndVerifyEnvelope(secondBytes))).resolves.toMatchObject({ status: "duplicate" });
    expect(c.game.failure).toBeNull();
  });

  it.each(["count", "bytes"] as const)("bounds active plus queued %s before additional signature work, then releases capacity", async (limit) => {
    const c = await context({ maxPendingEnvelopes: 1 });
    const first = c.f.deal(0, 1);
    const second = c.f.deal(0, 2);
    const game = limit === "count" ? c.game : new PersistentSaskuRoundReceiver({
      ...c.options, maxPendingEnvelopes: 32, maxPendingBytes: first.canonicalBytes.length + second.canonicalBytes.length - 1,
    });
    const gate = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (received) => {
      await gate.promise; return persist(received);
    });
    const pending = game.receive(first);
    const invalid = { ...second, canonicalBytes: new Uint8Array(second.canonicalBytes.length) } as EnvelopeArtifact;
    await expect(game.receive(invalid)).rejects.toMatchObject({ code: "queue_limit" });
    expect(game.pendingEnvelopes).toBe(1);
    expect(game.pendingBytes).toBe(first.canonicalBytes.length);
    gate.resolve();
    await pending;
    await expect(game.receive(second)).resolves.toMatchObject({ status: "accepted" });
    expect(game.pendingBytes).toBe(0);
  });

  it("releases admission and semantic-failure budgets without poisoning the receiver", async () => {
    const c = await context({ maxPendingEnvelopes: 1 });
    const valid = c.f.deal(0, 1);
    for (const bytes of [new Uint8Array(), new Uint8Array(65537), new Uint8Array([0xff])]) {
      await expect(c.game.receive({ ...valid, canonicalBytes: bytes } as EnvelopeArtifact)).rejects.toMatchObject({ code: "invalid_envelope" });
      expect(c.game.pendingEnvelopes).toBe(0);
      expect(c.game.pendingBytes).toBe(0);
    }
    await expect(c.game.receive(c.f.deal(0, 0))).rejects.toMatchObject({ code: "unexpected_sender" });
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.failure).toBeNull();
    await expect(c.game.receive(valid)).resolves.toMatchObject({ status: "accepted" });
  });

  it("keeps the queue usable on ordinary storage failure and does not consume a contribution", async () => {
    const c = await context();
    const before = c.game.snapshot;
    const message = c.f.deal(0, 1);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockRejectedValueOnce(new Error("disk failure"));
    await expect(c.game.receive(message)).rejects.toThrow("disk failure");
    expect(c.game.snapshot).toBe(before);
    expect(c.game.failure).toBeNull();
    expect(c.game.pendingEnvelopes).toBe(0);
    await expect(c.game.receive(message)).resolves.toMatchObject({ status: "accepted" });
  });

  it("surfaces broken-link and equivocation rejections without consuming a valid-looking contribution", async () => {
    const c = await context();
    const first = c.f.deal(0, 1);
    const broken = c.f.sign(1, "SHARES", first.envelope.phase, first.envelope.body, {
      seq: first.envelope.seq, prev: parseHash256(new Uint8Array(32).fill(0xaa)),
    });
    const before = c.game.snapshot;
    await expect(c.game.receive(broken)).resolves.toMatchObject({ status: "rejected", reason: "broken_prev" });
    expect(c.game.snapshot).toBe(before);
    await c.game.receive(first);
    const witness = c.f.sign(2, "WITNESS", c.game.snapshot.ledger.phase, { heads: [] });
    await c.durable.receive(witness);
    const share = c.f.deal(0, 2);
    const conflicting = c.f.sign(2, "SHARES", share.envelope.phase, share.envelope.body, {
      seq: witness.envelope.seq, prev: witness.envelope.prev,
    });
    const committed = c.game.snapshot;
    await expect(c.game.receive(conflicting)).resolves.toMatchObject({ status: "rejected", reason: "equivocation" });
    expect(c.game.snapshot).toBe(committed);
    expect(c.game.failure).toBeNull();
    expect(c.game.pendingBytes).toBe(0);
  });

  it("correlates by original canonical bytes even if the dependency mutates its argument and receipt views", async () => {
    const c = await context();
    const receive = c.durable.receive.bind(c.durable);
    vi.spyOn(c.durable, "receive").mockImplementationOnce(async (argument) => {
      const result = await receive(argument);
      argument.canonicalBytes.fill(0xff);
      argument.hash.fill(0xee);
      (result.received.envelope.body as Record<string, unknown>)["to"] = 3;
      result.received.hash.fill(0xaa);
      return result;
    });
    const message = c.f.deal(0, 1);
    const result = await c.game.receive(message);
    expect(result.status).toBe("accepted");
    expect(result.received.envelope.body).toEqual(message.envelope.body);
    expect(c.game.failure).toBeNull();
    expect(c.game.snapshot.ledger.deal?.pendingSenders).toEqual([2, 3]);
  });

  it("rejects matching receipt bytes when persistence corrupts the hash ingested by the shared session", async () => {
    const c = await context();
    const before = c.game.snapshot;
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (received) => {
      const stored = await persist(received);
      received.hash.fill(0xff);
      return stored;
    });
    const message = c.f.deal(0, 1);
    await expect(c.game.receive(message)).rejects.toMatchObject({ code: "invalid_receipt" });
    expect(c.session.readRange(message.envelope.from, message.envelope.seq, message.envelope.seq).status).toBe("complete");
    expect(c.session.classify(message)).toMatchObject({ status: "rejected", reason: "equivocation" });
    expect(c.game.snapshot).toBe(before);
    expect(c.game.failure?.code).toBe("invalid_receipt");
    expect(c.game.pendingEnvelopes).toBe(0);
    await expect(c.game.receive(message)).rejects.toBe(c.game.failure);
  });

  it.each(["different-artifact", "unrecorded-success", "bad-status", "bad-persistence", "wrong-scope-rejection"] as const)(
    "fails closed on an invalid durable receipt: %s", async (mode) => {
      const c = await context();
      const first = c.f.deal(0, 1);
      const second = c.f.deal(0, 2);
      const gate = deferred();
      const before = c.game.snapshot;
      const receive = vi.spyOn(c.durable, "receive").mockImplementationOnce(async (argument) => {
        await gate.promise;
        return {
          status: mode === "bad-status" ? "other" : mode === "wrong-scope-rejection" ? "rejected" : "accepted",
          reason: "wrong_game", persistenceStatus: mode === "bad-persistence" ? "other" : "stored",
          received: mode === "different-artifact" ? second : argument,
        } as never;
      });
      const a = expect(c.game.receive(first)).rejects.toMatchObject({ code: "invalid_receipt" });
      const b = expect(c.game.receive(second)).rejects.toMatchObject({ code: "invalid_receipt" });
      gate.resolve();
      await Promise.all([a, b]);
      expect(receive).toHaveBeenCalledTimes(1);
      expect(c.game.snapshot).toBe(before);
      expect(c.game.failure?.code).toBe("invalid_receipt");
      expect(c.game.pendingBytes).toBe(0);
      expect(c.game.pendingEnvelopes).toBe(0);
      await expect(c.game.receive(first)).rejects.toBe(c.game.failure);
    },
  );

  it("snapshots accepted receipt status fields once before committing", async () => {
    const c = await context();
    const real = c.durable.receive.bind(c.durable);
    let statusReads = 0;
    let persistenceReads = 0;
    vi.spyOn(c.durable, "receive").mockImplementationOnce(async (argument) => {
      const result = await real(argument);
      return { ...result,
        get status() { statusReads += 1; return statusReads === 1 ? "accepted" : "other"; },
        get persistenceStatus() { persistenceReads += 1; return persistenceReads === 1 ? "stored" : "other"; },
      } as never;
    });
    await expect(c.game.receive(c.f.deal(0, 1))).resolves.toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "stored" });
    expect(statusReads).toBe(1);
    expect(persistenceReads).toBe(1);
  });

  it("stops queued work when the durable receiver reports an invariant failure", async () => {
    const c = await context();
    const gate = deferred();
    vi.spyOn(c.durable, "receive").mockImplementationOnce(async () => {
      await gate.promise; throw new PersistentSessionReceiverError("wrong stored artifact");
    });
    const before = c.game.snapshot;
    const a = expect(c.game.receive(c.f.deal(0, 1))).rejects.toMatchObject({ code: "recovery_required" });
    const b = expect(c.game.receive(c.f.deal(0, 2))).rejects.toMatchObject({ code: "recovery_required" });
    gate.resolve();
    await Promise.all([a, b]);
    expect(c.game.snapshot).toBe(before);
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.failure).not.toBeNull();
  });

  it("does not publish partial state after an unexpected post-persistence rules commit failure", async () => {
    const c = await context({}, true);
    const before = c.game.snapshot;
    const apply = SaskuPublicHandController.prototype.apply;
    const fault = vi.spyOn(SaskuPublicHandController.prototype, "apply").mockImplementationOnce(function (this: SaskuPublicHandController, action) {
      apply.call(this, action);
      throw new Error("unexpected apply failure");
    });
    try {
      const opening = c.f.action(0, [], 0, "diamonds");
      const later = c.f.action(0, [0], 1);
      const a = expect(c.game.receive(opening)).rejects.toMatchObject({ code: "commit_failed" });
      const b = expect(c.game.receive(later)).rejects.toMatchObject({ code: "commit_failed" });
      await Promise.all([a, b]);
      expect(c.game.snapshot).toBe(before);
      expect(c.game.snapshot.history).toEqual([]);
      expect(c.session.readRange(opening.envelope.from, opening.envelope.seq, opening.envelope.seq).status).toBe("complete");
      expect(c.game.failure?.code).toBe("commit_failed");
      expect(c.game.pendingBytes).toBe(0);
      expect(() => c.game.readPrivateHand(c.f.roster[0]!, c.f.secrets[0]!)).toThrow(c.game.failure!);
    } finally { fault.mockRestore(); }
  });

  it.each(["stored", "failed"] as const)("cancels queued work on close while a submitted receipt is %s", async (outcome) => {
    const c = await context();
    const gate = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (received) => {
      await gate.promise;
      if (outcome === "failed") throw new Error("disk failure");
      return persist(received);
    });
    const first = c.f.deal(0, 1);
    const second = c.f.deal(0, 2);
    const receiving = c.game.receive(first);
    const active = outcome === "stored"
      ? expect(receiving).resolves.toMatchObject({ status: "accepted" })
      : expect(receiving).rejects.toThrow("disk failure");
    const queued = expect(c.game.receive(second)).rejects.toMatchObject({ code: "closed" });
    c.game.close();
    c.game.close();
    await queued;
    expect(c.game.closed).toBe(true);
    expect(c.game.pendingEnvelopes).toBe(1);
    expect(c.game.pendingBytes).toBe(first.canonicalBytes.length);
    await expect(c.game.receive(second)).rejects.toMatchObject({ code: "closed" });
    gate.resolve();
    await active;
    expect(write).toHaveBeenCalledTimes(1);
    expect(c.game.snapshot.ledger.deal?.pendingSenders).toEqual(outcome === "stored" ? [2, 3] : [1, 2, 3]);
    expect(c.game.pendingBytes).toBe(0);
  });

  it("handles reentrant close from persistence without publishing an inconsistent snapshot", async () => {
    const c = await context({}, true);
    const before = c.game.snapshot;
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (received) => {
      c.game.close();
      expect(c.game.snapshot).toBe(before);
      return persist(received);
    });
    await expect(c.game.receive(c.f.action(0, [], 0, "diamonds"))).resolves.toMatchObject({ status: "accepted" });
    expect(c.game.closed).toBe(true);
    expect(c.game.snapshot.hand.phase).toBe("playing");
    expect(c.game.snapshot.ledger.actionIndex).toBe(1);
  });

  it("treats a supplied-deck inconsistency as a terminal context failure, not a player violation", async () => {
    const c = await context();
    const deck = c.f.deck.map((card, pos) => pos === 0 ? { ...card, B: card.B.add(RistrettoPoint.base()) } : card);
    const game = new PersistentSaskuRoundReceiver({ ...c.options, deck });
    await finishDeals(c.f, game);
    await game.receive(c.f.action(0, [], 0, "diamonds"));
    const before = game.snapshot;
    await expect(game.receive(c.f.action(0, [0], 1))).rejects.toMatchObject({ code: "recovery_required" });
    expect(game.snapshot).toBe(before);
    expect(game.failure).not.toBeNull();
  });
});

describe("durable Sasku audit", () => {
  it.each(["deal", "bidding", "playing"] as const)("rejects premature disclosures during %s without storing or counting them", async (phase) => {
    const c = await context({}, phase !== "deal");
    if (phase === "playing") await c.game.receive(c.f.action(0, [], 0, "diamonds"));
    const before = c.game.snapshot;
    const heads = c.session.heads();
    const persist = vi.spyOn(c.store, "persistAcceptedEnvelope");
    await expect(c.game.receive(c.f.sign(1, "AUDIT_DISCLOSE", `round.${c.f.round}.audit`, { items: [] })))
      .rejects.toMatchObject({ code: "wrong_phase" });
    expect(persist).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    expect(c.game.snapshot.audit).toBeNull();
    expect(c.session.heads()).toEqual(heads);
    expect(c.game.failure).toBeNull();
    expect(c.game.pendingBytes).toBe(0);
  });

  it.each([
    { order: [0, 1, 2, 3] }, { order: [3, 2, 1, 0] }, { order: [2, 0, 3, 1] }, { order: [1, 3, 0, 2] },
  ])("audits the scheduled original hands independently of disclosure order $order", async ({ order }) => {
    const schedule = [2, 0, 3, 1, 1, 3, 0, 2, 2, 3, 1, 0].map((to) => ({ to, count: 3 }));
    const c = await context({}, true, { schedule });
    const { hands } = await completeHand(c);
    const before = c.game.snapshot;
    const checked = auditSaskuHand({ dealer: 3, hands }, before.history);
    expect(checked.status).toBe("valid");
    const pending = new Set([0, 1, 2, 3]);
    const disclosures = order.map((seat) => c.f.sign(seat, "AUDIT_DISCLOSE", before.audit!.phase, { items: [] }));
    for (const [index, message] of disclosures.entries()) {
      await expect(c.game.receive(message)).resolves.toMatchObject({ status: "accepted", chainStatus: "accepted" });
      pending.delete(order[index]!);
      expect(c.game.snapshot.audit?.pendingSenders).toEqual([...pending]);
      if (pending.size > 0) expect(c.game.snapshot.audit?.result).toBeNull();
      const snapshot = c.game.snapshot;
      await expect(c.game.receive(message)).resolves.toMatchObject({ status: "duplicate" });
      expect(c.game.snapshot).toBe(snapshot);
    }
    expect(c.game.snapshot.audit?.result).toEqual({ status: "valid", score: checked.status === "valid" ? checked.snapshot.score : null });
    expect(c.game.snapshot.hand).toBe(before.hand);
    expect(c.game.snapshot.history).toBe(before.history);
    expect(c.game.snapshot.ledger).toBe(before.ledger);
    expect(c.game.snapshot.hand).not.toHaveProperty("score");
    for (let seat = 0; seat < 4; seat += 1) {
      const privateHand = c.game.readPrivateHand(c.f.roster[seat]!, c.f.secrets[seat]!)!;
      expect(Object.keys(privateHand.dealt)).toHaveLength(9);
      expect(privateHand.remaining).toEqual({});
    }
    expect(Object.isFrozen(c.game.snapshot.audit)).toBe(true);
    expect(Object.isFrozen(c.game.snapshot.audit?.pendingSenders)).toBe(true);
    expect(Object.isFrozen(c.game.snapshot.audit?.result)).toBe(true);
    const final = c.game.snapshot;
    for (const message of [...disclosures, ...c.deals].reverse()) await c.game.receive(message);
    expect(c.game.snapshot).toBe(final);
    const persist = vi.spyOn(c.store, "persistAcceptedEnvelope");
    await expect(c.game.receive(c.f.sign(order[0]!, "AUDIT_DISCLOSE", before.audit!.phase, { items: [] })))
      .rejects.toMatchObject({ code: "conflicting_contribution" });
    expect(persist).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(final);
  }, 15_000);

  it("checks signatures, game, roster, round, exact phase, body shape, and the empty outstanding schedule before persistence", async () => {
    const c = await context({}, true);
    await completeHand(c);
    const before = c.game.snapshot;
    const valid = c.f.sign(0, "AUDIT_DISCLOSE", before.audit!.phase, { items: [] });
    const share = { pos: 0, ...createProvenDecryptionShare(
      { gameId: c.f.gameId, round: c.f.round, phase: before.audit!.phase }, 0, c.f.secrets[0]!, c.f.deck[0]!.A, c.f.source,
    ) };
    const cases: readonly [Partial<UnsignedEnvelope>, string][] = [
      [{ game: parseGameId(new Uint8Array(16).fill(0x7f)) }, "wrong_game"],
      [{ round: c.f.round + 1 }, "wrong_round"],
      [{ phase: `round.0${c.f.round}.audit` }, "wrong_phase"],
      [{ phase: before.ledger.phase }, "wrong_phase"],
      [{ type: "WITNESS", body: { heads: [] } }, "wrong_type"],
      [{ body: {} }, "malformed_body"],
      [{ body: { items: [], result: "valid" } }, "malformed_body"],
      [{ body: { items: [0] } }, "malformed_body"],
      [{ body: encodeAuditDiscloseBody({ items: [share] }) }, "wrong_positions"],
    ];
    const persist = vi.spyOn(c.store, "persistAcceptedEnvelope");
    for (const [overrides, code] of cases) {
      const invalid = signEnvelope({ ...valid.envelope, ...overrides }, c.f.identities[0]!.secretKey);
      await expect(c.game.receive(invalid)).rejects.toMatchObject({ code });
      expect(c.game.snapshot).toBe(before);
    }
    await expect(c.game.receive(c.f.sign(4, "AUDIT_DISCLOSE", before.audit!.phase, { items: [] })))
      .rejects.toMatchObject({ code: "unknown_sender" });
    const forged = { ...valid, canonicalBytes: valid.canonicalBytes.slice() } as EnvelopeArtifact;
    forged.canonicalBytes[forged.canonicalBytes.length - 1]! ^= 1;
    await expect(c.game.receive(forged)).rejects.toMatchObject({ code: "invalid_envelope" });
    expect(persist).not.toHaveBeenCalled();
    expect(c.game.failure).toBeNull();
    expect(c.game.pendingEnvelopes).toBe(0);
    await expect(c.game.receive(valid)).resolves.toMatchObject({ status: "accepted" });
    expect(c.game.snapshot.audit?.pendingSenders).toEqual([1, 2, 3]);
  }, 15_000);

  it("serializes final play and concurrent disclosures without publishing an early audit or retaining caller buffers", async () => {
    const c = await context({}, true);
    const { messages } = await completeHand(c, "valid", true);
    const finalPlay = messages.at(-1)!;
    const before = c.game.snapshot;
    expect(before.hand.phase).toBe("playing");
    expect(before.audit).toBeNull();
    const gate = deferred();
    const entered = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (received) => {
      entered.resolve(); await gate.promise; return persist(received);
    });
    const disclosures = [3, 0, 2, 1].map((seat) => c.f.sign(seat, "AUDIT_DISCLOSE", `round.${c.f.round}.audit`, { items: [] }));
    const messagesToQueue = [finalPlay, disclosures[0]!, disclosures[0]!, ...disclosures.slice(1)];
    const original = disclosures.map(({ canonicalBytes }) => canonicalBytes.slice());
    const receiving = Promise.all(messagesToQueue.map((message) => c.game.receive(message)));
    for (const disclosure of disclosures) { disclosure.canonicalBytes.fill(0xff); disclosure.hash.fill(0xee); }
    await entered.promise;
    expect(write).toHaveBeenCalledTimes(1);
    expect(c.game.snapshot).toBe(before);
    expect(c.game.pendingEnvelopes).toBe(6);
    gate.resolve();
    const results = await receiving;
    expect(results.map(({ status }) => status)).toEqual(["accepted", "accepted", "duplicate", "accepted", "accepted", "accepted"]);
    expect(c.game.snapshot.audit).toMatchObject({ pendingSenders: [], result: { status: "valid" } });
    const complete = c.game.snapshot;
    for (const result of results) { result.received.canonicalBytes.fill(0xaa); result.received.hash.fill(0xbb); }
    for (const bytes of original) await expect(c.game.receive(decodeAndVerifyEnvelope(bytes))).resolves.toMatchObject({ status: "duplicate" });
    expect(c.game.snapshot).toBe(complete);
    expect(c.game.pendingBytes).toBe(0);
    expect(c.game.failure).toBeNull();
  }, 15_000);

  it("does not count disclosures rejected for chain gaps or durable conflicts", async () => {
    const c = await context({}, true);
    await completeHand(c);
    const before = c.game.snapshot;
    const phase = before.audit!.phase;
    const witness = c.f.sign(0, "WITNESS", phase, { heads: [] });
    const disclosure = c.f.sign(0, "AUDIT_DISCLOSE", phase, { items: [] });
    await expect(c.game.receive(disclosure)).resolves.toMatchObject({ status: "rejected", reason: "gap" });
    expect(c.game.snapshot).toBe(before);
    await c.durable.receive(witness);
    await expect(c.game.receive(disclosure)).resolves.toMatchObject({ status: "accepted" });
    const waiting = c.game.snapshot;
    const conflict = c.f.sign(1, "AUDIT_DISCLOSE", phase, { items: [] });
    await c.store.persistAcceptedEnvelope(signEnvelope({ ...conflict.envelope, type: "WITNESS", body: { heads: [] } }, c.f.identities[1]!.secretKey));
    await expect(c.game.receive(conflict)).resolves.toMatchObject({ status: "rejected", reason: "durable_conflict" });
    expect(c.game.snapshot).toBe(waiting);
    for (const seat of [2, 3]) await c.game.receive(c.f.sign(seat, "AUDIT_DISCLOSE", phase, { items: [] }));
    expect(c.game.snapshot.audit).toEqual({ phase, pendingSenders: [1], result: null });
    expect(c.game.failure).toBeNull();
  }, 15_000);

  it.each(["false_bid", "follow_suit"] as const)("persists the last disclosure but attributes %s to the earlier action, including on replay", async (mode) => {
    const c = await context({}, true);
    const { messages, violation } = await completeHand(c, mode);
    expect(c.game.snapshot.hand.provisionalScore).not.toBeNull();
    expect(violation).not.toBeNull();
    const order = [0, 1, 2, 3].filter((seat) => seat !== violation!.seat);
    order.unshift(violation!.seat);
    const disclosures = order.map((seat) => c.f.sign(seat, "AUDIT_DISCLOSE", c.game.snapshot.audit!.phase, { items: [] }));
    for (const message of disclosures) await expect(c.game.receive(message)).resolves.toMatchObject({ status: "accepted" });
    expect(c.game.snapshot.audit).toMatchObject({ pendingSenders: [], result: violation });
    expect(c.game.snapshot.audit?.result).not.toHaveProperty("score");
    expect(c.game.failure).toBeNull();
    expect(c.session.classify(disclosures.at(-1)!)).toMatchObject({ status: "duplicate" });
    const replay = new PersistentSaskuRoundReceiver(c.options);
    for (const message of [...c.deals, ...messages, ...disclosures.slice().reverse()]) {
      await expect(replay.receive(message)).resolves.toMatchObject({ status: "accepted", chainStatus: "duplicate" });
    }
    expect(replay.snapshot).toEqual(c.game.snapshot);
    const audited = replay.snapshot;
    for (const message of [...messages, ...disclosures].reverse()) await replay.receive(message);
    expect(replay.snapshot).toBe(audited);
  }, 15_000);

  it.each(["corrupt_receipt", "audit_exception"] as const)("fails closed without publishing the fourth contribution on %s", async (mode) => {
    const c = await context({}, true);
    const { messages } = await completeHand(c);
    const disclosures = [0, 1, 2, 3].map((seat) => c.f.sign(seat, "AUDIT_DISCLOSE", c.game.snapshot.audit!.phase, { items: [] }));
    for (const message of disclosures.slice(0, 3)) await c.game.receive(message);
    const waiting = c.game.snapshot;
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    const fault = mode === "corrupt_receipt"
      ? vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (received) => {
          const receipt = await persist(received); received.hash.fill(0xff); return receipt;
        })
      : vi.spyOn(SaskuHandController.prototype, "apply").mockImplementationOnce(() => { throw new Error("unexpected audit failure"); });
    try {
      const code = mode === "corrupt_receipt" ? "invalid_receipt" : "commit_failed";
      const active = expect(c.game.receive(disclosures[3]!)).rejects.toMatchObject({ code });
      const queued = expect(c.game.receive(disclosures[0]!)).rejects.toMatchObject({ code });
      await Promise.all([active, queued]);
      expect(c.game.snapshot).toBe(waiting);
      expect(c.game.snapshot.audit?.result).toBeNull();
      expect(c.game.pendingEnvelopes).toBe(0);
      expect(c.game.pendingBytes).toBe(0);
      expect(c.game.failure?.code).toBe(code);
      await expect(c.game.receive(disclosures[3]!)).rejects.toBe(c.game.failure);
      const last = disclosures[3]!.envelope;
      expect(c.session.readRange(last.from, last.seq, last.seq).status).toBe("complete");
    } finally { fault.mockRestore(); }
    const restored = recoverSessionChains(c.f.gameId, c.f.roster, c.store.artifacts()).registry;
    const replay = new PersistentSaskuRoundReceiver({ ...c.options, session: restored, sessionReceiver: new PersistentSessionReceiver(restored, c.store) });
    for (const message of [...c.deals, ...messages, ...disclosures]) {
      await expect(replay.receive(message)).resolves.toMatchObject({ status: "accepted", chainStatus: "duplicate" });
    }
    expect(replay.snapshot.audit).toEqual({ phase: waiting.audit!.phase, pendingSenders: [], result: { status: "valid", score: waiting.hand.provisionalScore } });
    expect(replay.failure).toBeNull();
  }, 15_000);
});

describe("durable local private-hand access", () => {
  it("exposes no local cards until the last initial-deal write succeeds, without changing public state or persisting plaintext", async () => {
    const c = await context();
    const shares: EnvelopeArtifact[] = [];
    for (let step = 0; step < c.f.plans.length; step += 1) {
      for (let actor = 0; actor < 4; actor += 1) {
        if (actor !== c.f.plans[step]!.to) shares.push(c.f.deal(step, actor));
      }
    }
    for (const message of shares.slice(0, -1)) await c.game.receive(message);
    const before = c.game.snapshot;
    const gate = deferred();
    const entered = deferred();
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async () => {
      entered.resolve(); await gate.promise; throw new Error("last deal write failed");
    });
    const receiving = expect(c.game.receive(shares.at(-1)!)).rejects.toThrow("last deal write failed");
    await entered.promise;
    for (let seat = 0; seat < 4; seat += 1) expect(c.game.readPrivateHand(c.f.roster[seat]!, c.f.secrets[seat]!)).toBeNull();
    expect(c.game.snapshot).toBe(before);
    expect(write).toHaveBeenCalledTimes(1);
    gate.resolve();
    await receiving;
    expect(c.game.readPrivateHand(c.f.roster[0]!, c.f.secrets[0]!)).toBeNull();
    await c.game.receive(shares.at(-1)!);
    const publicState = c.game.snapshot;
    const heads = c.session.heads();
    for (let seat = 0; seat < 4; seat += 1) {
      const expected = Object.fromEntries(c.f.cards.flatMap((card, pos) => c.game.ownerAt(pos) === seat ? [[pos, card]] : []));
      const hand = c.game.readPrivateHand(c.f.roster[seat]!, c.f.secrets[seat]!)!;
      expect(hand).toEqual({ dealt: expected, remaining: expected });
      expect(Object.isFrozen(hand)).toBe(true);
      expect(Object.isFrozen(hand.dealt)).toBe(true);
      expect(Object.isFrozen(hand.remaining)).toBe(true);
    }
    expect(c.game.snapshot).toBe(publicState);
    expect(c.game.snapshot.ledger.revealed).toEqual({});
    expect(c.session.heads()).toEqual(heads);
    expect(write).toHaveBeenCalledTimes(2);
    for (const card of c.f.cards) expect(JSON.stringify(c.game.snapshot)).not.toContain(`"${card}"`);
    expect(JSON.stringify(c.game)).toBe("{}");
    expect(c.game.failure).toBeNull();
  });

  it("keeps an owned card available through rejected rules and pending/failed writes, then removes only its committed reveal", async () => {
    const c = await context({}, true);
    await c.game.receive(c.f.action(0, [], 0, "diamonds"));
    const original = c.game.readPrivateHand(c.f.roster[0]!, c.f.secrets[0]!)!;
    const play = c.f.action(0, [0], 1);
    const illegal = signEnvelope({ ...play.envelope, body: { kind: "pass", data: {}, reveal: [], shares: [] } }, c.f.identities[0]!.secretKey);
    await expect(c.game.receive(illegal)).rejects.toThrow(/Only card plays/);
    expect(c.game.readPrivateHand(c.f.roster[0]!, c.f.secrets[0]!)).toEqual(original);
    const gate = deferred();
    const entered = deferred();
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async () => {
      entered.resolve(); await gate.promise; throw new Error("play write failed");
    });
    const receiving = expect(c.game.receive(play)).rejects.toThrow("play write failed");
    await entered.promise;
    expect(c.game.readPrivateHand(c.f.roster[0]!, c.f.secrets[0]!)).toEqual(original);
    gate.resolve();
    await receiving;
    expect(c.game.readPrivateHand(c.f.roster[0]!, c.f.secrets[0]!)).toEqual(original);
    await c.game.receive(play);
    const { 0: opened, ...remaining } = original.remaining;
    expect(opened).toBe(c.f.cards[0]);
    const expected = { dealt: original.dealt, remaining };
    expect(c.game.readPrivateHand(c.f.roster[0]!, c.f.secrets[0]!)).toEqual(expected);
    expect(Object.keys(original.remaining)).toHaveLength(9);
    expect(Object.keys(c.game.readPrivateHand(c.f.roster[1]!, c.f.secrets[1]!)!.remaining)).toHaveLength(9);
    await c.game.receive(play);
    expect(c.game.readPrivateHand(c.f.roster[0]!, c.f.secrets[0]!)).toEqual(expected);
  });

  it("binds private access to the identity's accepted game key without retaining it, poisoning state, or authoring messages", async () => {
    const c = await context({}, true);
    const before = c.game.snapshot;
    const heads = c.session.heads();
    const persist = vi.spyOn(c.store, "persistAcceptedEnvelope");
    expect(() => c.game.readPrivateHand(c.f.roster[1]!, c.f.secrets[0]!)).toThrow(expect.objectContaining({ code: "invalid_local_key" }));
    expect(() => c.game.readPrivateHand(c.f.identities[4]!.publicKey, c.f.secrets[0]!)).toThrow(expect.objectContaining({ code: "unknown_sender" }));
    expect(c.game.failure).toBeNull();
    expect(c.game.snapshot).toBe(before);
    const hand = c.game.readPrivateHand(c.f.roster[0]!, c.f.secrets[0]!)!;
    expect(() => { (hand.remaining as Record<number, SaskuCardId>)[0] = "6D"; }).toThrow();
    expect(c.game.readPrivateHand(c.f.roster[0]!, c.f.secrets[0]!)!.remaining[0]).toBe(c.f.cards[0]);
    expect(c.session.heads()).toEqual(heads);
    expect(persist).not.toHaveBeenCalled();
    expect(c.game.pendingEnvelopes).toBe(0);
    c.game.close();
    expect(() => c.game.readPrivateHand(c.f.roster[0]!, c.f.secrets[0]!)).toThrow(expect.objectContaining({ code: "closed" }));
    expect(c.game.snapshot).toBe(before);
  });

  it.each(["stored", "failed"] as const)("does not publish an in-flight %s action after a private read detects an inconsistent supplied deck", async (outcome) => {
    const c = await context();
    const deck = c.f.deck.map((card, pos) => pos === 0 ? { ...card, B: card.B.add(RistrettoPoint.base()) } : card);
    const game = new PersistentSaskuRoundReceiver({ ...c.options, deck });
    await finishDeals(c.f, game);
    const before = game.snapshot;
    const gate = deferred();
    const entered = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (received) => {
      entered.resolve(); await gate.promise;
      if (outcome === "failed") throw new Error("write failed after private read");
      return persist(received);
    });
    const opening = c.f.action(0, [], 0, "diamonds");
    const active = expect(game.receive(opening)).rejects.toMatchObject({ code: "recovery_required" });
    const queued = expect(game.receive(c.f.action(0, [0], 1))).rejects.toMatchObject({ code: "recovery_required" });
    await entered.promise;
    expect(() => game.readPrivateHand(c.f.roster[0]!, c.f.secrets[0]!)).toThrow(expect.objectContaining({ code: "recovery_required" }));
    await queued;
    expect(game.pendingEnvelopes).toBe(1);
    expect(game.snapshot).toBe(before);
    gate.resolve();
    await active;
    expect(write).toHaveBeenCalledTimes(1);
    expect(game.snapshot).toBe(before);
    expect(game.pendingEnvelopes).toBe(0);
    expect(game.pendingBytes).toBe(0);
    expect(game.failure?.cause).toMatchObject({ code: "inconsistent_deck" });
    expect(c.session.classify(opening).status).toBe(outcome === "stored" ? "duplicate" : "accepted");
    await expect(game.receive(opening)).rejects.toBe(game.failure);
    expect(() => game.readPrivateHand(c.f.roster[0]!, c.f.secrets[0]!)).toThrow(game.failure!);
  });

  it.each(["accepted", "rejected"] as const)("preserves a private-read failure triggered reentrantly by a %s receipt", async (status) => {
    const c = await context();
    const deck = c.f.deck.map((card, pos) => pos === 0 ? { ...card, B: card.B.add(RistrettoPoint.base()) } : card);
    const game = new PersistentSaskuRoundReceiver({ ...c.options, deck });
    await finishDeals(c.f, game);
    const before = game.snapshot;
    const receive = c.durable.receive.bind(c.durable);
    vi.spyOn(c.durable, "receive").mockImplementationOnce(async (received) => {
      const result = await receive(received);
      return { ...result, reason: "gap",
        get status() {
          expect(() => game.readPrivateHand(c.f.roster[0]!, c.f.secrets[0]!)).toThrow(expect.objectContaining({ code: "recovery_required" }));
          return status;
        },
      } as never;
    });
    await expect(game.receive(c.f.action(0, [], 0, "diamonds"))).rejects.toMatchObject({ code: "recovery_required" });
    expect(game.snapshot).toBe(before);
    expect(game.pendingBytes).toBe(0);
    expect(game.failure?.cause).toMatchObject({ code: "inconsistent_deck" });
  });
});

async function completeHand(c: Awaited<ReturnType<typeof context>>, mode: "valid" | "false_bid" | "follow_suit" = "valid", deferFinalPlay = false) {
  const hands: [SaskuCardId[], SaskuCardId[], SaskuCardId[], SaskuCardId[]] = [[], [], [], []];
  c.f.cards.forEach((card, pos) => hands[c.game.ownerAt(pos)].push(parseSaskuCard(card).id));
  const remaining = hands.map((hand) => [...hand]);
  const messages: EnvelopeArtifact[] = [];
  let violation: Extract<SaskuHandAuditResult, { status: "violation" }> | null = null;
  if (mode === "false_bid") {
    messages.push(c.f.action(0, [], 0, "bid", { value: saskuBidStrength(hands[0]) + 1 }));
    await c.game.receive(messages.at(-1)!);
    violation = { status: "violation", seat: 0, at: 0, rule: "bid_strength" };
  }
  messages.push(c.f.action(c.game.snapshot.hand.turn!, [], c.game.snapshot.ledger.actionIndex, "diamonds"));
  await c.game.receive(messages.at(-1)!);
  for (let index = 0; index < 36; index += 1) {
    const state = c.game.snapshot;
    const seat = state.hand.turn!;
    const legal = legalSaskuCards(remaining[seat]!, state.hand.trick, "diamonds");
    let card = legal[0]!;
    if (mode === "follow_suit" && violation === null) {
      const illegal = remaining[seat]!.find((candidate) => !legal.includes(candidate));
      if (illegal !== undefined) { card = illegal; violation = { status: "violation", seat, at: state.history.length, rule: "follow_suit" }; }
    }
    messages.push(c.f.action(seat, [c.f.cards.indexOf(card)], state.ledger.actionIndex));
    if (index !== 35 || !deferFinalPlay) await c.game.receive(messages.at(-1)!);
    remaining[seat]!.splice(remaining[seat]!.indexOf(card), 1);
  }
  return { hands, messages, violation };
}

async function context(overrides: Partial<PersistentSaskuRoundOptions> = {}, ready = false, fixtureOptions: Parameters<typeof roundRevealFixture>[0] = {}) {
  const f = roundRevealFixture({ seats: 4, deckSpec: SASKU_DECK_SPEC, schedule: [0, 1, 2, 3].map((to) => ({ to, count: 9 })), ...fixtureOptions });
  const store = new MemoryStore();
  const session = new SessionChainRegistry(f.gameId, f.roster);
  const durable = new PersistentSessionReceiver(session, store);
  for (const artifact of f.setupEnvelopes) await durable.receive(artifact);
  const options: PersistentSaskuRoundOptions = {
    setup: f.setup, round: f.round, deck: f.deck, schedule: f.options.schedule,
    dealer: 3, session, sessionReceiver: durable, ...overrides,
  };
  const game = new PersistentSaskuRoundReceiver(options);
  const deals = ready ? await finishDeals(f, game) : [];
  return { f, store, session, durable, options, game, deals };
}

async function finishDeals(f: ReturnType<typeof roundRevealFixture>, game: PersistentSaskuRoundReceiver) {
  const messages: EnvelopeArtifact[] = [];
  for (let step = 0; step < f.plans.length; step += 1) {
    for (let actor = 0; actor < 4; actor += 1) {
      if (actor !== f.plans[step]!.to) {
        const message = f.deal(step, actor);
        await game.receive(message);
        messages.push(message);
      }
    }
  }
  return messages;
}

class MemoryStore implements AcceptedEnvelopeStore {
  readonly #records = new Map<string, EnvelopeArtifact>();
  artifacts(): EnvelopeArtifact[] { return [...this.#records.values()].map(({ canonicalBytes }) => decodeAndVerifyEnvelope(canonicalBytes)); }
  async persistAcceptedEnvelope(candidate: EnvelopeArtifact) {
    const received = decodeAndVerifyEnvelope(candidate.canonicalBytes);
    const key = `${bytesToHex(received.envelope.from)}:${received.envelope.seq}`;
    const existing = this.#records.get(key);
    if (existing !== undefined) {
      if (bytesToHex(existing.hash) !== bytesToHex(received.hash)) {
        return { status: "conflict" as const, existing: { artifact: existing }, received };
      }
      return { status: "duplicate" as const, record: { artifact: decodeAndVerifyEnvelope(existing.canonicalBytes) } };
    }
    this.#records.set(key, received);
    return { status: "stored" as const, record: { artifact: decodeAndVerifyEnvelope(received.canonicalBytes) } };
  }
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}
