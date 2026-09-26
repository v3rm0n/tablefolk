import { bytesToHex, RISTRETTO_SCALAR_ORDER, RistrettoPoint, scalarFromBigInt, type RistrettoScalar } from "@p2pcards/crypto";
import * as deckCrypto from "@p2pcards/deck";
import { createProvenDecryptionShare, encodeActionBody, encodeSharesBody, maskCard, type SharesBody } from "@p2pcards/deck";
import { decodeCanonical, encodeCanonical, type CborMap, type CborValue } from "@p2pcards/encoding";
import * as protocol from "@p2pcards/protocol";
import { parseGameId, type EnvelopeArtifact } from "@p2pcards/protocol";
import { describe, expect, it, vi } from "vitest";

import { MAX_ROUND_REVEAL_ENVELOPE_BYTES, RoundRevealError, RoundRevealLedger, type RoundRevealOptions } from "./round-reveal-ledger";
import { roundRevealFixture } from "./round-reveal.test-fixture";
import { SetupEnvelopeCoordinator } from "./setup-envelope-coordinator";
import { recoverSetup } from "./setup-recovery";

describe("private-round reveal ledger", () => {
  it("recovers key-only setup and accepts four fully proved donor batches before play", () => {
    const f = roundRevealFixture({ seats: 4, beaconRequired: false, batchDeal: true,
      deckSpec: { id: "batch-deal-test/v1", cards: Array.from({ length: 36 }, (_, i) => `card-${i}`) },
      schedule: [0, 1, 2, 3].map(to => ({ to, count: 9 })) });
    expect(f.setupEnvelopes).toHaveLength(4);
    expect(f.setup.state).toBe("complete");
    expect(f.setup.seed).toBeNull();
    expect(recoverSetup(f.gameId, 0, f.roster, f.setupEnvelopes, false).coordinator.state).toBe("complete");
    expect(recoverSetup(f.gameId, 0, f.roster, f.setupEnvelopes).coordinator.state).toBe("rand_commit");
    expect(f.ledger.snapshot.deal).toMatchObject({ to: 4, pendingSenders: [0, 1, 2, 3] });
    expect(() => f.ledger.classify(f.action(0, [0]), 0)).toThrow(expect.objectContaining({ code: "deal_incomplete" }));
    const first = f.dealAll(0);
    expect(first.envelope.body).toMatchObject({ to: 4 });
    expect((first.envelope.body as unknown as { items: unknown[] }).items).toHaveLength(27);
    expect(f.ledger.classify(first).status).toBe("accepted");
    expect(f.ledger.snapshot.deal?.pendingSenders).toEqual([0, 1, 2, 3]);
    f.ledger.commit(first);
    expect(f.ledger.commit(first).status).toBe("duplicate");
    for (const seat of [1, 2, 3]) f.ledger.commit(f.dealAll(seat));
    expect(f.ledger.snapshot.deal).toBeNull();
    expect(f.ledger.snapshot.phase).toBe("round.2.play.0");
    for (const seat of [0, 1, 2, 3]) expect(Object.keys(f.ledger.readPrivateHand(seat, f.secrets[seat]!)!.dealt)).toHaveLength(9);
  });

  it("rejects missing, foreign, or unproved positions in an all-recipient donor batch", () => {
    const f = roundRevealFixture({ seats: 4, beaconRequired: false, batchDeal: true,
      deckSpec: { id: "batch-deal-test/v1", cards: Array.from({ length: 36 }, (_, i) => `card-${i}`) },
      schedule: [0, 1, 2, 3].map(to => ({ to, count: 9 })) });
    const good = f.dealAll(0), body = good.envelope.body as unknown as { to: number; items: CborValue[] };
    const modified = (items: CborValue[], to = 4) => f.sign(0, "SHARES", good.envelope.phase, { to, items });
    expect(() => f.ledger.commit(modified(body.items.slice(1)))).toThrow(expect.objectContaining({ code: "wrong_positions" }));
    expect(() => f.ledger.commit(modified([...body.items].reverse()))).toThrow(expect.objectContaining({ code: "wrong_positions" }));
    expect(() => f.ledger.commit(modified([...body.items.slice(0, -1), { ...(body.items.at(-1) as CborMap), pos: 0 }]))).toThrow(expect.objectContaining({ code: "wrong_positions" }));
    expect(() => f.ledger.commit(modified(body.items, 0))).toThrow(expect.objectContaining({ code: "wrong_recipient" }));
    expect(() => f.ledger.commit(modified([{ ...(body.items[0] as CborMap), S: RistrettoPoint.identity().toBytes() }, ...body.items.slice(1)]))).toThrow(expect.objectContaining({ code: "invalid_share_proof" }));
    expect(f.ledger.snapshot.deal?.pendingSenders).toEqual([0, 1, 2, 3]);
  });
  it("assigns ascending stock positions to explicit private steps without opening cards", () => {
    const { ledger } = roundRevealFixture();
    expect([0, 1, 2, 3].map((pos) => ledger.ownerAt(pos))).toEqual([0, 0, 1, null]);
    expect(ledger.snapshot).toEqual({
      phase: "round.2.deal.0", dealIndex: 0, actionIndex: 0,
      deal: { to: 0, positions: [0, 1], pendingSenders: [1, 2] }, revealed: {},
    });
    expect(JSON.stringify(ledger.snapshot)).not.toContain("card-a");
  });

  it("classifies without mutation and counts each accepted sender once, independently of batch/donor order", () => {
    const f = roundRevealFixture();
    const other = new RoundRevealLedger(f.options);
    const first = f.deal(0, 2);
    const raw = f.deal(0, 1);
    const body = raw.envelope.body as CborMap;
    const second = f.sign(1, "SHARES", raw.envelope.phase, { ...body, items: [...body["items"] as CborValue[]].reverse() });
    const before = f.ledger.snapshot;
    expect(f.ledger.classify(first)).toMatchObject({ status: "accepted", type: "SHARES", seat: 2 });
    expect(f.ledger.snapshot).toEqual(before);
    f.ledger.commit(first);
    expect(f.ledger.snapshot.deal?.pendingSenders).toEqual([1]);
    expect(f.ledger.commit(first).status).toBe("duplicate");
    expect(f.ledger.snapshot.deal?.pendingSenders).toEqual([1]);
    f.ledger.commit(second);
    other.commit(second); other.commit(first);
    expect(f.ledger.snapshot).toEqual(other.snapshot);
    expect(f.ledger.snapshot).toMatchObject({ phase: "round.2.deal.1", revealed: {}, deal: { to: 1, positions: [2], pendingSenders: [0, 2] } });
    expect(f.ledger.classify(first).status).toBe("duplicate");
  });

  it("requires all scheduled contributions before play and can retry future traffic after prerequisites arrive", () => {
    const f = roundRevealFixture();
    const future = f.deal(1, 0);
    const play = f.action(0, [0]);
    const before = f.ledger.snapshot;
    expect(() => f.ledger.commit(future)).toThrow(expect.objectContaining({ code: "wrong_phase" }));
    expect(() => f.ledger.commit(play, 0)).toThrow(expect.objectContaining({ code: "deal_incomplete" }));
    expect(f.ledger.snapshot).toEqual(before);
    f.ledger.commit(f.deal(0, 1)); f.ledger.commit(f.deal(0, 2));
    f.ledger.commit(future);
    expect(() => f.ledger.classify(play, 0)).toThrow(expect.objectContaining({ code: "deal_incomplete" }));
    f.ledger.commit(f.deal(1, 2));
    expect(f.ledger.snapshot.deal).toBeNull();
    expect(f.ledger.classify(play, 0)).toMatchObject({ status: "accepted", revealed: { 0: f.cards[0] } });
  });

  it("opens only owner-proven positions, previews atomically, and never derives cards from plaintext deck indices", () => {
    const f = roundRevealFixture();
    finishDeal(f);
    const play = f.action(0, [1, 0]);
    const before = f.ledger.snapshot;
    const preview = f.ledger.classify(play, 0);
    expect(preview).toMatchObject({ type: "ACTION", seat: 0, revealed: { 0: "card-b", 1: "card-c" } });
    expect(f.ledger.snapshot).toEqual(before);
    expect(f.ledger.commit(play, 0)).toEqual(preview);
    expect(f.ledger.snapshot).toMatchObject({ phase: "round.2.play.1", actionIndex: 1, revealed: { 0: "card-b", 1: "card-c" } });
    const committed = f.ledger.snapshot;
    expect(f.ledger.commit(play, 2).status).toBe("duplicate");
    expect(f.ledger.snapshot).toEqual(committed);
    expect(() => f.ledger.commit(f.action(0, [0], 1), 0)).toThrow(expect.objectContaining({ code: "already_revealed" }));
    expect(f.ledger.snapshot).toEqual(committed);
  });

  it.each([3, 8])("requires each of the other %i-seat game keys and verifies the owner's final share", (seats) => {
    const f = roundRevealFixture({ seats, schedule: [{ to: seats - 1, count: 1 }] });
    for (let actor = seats - 2; actor >= 0; actor -= 1) f.ledger.commit(f.deal(0, actor));
    expect(f.ledger.snapshot.deal).toBeNull();
    expect(f.ledger.commit(f.action(seats - 1, [0]), seats - 1)).toMatchObject({ seat: seats - 1, revealed: { 0: f.cards[0] } });
  });

  it.each([
    ["wrong_game", { game: parseGameId(new Uint8Array(16).fill(0x62)) }],
    ["wrong_round", { round: 3 }],
    ["wrong_phase", { phase: "round.2.deal.00" }],
    ["wrong_type", { type: "AUDIT_DISCLOSE" }],
  ] as const)("rejects signed deal context errors: %s", (code, overrides) => {
    const f = roundRevealFixture();
    const good = f.deal(0, 1);
    const bad = f.sign(1, "SHARES", good.envelope.phase, good.envelope.body, overrides);
    const before = f.ledger.snapshot;
    expect(() => f.ledger.commit(bad)).toThrow(expect.objectContaining({ code }));
    expect(f.ledger.snapshot).toEqual(before);
  });

  it("rejects a recipient's premature share and unknown authors before accepting contributions", () => {
    const f = roundRevealFixture();
    const owner = f.deal(0, 0);
    expect(() => f.ledger.commit(owner)).toThrow(expect.objectContaining({ code: "unexpected_sender" }));
    const outsider = f.sign(3, "SHARES", owner.envelope.phase, owner.envelope.body);
    expect(() => f.ledger.commit(outsider)).toThrow(expect.objectContaining({ code: "unknown_sender" }));
    expect(f.ledger.snapshot.deal?.pendingSenders).toEqual([1, 2]);
  });

  it("requires an exact recipient/position set and rejects a second distinct contribution from one sender", () => {
    const f = roundRevealFixture();
    const good = f.deal(0, 1);
    const body = good.envelope.body as CborMap;
    const items = body["items"] as readonly CborMap[];
    for (const [code, changed] of [
      ["wrong_recipient", { ...body, to: 1 }],
      ["wrong_positions", { ...body, items: [items[0]!] }],
      ["wrong_positions", { ...body, items: [items[0]!, { ...items[1]!, pos: 2 }] }],
      ["malformed_body", { ...body, items: [items[0]!, items[0]!] }],
      ["malformed_body", { ...body, items: [] }],
      ["malformed_body", { ...body, extra: 1 }],
    ] as const) {
      const before = f.ledger.snapshot;
      expect(() => f.ledger.commit(f.sign(1, "SHARES", good.envelope.phase, changed))).toThrow(expect.objectContaining({ code }));
      expect(f.ledger.snapshot).toEqual(before);
    }
    f.ledger.commit(good);
    expect(() => f.ledger.commit(f.deal(0, 1))).toThrow(expect.objectContaining({ code: "conflicting_contribution" }));
    expect(f.ledger.snapshot.deal?.pendingSenders).toEqual([2]);
  });

  it("verifies every item and commits no partial batch when the last deal proof fails", () => {
    const f = roundRevealFixture();
    const good = f.deal(0, 1);
    const body = good.envelope.body as CborMap;
    const items = body["items"] as readonly CborMap[];
    const bad = f.sign(1, "SHARES", good.envelope.phase, { ...body, items: [items[0]!, { ...items[1]!, z: new Uint8Array(32) }] });
    const before = f.ledger.snapshot;
    expect(() => f.ledger.commit(bad)).toThrow(expect.objectContaining({ code: "invalid_share_proof" }));
    expect(f.ledger.snapshot).toEqual(before);
    expect(f.ledger.commit(good).status).toBe("accepted");
    f.ledger.commit(f.deal(0, 2));
    f.ledger.commit(f.deal(1, 0)); f.ledger.commit(f.deal(1, 2));
    expect(f.ledger.commit(f.action(0, [0, 1]), 0)).toMatchObject({ revealed: { 0: f.cards[0], 1: f.cards[1] } });
  });

  it("binds deal proofs to their signer, ciphertext, round, and exact original phase", () => {
    const f = roundRevealFixture();
    const good = f.deal(0, 1);
    const phase = good.envelope.phase;
    const wrongAuthor = f.sign(2, "SHARES", phase, good.envelope.body);
    expect(() => f.ledger.commit(wrongAuthor)).toThrow(expect.objectContaining({ code: "invalid_share_proof" }));
    for (const context of [
      { gameId: f.gameId, round: f.round + 1, phase },
      { gameId: f.gameId, round: f.round, phase: "round.2.play.0" },
      { gameId: parseGameId(new Uint8Array(16).fill(1)), round: f.round, phase },
    ]) {
      const items = [0, 1].map((pos) => ({ pos, ...createProvenDecryptionShare(context, pos, f.secrets[1]!, f.deck[pos]!.A, f.source) }));
      const body = encodeActionBody({ kind: "test", data: {}, reveal: [0, 1], shares: items });
      expect(() => f.ledger.commit(f.sign(1, "SHARES", phase, { to: 0, items: body["shares"]! }))).toThrow(expect.objectContaining({ code: "invalid_share_proof" }));
    }
    const changedDeck = f.deck.map((card, pos) => pos === 1 ? { ...card, A: RistrettoPoint.base() } : card);
    const wrongCiphertext = new RoundRevealLedger({ ...f.options, deck: changedDeck });
    expect(() => wrongCiphertext.commit(good)).toThrow(expect.objectContaining({ code: "invalid_share_proof" }));
    expect(f.ledger.snapshot.deal?.pendingSenders).toEqual([1, 2]);
  });

  it.each([["wrong_owner", 2], ["unscheduled_position", 3], ["unscheduled_position", 127]] as const)(
    "rejects %s even with a real signed proof for position %i", (code, position) => {
      const f = roundRevealFixture();
      finishDeal(f);
      const before = f.ledger.snapshot;
      expect(() => f.ledger.commit(f.action(0, [position]), 0)).toThrow(expect.objectContaining({ code }));
      expect(f.ledger.snapshot).toEqual(before);
    },
  );

  it("rechecks action authority and current phase without trusting a previously classified artifact view", () => {
    const f = roundRevealFixture();
    finishDeal(f);
    const good = f.action(0, [0]);
    expect(() => f.ledger.classify(good)).toThrow(RangeError);
    expect(() => f.ledger.classify(good, 1)).toThrow(expect.objectContaining({ code: "unexpected_sender" }));
    expect(() => f.ledger.commit(f.action(0, [0], 1), 0)).toThrow(expect.objectContaining({ code: "wrong_phase" }));
    const classified = f.ledger.classify(good, 0);
    expect(classified.type).toBe("ACTION");
    if (classified.type !== "ACTION") throw new Error("Expected action");
    (classified.body.data as Record<string, CborValue>)["card"] = "forged-card";
    classified.received.hash.fill(0xff);
    (classified.received.envelope.body as Record<string, CborValue>)["kind"] = "forged";
    const committed = f.ledger.commit(classified.received, 0);
    expect(committed).toMatchObject({ body: { kind: "play", data: {} }, revealed: { 0: f.cards[0] } });
    expect(() => (classified.revealed as Record<number, string>)[0] = "changed").toThrow();
    expect(f.ledger.classify(good)).toMatchObject({ status: "duplicate", revealed: { 0: f.cards[0] } });
  });

  it("does not consume any reveal or the action index when the last owner proof is invalid", () => {
    const f = roundRevealFixture();
    finishDeal(f);
    const good = f.action(0, [0, 1]);
    const body = good.envelope.body as CborMap;
    const shares = body["shares"] as readonly CborMap[];
    const bad = f.sign(0, "ACTION", good.envelope.phase, { ...body, shares: [shares[0]!, { ...shares[1]!, z: new Uint8Array(32) }] });
    const before = f.ledger.snapshot;
    expect(() => f.ledger.commit(bad, 0)).toThrow(expect.objectContaining({ code: "invalid_share_proof" }));
    expect(f.ledger.snapshot).toEqual(before);
    expect(f.ledger.commit(good, 0).status).toBe("accepted");
  });

  it("will not reuse original deal proofs as owner action proofs", () => {
    const f = roundRevealFixture();
    finishDeal(f);
    const item = { pos: 0, ...createProvenDecryptionShare({ gameId: f.gameId, round: f.round, phase: "round.2.deal.0" }, 0, f.secrets[0]!, f.deck[0]!.A, f.source) };
    const body = encodeActionBody({ kind: "play", data: {}, reveal: [0], shares: [item] });
    expect(() => f.ledger.commit(f.sign(0, "ACTION", "round.2.play.0", body), 0)).toThrow(expect.objectContaining({ code: "invalid_share_proof" }));
    expect(f.ledger.snapshot.actionIndex).toBe(0);
  });

  it("rejects an owner action carrying another seat's mathematically valid share", () => {
    const f = roundRevealFixture();
    finishDeal(f);
    const context = { gameId: f.gameId, round: f.round, phase: f.ledger.snapshot.phase };
    const share = { pos: 0, ...createProvenDecryptionShare(context, 0, f.secrets[1]!, f.deck[0]!.A, f.source) };
    const body = encodeActionBody({ kind: "play", data: {}, reveal: [0], shares: [share] });
    expect(() => f.ledger.commit(f.sign(0, "ACTION", context.phase, body), 0)).toThrow(expect.objectContaining({ code: "invalid_share_proof" }));
    expect(f.ledger.snapshot.revealed).toEqual({});
  });

  it("binds proofs to position even when two owned ciphertexts have the same A component", () => {
    const f = roundRevealFixture();
    f.deck[1] = maskCard(f.table.pointAt(2), scalarFromBigInt(10n), f.setup.aggregateKey!);
    const ledger = new RoundRevealLedger(f.options);
    finishDeal(f, ledger);
    const original = f.action(0, [0]);
    const body = original.envelope.body as CborMap;
    const share = (body["shares"] as readonly CborMap[])[0]!;
    const changed = f.sign(0, "ACTION", original.envelope.phase, { ...body, reveal: [1], shares: [{ ...share, pos: 1 }] });
    expect(() => ledger.commit(changed, 0)).toThrow(expect.objectContaining({ code: "invalid_share_proof" }));
    expect(ledger.snapshot.actionIndex).toBe(0);
    expect(ledger.commit(original, 0)).toMatchObject({ revealed: { 0: f.cards[0] } });
  });

  it.each(["unknown-card", "duplicate-in-batch", "duplicate-across-actions"] as const)(
    "reports supplied-deck inconsistency without mutating reveals or blaming the author: %s", (mode) => {
      const f = roundRevealFixture();
      const plaintext = mode === "unknown-card" ? RistrettoPoint.base() : f.table.pointAt(1);
      const card = maskCard(plaintext, scalarFromBigInt(11n), f.setup.aggregateKey!);
      const ledger = new RoundRevealLedger({ ...f.options, deck: [f.deck[0]!, card, ...f.deck.slice(2)] });
      finishDeal(f, ledger);
      if (mode === "duplicate-across-actions") ledger.commit(f.action(0, [0]), 0);
      const before = ledger.snapshot;
      const action = f.action(0, mode === "duplicate-across-actions" ? [1] : [0, 1], ledger.snapshot.actionIndex);
      expect(() => ledger.commit(action, 0)).toThrow(expect.objectContaining({ code: "inconsistent_deck" }));
      expect(ledger.snapshot).toEqual(before);
    },
  );

  it("bounds even non-revealing actions and keeps exact replay idempotent after the budget is reached", () => {
    const f = roundRevealFixture({ schedule: [], maxActions: 1 });
    const pass = f.action(1, [], 0, "pass");
    f.ledger.commit(pass, 1);
    expect(f.ledger.snapshot).toMatchObject({ actionIndex: 1, revealed: {} });
    expect(f.ledger.commit(pass).status).toBe("duplicate");
    expect(() => f.ledger.commit(f.action(1, [], 1, "pass"), 1)).toThrow(expect.objectContaining({ code: "action_limit" }));
    expect(f.ledger.snapshot.actionIndex).toBe(1);
  });

  it("rebuilds the same phase and opened cards from original messages without trusting arrival metadata", () => {
    const f = roundRevealFixture();
    const accepted = finishDeal(f);
    for (const [actor, positions] of [[0, [0]], [1, [2]], [0, [1]]] as const) {
      const envelope = f.action(actor, positions, f.ledger.snapshot.actionIndex);
      f.ledger.commit(envelope, actor);
      accepted.push(envelope);
    }
    const replay = new RoundRevealLedger(f.options);
    for (const envelope of accepted) {
      const actor = f.roster.findIndex((identity) => bytesToHex(identity) === bytesToHex(envelope.envelope.from));
      replay.commit(envelope, actor);
    }
    expect(replay.snapshot).toEqual(f.ledger.snapshot);
    for (const envelope of accepted.reverse()) expect(replay.commit(envelope).status).toBe("duplicate");
    expect(replay.snapshot).toEqual(f.ledger.snapshot);
  });

  it("isolates constructor inputs and exported snapshots from subsequent mutation", () => {
    const f = roundRevealFixture();
    const deck = f.deck.map((card) => ({ ...card }));
    const schedule = f.options.schedule.map((step) => ({ ...step }));
    const cards = [...f.options.deckSpec.cards];
    const ledger = new RoundRevealLedger({ ...f.options, deck, schedule, deckSpec: { id: f.options.deckSpec.id, cards } });
    deck[0]!.A = RistrettoPoint.identity();
    schedule[0]!.to = 2; schedule[0]!.count = 4; cards.fill("other");
    const snapshot = ledger.snapshot;
    expect(Object.isFrozen(snapshot.deal?.positions)).toBe(true);
    expect(Object.isFrozen(snapshot.deal?.pendingSenders)).toBe(true);
    expect(() => (snapshot.deal!.positions as number[]).push(3)).toThrow();
    const body = ledger.createDealShares(1, f.secrets[1]!, f.source);
    expect(body.to).toBe(0);
    expect(body.items.map(({ pos }) => pos)).toEqual([0, 1]);
    expect(ledger.classify(f.sign(1, "SHARES", snapshot.phase, encodeSharesBody(body)))).toMatchObject({ status: "accepted", seat: 1 });
    expect(ledger.snapshot).toEqual(snapshot);
    finishDeal(f, ledger);
    ledger.commit(f.action(0, [0]), 0);
    expect(ledger.snapshot.revealed).toEqual({ 0: f.cards[0] });
    expect(Object.isFrozen(ledger.snapshot.revealed)).toBe(true);
    expect(snapshot.revealed).toEqual({});
  });

  it("rejects corrupt, oversized, or forged artifact bytes without using the supplied decoded view", () => {
    const f = roundRevealFixture();
    const valid = f.deal(0, 1);
    const wire = decodeCanonical(valid.canonicalBytes) as CborMap;
    const tampered = encodeCanonical({ ...wire, body: {} });
    for (const bytes of [tampered, new Uint8Array(), new Uint8Array(MAX_ROUND_REVEAL_ENVELOPE_BYTES + 1), new Uint8Array([0xff])]) {
      expect(() => f.ledger.commit({ ...valid, canonicalBytes: bytes } as EnvelopeArtifact)).toThrow(expect.objectContaining({ code: "invalid_envelope" }));
    }
    (valid.envelope.body as Record<string, CborValue>)["to"] = 2;
    expect(f.ledger.commit(valid)).toMatchObject({ type: "SHARES", body: { to: 0 } });
  });

  it("validates completed setup, deck shape, schedule capacity, and explicit resource budgets", () => {
    const f = roundRevealFixture();
    const pending = new SetupEnvelopeCoordinator(f.gameId, 0, f.roster);
    const keysOnly = new SetupEnvelopeCoordinator(f.gameId, 0, f.roster);
    for (const artifact of f.setupEnvelopes.slice(0, f.roster.length)) keysOnly.ingest(artifact);
    expect(keysOnly.state).toBe("rand_commit");
    for (const change of [
      { setup: pending }, { setup: keysOnly }, { setup: {} }, { round: -1 }, { round: -0 }, { round: 0.5 },
      { round: Number.MAX_SAFE_INTEGER + 1 }, { maxActions: 0 }, { maxActions: Infinity }, { maxActions: 1.5 },
      { deck: [] }, { deck: new Array(4) }, { deckSpec: { id: "invalid", cards: ["same", "same"] } },
      { schedule: new Array(1) }, { schedule: new Array(5) }, { schedule: [{ to: 0, count: 5 }] },
      { schedule: [{ to: 3, count: 1 }] }, { schedule: [{ to: -0, count: 1 }] },
      { schedule: [{ to: 0, count: 0 }] }, { schedule: [{ to: 0, count: 1.5 }] },
      { schedule: [{ to: 0, count: 3 }, { to: 1, count: 2 }] },
    ]) expect(() => new RoundRevealLedger({ ...f.options, ...change } as RoundRevealOptions)).toThrow();
    for (const pos of [-0, -1, 4, 0.5, NaN]) expect(() => f.ledger.ownerAt(pos)).toThrow(RangeError);
  });
});

describe("private-round local hand reads", () => {
  it.each([3, 8])("reads only the owned positions for every local seat in a %i-seat roster", (seats) => {
    const f = roundRevealFixture({
      seats,
      deckSpec: { id: `private-hand-${seats}/v1`, cards: Array.from({ length: seats + 1 }, (_, index) => `card-${index}`) },
      schedule: Array.from({ length: seats }, (_, index) => ({ to: seats - index - 1, count: 1 })),
    });
    finishDeal(f);
    const before = f.ledger.snapshot;
    for (let seat = 0; seat < seats; seat += 1) {
      const position = seats - seat - 1;
      const owned = { [position]: f.cards[position] };
      expect(f.ledger.readPrivateHand(seat, f.secrets[seat]!)).toEqual({ dealt: owned, remaining: owned });
      expect(f.ledger.snapshot).toEqual(before);
    }
    expect(f.ledger.ownerAt(seats)).toBeNull();
    expect(before.revealed).toEqual({});
    for (const card of f.cards) expect(JSON.stringify(f.ledger.snapshot)).not.toContain(card);
  });

  it("waits for the entire committed deal, not a completed local batch or classified contributions", () => {
    const f = roundRevealFixture();
    const envelopes = finishDeal(f, new RoundRevealLedger(f.options));
    for (const envelope of envelopes) {
      const before = f.ledger.snapshot;
      expect(f.ledger.classify(envelope).status).toBe("accepted");
      expect(f.ledger.classify(envelope).status).toBe("accepted");
      for (let seat = 0; seat < f.roster.length; seat += 1) {
        expect(f.ledger.readPrivateHand(seat, f.secrets[seat]!)).toBeNull();
      }
      expect(f.ledger.snapshot).toEqual(before);
      f.ledger.commit(envelope);
      if (f.ledger.snapshot.deal !== null) {
        for (let seat = 0; seat < f.roster.length; seat += 1) {
          expect(f.ledger.readPrivateHand(seat, f.secrets[seat]!)).toBeNull();
        }
      }
    }
    expect(f.ledger.readPrivateHand(0, f.secrets[0]!)).toEqual({
      dealt: { 0: "card-b", 1: "card-c" }, remaining: { 0: "card-b", 1: "card-c" },
    });
    expect(f.ledger.readPrivateHand(1, f.secrets[1]!)).toEqual({ dealt: { 2: "card-d" }, remaining: { 2: "card-d" } });
    expect(f.ledger.readPrivateHand(2, f.secrets[2]!)).toEqual({ dealt: {}, remaining: {} });
    expect(f.ledger.snapshot.revealed).toEqual({});
  });

  it("collects noncontiguous owned positions independently of share-item and donor order", () => {
    const f = roundRevealFixture({ schedule: [{ to: 0, count: 2 }, { to: 1, count: 1 }, { to: 0, count: 1 }] });
    finishDeal(f);
    const reordered = new RoundRevealLedger(f.options);
    for (let index = 0; index < f.plans.length; index += 1) {
      for (let actor = f.roster.length - 1; actor >= 0; actor -= 1) {
        if (actor === f.plans[index]!.to) continue;
        const envelope = f.deal(index, actor);
        const body = envelope.envelope.body as CborMap;
        reordered.commit(f.sign(actor, "SHARES", envelope.envelope.phase, { ...body, items: [...body["items"] as CborValue[]].reverse() }));
      }
    }
    expect(reordered.readPrivateHand(0, f.secrets[0]!)).toEqual({
      dealt: { 0: "card-b", 1: "card-c", 3: "card-a" }, remaining: { 0: "card-b", 1: "card-c", 3: "card-a" },
    });
    for (let seat = 0; seat < f.roster.length; seat += 1) {
      expect(reordered.readPrivateHand(seat, f.secrets[seat]!)).toEqual(f.ledger.readPrivateHand(seat, f.secrets[seat]!));
    }
    expect(reordered.snapshot).toEqual(f.ledger.snapshot);
    expect(reordered.snapshot.revealed).toEqual({});
  });

  it.each([false, true])("returns frozen empty maps for an undealt seat (all stock: %s)", (allStock) => {
    const f = roundRevealFixture({ schedule: allStock ? [] : [{ to: 0, count: 2 }] });
    if (!allStock) expect(f.ledger.readPrivateHand(2, f.secrets[2]!)).toBeNull();
    finishDeal(f);
    const before = f.ledger.snapshot;
    const hand = f.ledger.readPrivateHand(2, f.secrets[2]!)!;
    expect(hand).toEqual({ dealt: {}, remaining: {} });
    for (const value of [hand, hand.dealt, hand.remaining]) expect(Object.isFrozen(value)).toBe(true);
    expect(() => f.ledger.readPrivateHand(2, f.secrets[0]!)).toThrow(expect.objectContaining({ code: "invalid_local_key" }));
    expect(f.ledger.snapshot).toEqual(before);
  });

  it.each([false, true])("rejects invalid seats before reading a hand (deal complete: %s)", (complete) => {
    const f = roundRevealFixture();
    if (complete) finishDeal(f);
    const before = f.ledger.snapshot;
    for (const seat of [-1, -0, f.roster.length, 0.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1, "0", null, undefined]) {
      expect(() => f.ledger.readPrivateHand(seat as number, f.secrets[0]!)).toThrow(RangeError);
    }
    expect(f.ledger.snapshot).toEqual(before);
  });

  it.each([false, true])("requires a canonical key matching the requested setup seat without exposing causes (deal complete: %s)", (complete) => {
    const f = roundRevealFixture();
    if (complete) finishDeal(f);
    const before = f.ledger.snapshot;
    for (let seat = 0; seat < f.roster.length; seat += 1) {
      const valid = f.ledger.readPrivateHand(seat, f.secrets[seat]!);
      const keyBytes = new Uint8Array(32).fill(0xa7);
      const invalidKeys: unknown[] = [
        ...f.secrets.filter((_, other) => other !== seat), scalarFromBigInt(77n), 0n, -1n,
        RISTRETTO_SCALAR_ORDER, RISTRETTO_SCALAR_ORDER + f.secrets[seat]!, f.secrets[seat]! - RISTRETTO_SCALAR_ORDER,
        Number(f.secrets[seat]!), String(f.secrets[seat]!), Object(f.secrets[seat]!), keyBytes, null, undefined,
      ];
      for (const key of invalidKeys) {
        let error: unknown;
        try { f.ledger.readPrivateHand(seat, key as RistrettoScalar); }
        catch (caught) { error = caught; }
        expect(error).toBeInstanceOf(RoundRevealError);
        expect(error).toMatchObject({ code: "invalid_local_key", message: "Round reveal rejected: invalid_local_key" });
        expect(error).not.toHaveProperty("cause");
      }
      expect(keyBytes).toEqual(new Uint8Array(32).fill(0xa7));
      expect(f.ledger.readPrivateHand(seat, f.secrets[seat]!)).toEqual(valid);
    }
    expect(f.ledger.snapshot).toEqual(before);
  });

  it.each(["malformed_body", "invalid_share_proof"] as const)("does not make hands ready when the final contribution fails: %s", (code) => {
    const f = roundRevealFixture();
    const envelopes = finishDeal(f, new RoundRevealLedger(f.options));
    for (const envelope of envelopes.slice(0, -1)) f.ledger.commit(envelope);
    const last = envelopes.at(-1)!;
    const body = last.envelope.body as CborMap;
    const items = body["items"] as readonly CborMap[];
    const changed = code === "malformed_body" ? { ...body, items: [] } : { ...body, items: [{ ...items[0]!, z: new Uint8Array(32) }] };
    const bad = f.sign(2, "SHARES", last.envelope.phase, changed);
    const before = f.ledger.snapshot;
    expect(() => f.ledger.commit(bad)).toThrow(expect.objectContaining({ code }));
    expect(f.ledger.classify(last).status).toBe("accepted");
    for (let seat = 0; seat < f.roster.length; seat += 1) {
      expect(f.ledger.readPrivateHand(seat, f.secrets[seat]!)).toBeNull();
    }
    expect(f.ledger.snapshot).toEqual(before);
    f.ledger.commit(last);
    expect(f.ledger.readPrivateHand(0, f.secrets[0]!)).toEqual({
      dealt: { 0: "card-b", 1: "card-c" }, remaining: { 0: "card-b", 1: "card-c" },
    });
    expect(f.ledger.readPrivateHand(1, f.secrets[1]!)).toEqual({ dealt: { 2: "card-d" }, remaining: { 2: "card-d" } });
  });

  it("uses only owned local decryption shares without generating or reverifying proofs or publishing cards", () => {
    const f = roundRevealFixture();
    finishDeal(f);
    const before = f.ledger.snapshot;
    const decrypt = vi.spyOn(deckCrypto, "decryptionShare");
    const prove = vi.spyOn(deckCrypto, "createProvenDecryptionShare");
    const verify = vi.spyOn(deckCrypto, "verifyProvenDecryptionShare");
    try {
      for (let repeat = 0; repeat < 2; repeat += 1) {
        for (let seat = 0; seat < f.roster.length; seat += 1) f.ledger.readPrivateHand(seat, f.secrets[seat]!);
      }
      expect(decrypt.mock.calls.map(([key, point]) => [key, bytesToHex(point.toBytes())])).toEqual(
        [0, 1].flatMap(() => [0, 1, 2].map((pos) => [f.secrets[pos === 2 ? 1 : 0], bytesToHex(f.deck[pos]!.A.toBytes())])),
      );
      expect(prove).not.toHaveBeenCalled();
      expect(verify).not.toHaveBeenCalled();
      expect(f.ledger.snapshot).toEqual(before);
      expect(f.ledger.snapshot.revealed).toEqual({});
    } finally {
      decrypt.mockRestore(); prove.mockRestore(); verify.mockRestore();
    }
  });

  it("freezes hand maps and isolates reads from caller-owned deck, schedule, card and committed-envelope buffers", () => {
    const f = roundRevealFixture();
    const deck = f.deck.map((card) => ({ ...card }));
    const schedule = f.options.schedule.map((step) => ({ ...step }));
    const cards = [...f.options.deckSpec.cards];
    const ledger = new RoundRevealLedger({ ...f.options, deck, schedule, deckSpec: { id: f.options.deckSpec.id, cards } });
    const envelopes = finishDeal(f, ledger);
    const before = ledger.snapshot;
    const hand = ledger.readPrivateHand(0, f.secrets[0]!)!;
    expect(hand).toEqual({ dealt: { 0: "card-b", 1: "card-c" }, remaining: { 0: "card-b", 1: "card-c" } });
    for (const value of [hand, hand.dealt, hand.remaining]) expect(Object.isFrozen(value)).toBe(true);
    expect(() => (hand as { dealt: Record<number, string> }).dealt = {}).toThrow(TypeError);
    expect(() => (hand.dealt as Record<number, string>)[0] = "forged-card").toThrow(TypeError);
    expect(() => delete (hand.remaining as Record<number, string>)[1]).toThrow(TypeError);
    deck[0]!.B = RistrettoPoint.identity();
    schedule[0]!.to = 2; schedule[0]!.count = 4; cards.fill("other");
    for (const envelope of envelopes) {
      envelope.canonicalBytes.fill(0);
      envelope.hash.fill(0xff);
      const body = envelope.envelope.body as CborMap;
      for (const item of body["items"] as readonly CborMap[]) {
        for (const value of Object.values(item)) if (value instanceof Uint8Array) value.fill(0);
      }
    }
    expect(ledger.readPrivateHand(0, f.secrets[0]!)).toEqual(hand);
    expect(ledger.snapshot).toEqual(before);
    expect(ledger.commit(f.action(0, [0]), 0)).toMatchObject({ revealed: { 0: "card-b" } });
    expect(ledger.readPrivateHand(0, f.secrets[0]!)).toEqual({ dealt: hand.dealt, remaining: { 1: "card-c" } });
    expect(hand.remaining).toEqual({ 0: "card-b", 1: "card-c" });
  });

  it("preserves dealt cards while removing only committed own openings, including replay and exhaustion", () => {
    const f = roundRevealFixture();
    const envelopes = finishDeal(f);
    const original = f.ledger.readPrivateHand(0, f.secrets[0]!)!;
    const own = f.action(0, [0]);
    f.ledger.classify(own, 0);
    expect(f.ledger.readPrivateHand(0, f.secrets[0]!)).toEqual(original);
    expect(f.ledger.snapshot.revealed).toEqual({});
    f.ledger.commit(own, 0);
    const afterOwn = f.ledger.readPrivateHand(0, f.secrets[0]!);
    expect(afterOwn).toEqual({ dealt: original.dealt, remaining: { 1: "card-c" } });
    expect(f.ledger.readPrivateHand(1, f.secrets[1]!)).toEqual({ dealt: { 2: "card-d" }, remaining: { 2: "card-d" } });
    const other = f.action(1, [2], 1);
    f.ledger.commit(other, 1);
    envelopes.push(own, other);
    expect(f.ledger.readPrivateHand(0, f.secrets[0]!)).toEqual(afterOwn);
    expect(f.ledger.readPrivateHand(1, f.secrets[1]!)).toEqual({ dealt: { 2: "card-d" }, remaining: {} });
    expect(f.ledger.snapshot.revealed).toEqual({ 0: "card-b", 2: "card-d" });
    expect(JSON.stringify(f.ledger.snapshot)).not.toContain("card-c");
    const expectedHands = f.secrets.map((key, seat) => f.ledger.readPrivateHand(seat, key));
    const replay = new RoundRevealLedger(f.options);
    for (const envelope of envelopes) {
      const actor = f.roster.findIndex((identity) => bytesToHex(identity) === bytesToHex(envelope.envelope.from));
      replay.commit(envelope, actor);
    }
    for (const ledger of [f.ledger, replay]) {
      const before = ledger.snapshot;
      for (const envelope of [...envelopes].reverse()) expect(ledger.commit(envelope).status).toBe("duplicate");
      for (let seat = 0; seat < f.roster.length; seat += 1) {
        expect(ledger.readPrivateHand(seat, f.secrets[seat]!)).toEqual(expectedHands[seat]);
      }
      expect(ledger.snapshot).toEqual(before);
    }
    expect(replay.snapshot).toEqual(f.ledger.snapshot);
    const final = f.action(0, [1], 2);
    for (const ledger of [f.ledger, replay]) {
      ledger.commit(final, 0);
      expect(ledger.readPrivateHand(0, f.secrets[0]!)).toEqual({ dealt: original.dealt, remaining: {} });
    }
    expect(original.remaining).toEqual(original.dealt);
    expect(afterOwn).toEqual({ dealt: original.dealt, remaining: { 1: "card-c" } });
  });

  it.each(["unknown-plaintext", "duplicate-local-card"] as const)("rejects an inconsistent supplied local deck without changing public state: %s", (mode) => {
    const f = roundRevealFixture();
    const point = mode === "unknown-plaintext" ? RistrettoPoint.base() : f.table.pointAt(1);
    const card = maskCard(point, scalarFromBigInt(11n), f.setup.aggregateKey!);
    const ledger = new RoundRevealLedger({ ...f.options, deck: [f.deck[0]!, card, ...f.deck.slice(2)] });
    expect(ledger.readPrivateHand(0, f.secrets[0]!)).toBeNull();
    finishDeal(f, ledger);
    const before = ledger.snapshot;
    expect(() => ledger.readPrivateHand(0, f.secrets[0]!)).toThrow(expect.objectContaining({ code: "inconsistent_deck" }));
    expect(ledger.readPrivateHand(1, f.secrets[1]!)).toEqual({ dealt: { 2: "card-d" }, remaining: { 2: "card-d" } });
    expect(ledger.readPrivateHand(2, f.secrets[2]!)).toEqual({ dealt: {}, remaining: {} });
    expect(ledger.snapshot).toEqual(before);
    if (mode === "duplicate-local-card") {
      ledger.commit(f.action(0, [0]), 0);
      const opened = ledger.snapshot;
      expect(() => ledger.readPrivateHand(0, f.secrets[0]!)).toThrow(expect.objectContaining({ code: "inconsistent_deck" }));
      expect(ledger.snapshot).toEqual(opened);
    }
  });

  it("detects collisions with another public position without treating private reads or classification as public openings", () => {
    const f = roundRevealFixture();
    const card = maskCard(f.table.pointAt(1), scalarFromBigInt(12n), f.setup.aggregateKey!);
    const ledger = new RoundRevealLedger({ ...f.options, deck: [f.deck[0]!, f.deck[1]!, card, f.deck[3]!] });
    finishDeal(f, ledger);
    const local = { dealt: { 0: "card-b", 1: "card-c" }, remaining: { 0: "card-b", 1: "card-c" } };
    expect(ledger.readPrivateHand(0, f.secrets[0]!)).toEqual(local);
    expect(ledger.readPrivateHand(1, f.secrets[1]!)).toEqual({ dealt: { 2: "card-b" }, remaining: { 2: "card-b" } });
    expect(ledger.readPrivateHand(0, f.secrets[0]!)).toEqual(local);
    const other = f.action(1, [2]);
    expect(ledger.classify(other, 1)).toMatchObject({ status: "accepted", revealed: { 2: "card-b" } });
    expect(ledger.readPrivateHand(0, f.secrets[0]!)).toEqual(local);
    expect(ledger.snapshot.revealed).toEqual({});
    ledger.commit(other, 1);
    const before = ledger.snapshot;
    expect(() => ledger.readPrivateHand(0, f.secrets[0]!)).toThrow(expect.objectContaining({ code: "inconsistent_deck" }));
    expect(ledger.readPrivateHand(1, f.secrets[1]!)).toEqual({ dealt: { 2: "card-b" }, remaining: {} });
    expect(ledger.commit(other).status).toBe("duplicate");
    expect(() => ledger.readPrivateHand(0, f.secrets[0]!)).toThrow(expect.objectContaining({ code: "inconsistent_deck" }));
    expect(ledger.snapshot).toEqual(before);
  });

  it.each(["unknown-plaintext", "duplicate-local-card"] as const)("does not decrypt or validate supplied stock plaintext: %s", (mode) => {
    const f = roundRevealFixture();
    const point = mode === "unknown-plaintext" ? RistrettoPoint.base() : f.table.pointAt(1);
    const stock = maskCard(point, scalarFromBigInt(13n), f.setup.aggregateKey!);
    const ledger = new RoundRevealLedger({ ...f.options, deck: [...f.deck.slice(0, 3), stock] });
    finishDeal(f, ledger);
    const before = ledger.snapshot;
    expect(ledger.ownerAt(3)).toBeNull();
    expect(ledger.readPrivateHand(0, f.secrets[0]!)).toEqual({
      dealt: { 0: "card-b", 1: "card-c" }, remaining: { 0: "card-b", 1: "card-c" },
    });
    expect(ledger.readPrivateHand(1, f.secrets[1]!)).toEqual({ dealt: { 2: "card-d" }, remaining: { 2: "card-d" } });
    expect(ledger.readPrivateHand(2, f.secrets[2]!)).toEqual({ dealt: {}, remaining: {} });
    expect(ledger.snapshot).toEqual(before);
  });
});

describe("private-round local deal shares", () => {
  it.each([3, 4, 8])("prepares caller-signed SHARES for every donor/recipient pair in a %i-seat round", (seats) => {
    const f = roundRevealFixture({
      seats,
      round: 7,
      deckSpec: { id: `deal-share-${seats}/v1`, cards: Array.from({ length: seats + 1 }, (_, index) => `card-${index}`) },
      schedule: Array.from({ length: seats }, (_, index) => ({ to: seats - index - 1, count: 1 })),
    });
    for (let position = 0; position < seats; position += 1) {
      const to = seats - position - 1;
      const phase = `round.7.deal.${position}`;
      for (let seat = seats - 1; seat >= 0; seat -= 1) {
        if (seat === to) continue;
        const before = f.ledger.snapshot;
        const body = f.ledger.createDealShares(seat, f.secrets[seat]!, f.source);
        expect(body.to).toBe(to);
        expect(body.items.map(({ pos }) => pos)).toEqual([position]);
        expect(deckCrypto.verifyProvenDecryptionShare(
          { gameId: f.gameId, round: 7, phase }, position, f.setup.publicKeyAt(seat)!, f.deck[position]!.A, body.items[0]!,
        )).toBe(true);
        expect(f.ledger.snapshot).toEqual(before);
        const envelope = f.sign(seat, "SHARES", phase, encodeSharesBody(body));
        expect(f.ledger.classify(envelope)).toMatchObject({ status: "accepted", type: "SHARES", seat, body: { to } });
        expect(f.ledger.snapshot).toEqual(before);
        expect(f.ledger.commit(envelope)).toMatchObject({ status: "accepted", type: "SHARES", seat });
      }
      expect(f.ledger.snapshot.dealIndex).toBe(position + 1);
    }
    expect(f.ledger.snapshot).toEqual({ phase: "round.7.play.0", dealIndex: seats, actionIndex: 0, deal: null, revealed: {} });
    expect(f.ledger.ownerAt(seats)).toBeNull();
  });

  it("uses only the current batch for noncontiguous repeated recipients, excluding future positions and stock", () => {
    const f = roundRevealFixture({
      deckSpec: { id: "repeated-deal-share/v1", cards: Array.from({ length: 7 }, (_, index) => `card-${index}`) },
      schedule: [{ to: 0, count: 2 }, { to: 1, count: 1 }, { to: 0, count: 2 }],
    });
    const batches = [{ to: 0, positions: [0, 1] }, { to: 1, positions: [2] }, { to: 0, positions: [3, 4] }];
    for (const [index, { to, positions }] of batches.entries()) {
      for (const seat of [2, 1, 0]) {
        if (seat === to) continue;
        const body = f.ledger.createDealShares(seat, f.secrets[seat]!, f.source);
        expect(body.to).toBe(to);
        expect(body.items.map(({ pos }) => pos)).toEqual(positions);
        expect(f.ledger.readPrivateHand(to, f.secrets[to]!)).toBeNull();
        expect(f.ledger.commit(f.sign(seat, "SHARES", `round.2.deal.${index}`, encodeSharesBody(body))).status).toBe("accepted");
      }
    }
    expect(f.deck.map((_, pos) => f.ledger.ownerAt(pos))).toEqual([0, 0, 1, 0, 0, null, null]);
    expect(f.ledger.snapshot).toMatchObject({ phase: "round.2.play.0", revealed: {} });
  });

  it("binds every proof to the current game, round, exact deal phase, accepted key, position, and ciphertext A", () => {
    const f = roundRevealFixture({ round: 9, schedule: [{ to: 1, count: 1 }, { to: 0, count: 2 }] });
    f.ledger.commit(f.deal(0, 0)); f.ledger.commit(f.deal(0, 2));
    const before = f.ledger.snapshot;
    const context = { gameId: f.gameId, round: 9, phase: "round.9.deal.1" };
    const body = f.ledger.createDealShares(1, f.secrets[1]!, f.source);
    for (const item of body.items) {
      const key = f.setup.publicKeyAt(1)!;
      const A = f.deck[item.pos]!.A;
      expect(deckCrypto.verifyProvenDecryptionShare(context, item.pos, key, A, item)).toBe(true);
      for (const changed of [
        { ...context, gameId: parseGameId(new Uint8Array(16).fill(0x62)) },
        { ...context, round: 10 },
        { ...context, phase: "round.9.deal.0" },
        { ...context, phase: "round.9.deal.2" },
        { ...context, phase: "round.9.deal.01" },
        { ...context, phase: "round.9.play.1" },
      ]) expect(deckCrypto.verifyProvenDecryptionShare(changed, item.pos, key, A, item)).toBe(false);
      const otherPosition = item.pos === 1 ? 2 : 1;
      expect(deckCrypto.verifyProvenDecryptionShare(context, item.pos, f.setup.publicKeyAt(0)!, A, item)).toBe(false);
      expect(deckCrypto.verifyProvenDecryptionShare(context, otherPosition, key, A, item)).toBe(false);
      expect(deckCrypto.verifyProvenDecryptionShare(context, item.pos, key, f.deck[otherPosition]!.A, item)).toBe(false);
    }
    expect(body.items.map(({ pos }) => pos)).toEqual([1, 2]);
    expect(f.ledger.snapshot).toEqual(before);
  });

  it("uses fresh per-item nonces across unsigned attempts without signing, opening hands, or changing state", () => {
    const f = roundRevealFixture();
    const before = f.ledger.snapshot;
    const source = { fill: vi.fn((bytes: Uint8Array) => {
      expect(bytes).toEqual(new Uint8Array(32));
      expect(f.ledger.snapshot).toEqual(before);
      for (let seat = 0; seat < f.roster.length; seat += 1) expect(f.ledger.readPrivateHand(seat, f.secrets[seat]!)).toBeNull();
      f.source.fill(bytes);
    }) };
    const sign = vi.spyOn(protocol, "signEnvelope");
    const open = vi.spyOn(deckCrypto, "removeDecryptionShares");
    const identify = vi.spyOn(deckCrypto.CardPointTable.prototype, "identify");
    try {
      const first = f.ledger.createDealShares(1, f.secrets[1]!, source);
      const second = f.ledger.createDealShares(1, f.secrets[1]!, source);
      expect(source.fill).toHaveBeenCalledTimes(4);
      expect(new Set([...first.items, ...second.items].map(({ proof }) => bytesToHex(proof.R1.toBytes()))).size).toBe(4);
      for (const [index, item] of first.items.entries()) {
        const repeat = second.items[index]!;
        expect(item.S.equals(repeat.S)).toBe(true);
        expect(item.proof.R2.equals(repeat.proof.R2)).toBe(false);
        expect(item.proof.z).not.toBe(repeat.proof.z);
      }
      for (const body of [first, second]) {
        expect(Object.keys(body).sort()).toEqual(["items", "to"]);
        for (const item of body.items) {
          expect(Object.keys(item).sort()).toEqual(["S", "pos", "proof"]);
          expect(Object.keys(item.proof).sort()).toEqual(["R1", "R2", "z"]);
        }
      }
      expect(sign).not.toHaveBeenCalled();
      expect(open).not.toHaveBeenCalled();
      expect(identify).not.toHaveBeenCalled();
      expect(f.ledger.snapshot).toEqual(before);
      for (let seat = 0; seat < f.roster.length; seat += 1) expect(f.ledger.readPrivateHand(seat, f.secrets[seat]!)).toBeNull();
    } finally {
      sign.mockRestore(); open.mockRestore(); identify.mockRestore();
    }
  });

  it("returns frozen bodies, item arrays, items, and proofs with isolated point encodings", () => {
    const f = roundRevealFixture();
    const before = f.ledger.snapshot;
    const body = f.ledger.createDealShares(1, f.secrets[1]!, f.source);
    expect(Object.isFrozen(body)).toBe(true);
    expect(Object.isFrozen(body.items)).toBe(true);
    expect(() => (body as { to: number }).to = 2).toThrow(TypeError);
    expect(() => (body.items as unknown[]).pop()).toThrow(TypeError);
    for (const item of body.items) {
      expect(Object.isFrozen(item)).toBe(true);
      expect(Object.isFrozen(item.proof)).toBe(true);
      expect(() => (item as { pos: number }).pos = 3).toThrow(TypeError);
      expect(() => (item as { S: RistrettoPoint }).S = RistrettoPoint.identity()).toThrow(TypeError);
      expect(() => (item.proof as { z: RistrettoScalar }).z = scalarFromBigInt(0n)).toThrow(TypeError);
      for (const point of [item.S, item.proof.R1, item.proof.R2]) {
        const encoding = bytesToHex(point.toBytes());
        point.toBytes().fill(0xff);
        expect(bytesToHex(point.toBytes())).toBe(encoding);
      }
    }
    expect(f.ledger.snapshot).toEqual(before);
    expect(f.ledger.commit(f.sign(1, "SHARES", before.phase, encodeSharesBody(body))).status).toBe("accepted");
  });

  it("rejects mismatched and noncanonical local keys before randomness without exposing key values or causes", () => {
    const f = roundRevealFixture();
    const before = f.ledger.snapshot;
    const source = { fill: vi.fn(f.source.fill) };
    const keyBytes = new Uint8Array(32).fill(0xa7);
    for (const key of [f.secrets[0], scalarFromBigInt(77n), 0n, -1n, RISTRETTO_SCALAR_ORDER,
      RISTRETTO_SCALAR_ORDER + f.secrets[1]!, Number(f.secrets[1]!), "private-key-must-not-leak", keyBytes, null]) {
      let error: unknown;
      try { f.ledger.createDealShares(1, key as RistrettoScalar, source); }
      catch (caught) { error = caught; }
      expect(error).toBeInstanceOf(RoundRevealError);
      expect(error).toMatchObject({ code: "invalid_local_key", message: "Round reveal rejected: invalid_local_key" });
      expect(error).not.toHaveProperty("cause");
      expect(JSON.parse(JSON.stringify(error))).toEqual({ name: "RoundRevealError", code: "invalid_local_key" });
    }
    expect(keyBytes).toEqual(new Uint8Array(32).fill(0xa7));
    expect(source.fill).not.toHaveBeenCalled();
    expect(f.ledger.snapshot).toEqual(before);
  });

  it("rejects invalid local seats before randomness", () => {
    const f = roundRevealFixture();
    const before = f.ledger.snapshot;
    const source = { fill: vi.fn(f.source.fill) };
    for (const seat of [-0, -1, f.roster.length, 0.5, NaN, Infinity, "0", null, undefined]) {
      expect(() => f.ledger.createDealShares(seat as number, f.secrets[0]!, source)).toThrow(RangeError);
    }
    expect(source.fill).not.toHaveBeenCalled();
    expect(f.ledger.snapshot).toEqual(before);
  });

  it("rejects the recipient and an already committed contributor before randomness", () => {
    const f = roundRevealFixture();
    const source = { fill: vi.fn(f.source.fill) };
    for (const [seat, code] of [[0, "unexpected_sender"], [1, "conflicting_contribution"]] as const) {
      if (seat === 1) f.ledger.commit(f.deal(0, seat));
      const before = f.ledger.snapshot;
      expect(() => f.ledger.createDealShares(seat, f.secrets[seat]!, source)).toThrow(expect.objectContaining({ code }));
      expect(source.fill).not.toHaveBeenCalled();
      expect(f.ledger.snapshot).toEqual(before);
    }
  });

  it("rejects empty and fully committed schedules before randomness", () => {
    for (const schedule of [[], [{ to: 0, count: 2 }]]) {
      const f = roundRevealFixture({ schedule });
      finishDeal(f);
      const before = f.ledger.snapshot;
      const source = { fill: vi.fn(f.source.fill) };
      expect(() => f.ledger.createDealShares(1, f.secrets[1]!, source)).toThrow(expect.objectContaining({ code: "wrong_phase" }));
      expect(source.fill).not.toHaveBeenCalled();
      expect(f.ledger.snapshot).toEqual(before);
    }
  });

  it("returns no partial batch or state changes when the second random draw throws, and permits a full retry", () => {
    const f = roundRevealFixture();
    const before = f.ledger.snapshot;
    const failure = new Error("Random source failed");
    let draws = 0;
    const source = { fill: vi.fn((bytes: Uint8Array) => {
      if (++draws === 2) throw failure;
      f.source.fill(bytes);
    }) };
    let returned: SharesBody | undefined;
    let error: unknown;
    try { returned = f.ledger.createDealShares(1, f.secrets[1]!, source); }
    catch (caught) { error = caught; }
    expect(error).toBe(failure);
    expect(Object.keys(failure)).toEqual([]);
    expect(returned).toBeUndefined();
    expect(source.fill).toHaveBeenCalledTimes(2);
    expect(f.ledger.snapshot).toEqual(before);
    for (let seat = 0; seat < f.roster.length; seat += 1) expect(f.ledger.readPrivateHand(seat, f.secrets[seat]!)).toBeNull();
    const retry = f.ledger.createDealShares(1, f.secrets[1]!, f.source);
    expect(retry.items.map(({ pos }) => pos)).toEqual([0, 1]);
    expect(f.ledger.commit(f.sign(1, "SHARES", before.phase, encodeSharesBody(retry))).status).toBe("accepted");
    expect(f.ledger.snapshot.deal?.pendingSenders).toEqual([2]);
  });

  it.each(["first item", "last item", "rejected nonce"] as const)(
    "rejects a reentrant own contribution without another draw or rollback: %s", (when) => {
      const f = roundRevealFixture();
      const before = f.ledger.snapshot;
      const own = f.deal(0, 1);
      const commitAt = when === "last item" ? 2 : 1;
      let draws = 0;
      const source = { fill: vi.fn((bytes: Uint8Array) => {
        if (++draws === commitAt) {
          expect(f.ledger.commit(own).status).toBe("accepted");
          if (when === "rejected nonce") { bytes.fill(0); return; }
        }
        f.source.fill(bytes);
      }) };
      expect(() => f.ledger.createDealShares(1, f.secrets[1]!, source)).toThrow(expect.objectContaining({ code: "conflicting_contribution" }));
      const committed = { ...before, deal: { ...before.deal!, pendingSenders: [2] } };
      expect(f.ledger.snapshot).toEqual(committed);
      expect(f.ledger.commit(own).status).toBe("duplicate");
      expect(f.ledger.snapshot).toEqual(committed);
      expect(source.fill).toHaveBeenCalledTimes(commitAt);
    },
  );

  it.each([false, true])("rejects a batch when the final callback advances the phase without rolling back commits (play: %s)", (play) => {
    const f = roundRevealFixture({ schedule: [{ to: 0, count: 2 }, ...(play ? [] : [{ to: 1, count: 1 }])] });
    f.ledger.commit(f.deal(0, 2));
    const advance = f.deal(0, 1);
    let draws = 0;
    const source = { fill: vi.fn((bytes: Uint8Array) => {
      if (++draws === 2) expect(f.ledger.commit(advance).status).toBe("accepted");
      f.source.fill(bytes);
    }) };
    expect(() => f.ledger.createDealShares(1, f.secrets[1]!, source)).toThrow(expect.objectContaining({ code: "wrong_phase" }));
    expect(source.fill).toHaveBeenCalledTimes(2);
    const committed = f.ledger.snapshot;
    expect(committed).toEqual({
      phase: play ? "round.2.play.0" : "round.2.deal.1", dealIndex: 1, actionIndex: 0,
      deal: play ? null : { to: 1, positions: [2], pendingSenders: [0, 2] }, revealed: {},
    });
    expect(f.ledger.commit(advance).status).toBe("duplicate");
    expect(f.ledger.snapshot).toEqual(committed);
  });

  it("allows other donors to commit during preparation while the same step and local contribution remain pending", () => {
    const f = roundRevealFixture({ seats: 4 });
    const before = f.ledger.snapshot;
    const others = [f.deal(0, 2), f.deal(0, 3)];
    let draws = 0;
    const source = { fill: vi.fn((bytes: Uint8Array) => {
      expect(f.ledger.commit(others[draws++]!).status).toBe("accepted");
      f.source.fill(bytes);
    }) };
    const body = f.ledger.createDealShares(1, f.secrets[1]!, source);
    expect(source.fill).toHaveBeenCalledTimes(2);
    expect(body.to).toBe(0);
    expect(body.items.map(({ pos }) => pos)).toEqual([0, 1]);
    expect(f.ledger.snapshot).toEqual({ ...before, deal: { ...before.deal!, pendingSenders: [1] } });
    expect(f.ledger.readPrivateHand(0, f.secrets[0]!)).toBeNull();
    expect(f.ledger.commit(f.sign(1, "SHARES", before.phase, encodeSharesBody(body))).status).toBe("accepted");
    expect(f.ledger.snapshot).toMatchObject({ phase: "round.2.deal.1", dealIndex: 1, revealed: {} });
  });
});

describe("private-round local action shares", () => {
  it.each([3, 8])("prepares each owner's share for a caller-signed current-phase ACTION in a %i-seat round", (seats) => {
    const f = roundRevealFixture({
      seats,
      round: 7,
      deckSpec: { id: `action-share-${seats}/v1`, cards: Array.from({ length: seats + 1 }, (_, index) => `card-${index}`) },
      schedule: Array.from({ length: seats }, (_, index) => ({ to: seats - index - 1, count: 1 })),
    });
    finishDeal(f);
    for (let seat = 0; seat < seats; seat += 1) {
      const position = seats - seat - 1;
      const phase = f.ledger.snapshot.phase;
      const share = f.ledger.createActionShare(seat, f.secrets[seat]!, position);
      expect(share.pos).toBe(position);
      for (let signer = 0; signer < seats; signer += 1) {
        expect(deckCrypto.verifyProvenDecryptionShare(
          { gameId: f.gameId, round: f.round, phase }, position, f.setup.publicKeyAt(signer)!, f.deck[position]!.A, share,
        )).toBe(signer === seat);
      }
      const body = encodeActionBody({ kind: "caller_defined", data: {}, reveal: [position], shares: [share] });
      expect(f.ledger.commit(f.sign(seat, "ACTION", phase, body), seat)).toMatchObject({
        status: "accepted", type: "ACTION", seat, revealed: { [position]: f.cards[position] },
      });
      expect(f.ledger.snapshot.phase).toBe(`round.7.play.${seat + 1}`);
    }
  });

  it("uses fresh nonces in the exact current context without signing, changing hands, or consuming a position or budget", () => {
    const f = roundRevealFixture({ round: 9, maxActions: 2 });
    finishDeal(f);
    f.ledger.commit(f.action(1, [], 0, "pass"), 1);
    const before = f.ledger.snapshot;
    const hands = f.secrets.map((key, seat) => f.ledger.readPrivateHand(seat, key));
    const owners = f.deck.map((_, pos) => f.ledger.ownerAt(pos));
    const context = { gameId: f.gameId, round: 9, phase: "round.9.play.1" };
    const source = { fill: vi.fn(f.source.fill) };
    const sign = vi.spyOn(protocol, "signEnvelope");
    try {
      const first = f.ledger.createActionShare(0, f.secrets[0]!, 1, source);
      const second = f.ledger.createActionShare(0, f.secrets[0]!, 1, source);
      expect(source.fill).toHaveBeenCalledTimes(2);
      expect(first.S.equals(second.S)).toBe(true);
      expect(first.proof.R1.equals(second.proof.R1)).toBe(false);
      expect(first.proof.R2.equals(second.proof.R2)).toBe(false);
      expect(first.proof.z).not.toBe(second.proof.z);
      for (const share of [first, second]) {
        expect(deckCrypto.verifyProvenDecryptionShare(context, 1, f.setup.publicKeyAt(0)!, f.deck[1]!.A, share)).toBe(true);
        for (const changed of [
          { ...context, gameId: parseGameId(new Uint8Array(16).fill(0x62)) },
          { ...context, round: 10 },
          { ...context, phase: "round.9.deal.0" },
          { ...context, phase: "round.9.play.0" },
          { ...context, phase: "round.9.play.2" },
          { ...context, phase: "round.9.play.01" },
        ]) expect(deckCrypto.verifyProvenDecryptionShare(changed, 1, f.setup.publicKeyAt(0)!, f.deck[1]!.A, share)).toBe(false);
        expect(deckCrypto.verifyProvenDecryptionShare(context, 0, f.setup.publicKeyAt(0)!, f.deck[1]!.A, share)).toBe(false);
        expect(deckCrypto.verifyProvenDecryptionShare(context, 1, f.setup.publicKeyAt(0)!, f.deck[0]!.A, share)).toBe(false);
      }
      expect(sign).not.toHaveBeenCalled();
      expect(f.ledger.snapshot).toEqual(before);
      expect(f.secrets.map((key, seat) => f.ledger.readPrivateHand(seat, key))).toEqual(hands);
      expect(f.deck.map((_, pos) => f.ledger.ownerAt(pos))).toEqual(owners);
      const body = encodeActionBody({ kind: "play", data: {}, reveal: [1], shares: [second] });
      const action = f.sign(0, "ACTION", before.phase, body);
      expect(f.ledger.classify(action, 0)).toMatchObject({ status: "accepted", revealed: { 1: f.cards[1] } });
      expect(f.ledger.snapshot).toEqual(before);
      expect(f.ledger.commit(action, 0).status).toBe("accepted");
      expect(f.ledger.readPrivateHand(0, f.secrets[0]!)).toEqual({ dealt: hands[0]!.dealt, remaining: { 0: f.cards[0] } });
    } finally {
      sign.mockRestore();
    }
  });

  it.each([false, true])("rejects a mismatched key before requesting randomness (deal complete: %s)", (complete) => {
    const f = roundRevealFixture();
    if (complete) finishDeal(f);
    const before = f.ledger.snapshot;
    const hand = f.ledger.readPrivateHand(0, f.secrets[0]!);
    const source = { fill: vi.fn(f.source.fill) };
    expect(() => f.ledger.createActionShare(0, f.secrets[1]!, 0, source)).toThrow(expect.objectContaining({ code: "invalid_local_key" }));
    expect(source.fill).not.toHaveBeenCalled();
    expect(f.ledger.snapshot).toEqual(before);
    expect(f.ledger.readPrivateHand(0, f.secrets[0]!)).toEqual(hand);
  });

  it("requires the whole committed deal, not a completed local batch or a classified final contribution, before randomness", () => {
    const f = roundRevealFixture();
    const envelopes = finishDeal(f, new RoundRevealLedger(f.options));
    const source = { fill: vi.fn(f.source.fill) };
    for (const envelope of envelopes) {
      const before = f.ledger.snapshot;
      expect(f.ledger.classify(envelope).status).toBe("accepted");
      expect(() => f.ledger.createActionShare(0, f.secrets[0]!, 0, source)).toThrow(expect.objectContaining({ code: "deal_incomplete" }));
      expect(source.fill).not.toHaveBeenCalled();
      expect(f.ledger.readPrivateHand(0, f.secrets[0]!)).toBeNull();
      expect(f.ledger.snapshot).toEqual(before);
      f.ledger.commit(envelope);
    }
    expect(f.ledger.createActionShare(0, f.secrets[0]!, 0, source).pos).toBe(0);
    expect(source.fill).toHaveBeenCalledTimes(1);
    expect(f.ledger.snapshot).toMatchObject({ phase: "round.2.play.0", revealed: {} });
  });

  it.each([
    ["wrong_owner", 2], ["unscheduled_position", 3], ["already_revealed", 0], ["action_limit", 1],
  ] as const)("rejects %s before requesting randomness for position %i", (code, position) => {
    const f = roundRevealFixture({ maxActions: code === "action_limit" ? 1 : 64 });
    finishDeal(f);
    if (code === "already_revealed") f.ledger.commit(f.action(0, [0]), 0);
    if (code === "action_limit") f.ledger.commit(f.action(0, [], 0, "pass"), 0);
    const before = f.ledger.snapshot;
    const hands = f.secrets.map((key, seat) => f.ledger.readPrivateHand(seat, key));
    const source = { fill: vi.fn(f.source.fill) };
    expect(() => f.ledger.createActionShare(0, f.secrets[0]!, position, source)).toThrow(expect.objectContaining({ code }));
    expect(source.fill).not.toHaveBeenCalled();
    expect(f.ledger.snapshot).toEqual(before);
    expect(f.secrets.map((key, seat) => f.ledger.readPrivateHand(seat, key))).toEqual(hands);
  });

  it("rejects invalid positions before requesting randomness", () => {
    const f = roundRevealFixture();
    finishDeal(f);
    const before = f.ledger.snapshot;
    const hand = f.ledger.readPrivateHand(0, f.secrets[0]!);
    const source = { fill: vi.fn(f.source.fill) };
    for (const pos of [-0, -1, f.deck.length, 0.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1, "0", null, undefined]) {
      expect(() => f.ledger.createActionShare(0, f.secrets[0]!, pos as number, source)).toThrow(RangeError);
      expect(source.fill).not.toHaveBeenCalled();
      expect(f.ledger.snapshot).toEqual(before);
    }
    expect(f.ledger.readPrivateHand(0, f.secrets[0]!)).toEqual(hand);
  });

  it.each(["unknown-plaintext", "duplicate-local-card"] as const)("validates the whole local hand before randomness, even for an unaffected position: %s", (mode) => {
    const f = roundRevealFixture();
    const point = mode === "unknown-plaintext" ? RistrettoPoint.base() : f.table.pointAt(1);
    const card = maskCard(point, scalarFromBigInt(11n), f.setup.aggregateKey!);
    const ledger = new RoundRevealLedger({ ...f.options, deck: [f.deck[0]!, card, ...f.deck.slice(2)] });
    finishDeal(f, ledger);
    const before = ledger.snapshot;
    const otherHand = ledger.readPrivateHand(1, f.secrets[1]!);
    const source = { fill: vi.fn(f.source.fill) };
    expect(() => ledger.createActionShare(0, f.secrets[0]!, 0, source)).toThrow(expect.objectContaining({ code: "inconsistent_deck" }));
    expect(source.fill).not.toHaveBeenCalled();
    expect(ledger.snapshot).toEqual(before);
    expect(ledger.readPrivateHand(1, f.secrets[1]!)).toEqual(otherHand);
  });

  it("leaves the ledger and private hands unchanged when randomness throws and permits a retry", () => {
    const f = roundRevealFixture({ maxActions: 1 });
    finishDeal(f);
    const before = f.ledger.snapshot;
    const hands = f.secrets.map((key, seat) => f.ledger.readPrivateHand(seat, key));
    const failure = new Error("Random source failed");
    const source = { fill: vi.fn(() => { throw failure; }) };
    expect(() => f.ledger.createActionShare(0, f.secrets[0]!, 0, source)).toThrow(failure);
    expect(source.fill).toHaveBeenCalledTimes(1);
    expect(f.ledger.snapshot).toEqual(before);
    expect(f.secrets.map((key, seat) => f.ledger.readPrivateHand(seat, key))).toEqual(hands);
    const share = f.ledger.createActionShare(0, f.secrets[0]!, 0, f.source);
    const body = encodeActionBody({ kind: "play", data: {}, reveal: [0], shares: [share] });
    expect(f.ledger.commit(f.sign(0, "ACTION", before.phase, body), 0)).toMatchObject({ status: "accepted", revealed: { 0: f.cards[0] } });
    expect(f.ledger.snapshot.actionIndex).toBe(1);
  });

  it.each([
    [false, false], [false, true], [true, false], [true, true],
  ])("rejects a stale proof without rolling back an action committed by the random source (opens requested position: %s, zero nonce: %s)", (opens, zeroNonce) => {
    const f = roundRevealFixture();
    finishDeal(f);
    const before = f.ledger.snapshot;
    const hand = f.ledger.readPrivateHand(0, f.secrets[0]!)!;
    const shares = opens ? [f.ledger.createActionShare(0, f.secrets[0]!, 0, f.source)] : [];
    const body = encodeActionBody({ kind: opens ? "play" : "pass", data: {}, reveal: opens ? [0] : [], shares });
    const advance = f.sign(0, "ACTION", before.phase, body);
    let draws = 0;
    const source = { fill: vi.fn((bytes: Uint8Array) => {
      if (++draws === 1) {
        expect(f.ledger.commit(advance, 0).status).toBe("accepted");
        if (zeroNonce) { bytes.fill(0); return; }
      }
      f.source.fill(bytes);
    }) };
    expect(() => f.ledger.createActionShare(0, f.secrets[0]!, 0, source)).toThrow(expect.objectContaining({ code: "wrong_phase" }));
    expect(source.fill).toHaveBeenCalledTimes(1);
    const committed = f.ledger.snapshot;
    expect(committed).toEqual({ ...before, phase: "round.2.play.1", actionIndex: 1, revealed: opens ? { 0: f.cards[0] } : {} });
    expect(f.ledger.readPrivateHand(0, f.secrets[0]!)).toEqual({ dealt: hand.dealt, remaining: opens ? { 1: f.cards[1] } : hand.remaining });
    expect(f.ledger.commit(advance, 0).status).toBe("duplicate");
    expect(f.ledger.snapshot).toEqual(committed);
    const fresh = f.ledger.createActionShare(0, f.secrets[0]!, 1, f.source);
    const next = encodeActionBody({ kind: "play", data: {}, reveal: [1], shares: [fresh] });
    expect(f.ledger.commit(f.sign(0, "ACTION", committed.phase, next), 0)).toMatchObject({ status: "accepted", revealed: { 1: f.cards[1] } });
  });
});

function finishDeal(fixture: ReturnType<typeof roundRevealFixture>, ledger = fixture.ledger): EnvelopeArtifact[] {
  const envelopes: EnvelopeArtifact[] = [];
  for (let index = 0; index < fixture.plans.length; index += 1) {
    for (let actor = 0; actor < fixture.roster.length; actor += 1) {
      if (actor === fixture.plans[index]!.to) continue;
      const envelope = fixture.deal(index, actor);
      ledger.commit(envelope);
      envelopes.push(envelope);
    }
  }
  return envelopes;
}
