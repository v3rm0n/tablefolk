import { decodeActionBody, encodeActionBody, verifyProvenDecryptionShare } from "@p2pcards/deck";
import type { CborMap } from "@p2pcards/encoding";
import { MAX_ROUND_REVEAL_ENVELOPE_BYTES } from "@p2pcards/engine";
import * as protocol from "@p2pcards/protocol";
import { decodeAndVerifyEnvelope, parseGameId, type EnvelopeArtifact } from "@p2pcards/protocol";
import { SaskuHandError, legalSaskuCards, saskuBidStrength, saskuEffectiveSuit } from "@p2pcards/rules-sasku";
import { AuthoredEnvelopeStoreError, PersistentEnvelopeAuthor } from "@p2pcards/session";
import { afterEach, describe, expect, it, vi } from "vitest";

import { act, context, deferred } from "./local-authoring.test-fixture";
import { PersistentSaskuRoundReceiver, type SaskuActionIntent } from "./persistent-round-receiver";

describe("local Sasku action authoring", () => {
  afterEach(() => vi.restoreAllMocks());

  it("authors an exact bid, three passes, chosen trump and a play with the current phase's proof", async () => {
    const c = await context();
    const before = c.game.snapshot;
    const hand = c.game.readPrivateHand(c.author.sender, c.f.secrets[0]!)!;
    const value = saskuBidStrength(Object.values(hand.dealt));
    const native = c.author.author.bind(c.author);
    const guard = vi.fn();
    vi.spyOn(c.author, "author").mockImplementation((content, beforeSign) => {
      expect(beforeSign).toBeTypeOf("function");
      return native(content, (head) => {
        guard(head);
        expect(head).toEqual(c.store.head(c.f.gameId, c.author.sender));
        return beforeSign!(head);
      });
    });
    const rng = vi.spyOn(c.f.source, "fill");
    const bid = await act(c, 0, { type: "bid", value });
    expect(bid).toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "duplicate", snapshot: c.game.snapshot });
    expect(bid.received.envelope).toMatchObject({
      from: c.author.sender, seq: 6, round: c.f.round, phase: before.ledger.phase, type: "ACTION",
      body: { kind: "bid", data: { value }, reveal: [], shares: [] },
    });
    for (const seat of [1, 2, 3] as const) {
      const phase = c.game.snapshot.ledger.phase;
      const pass = await act(c, seat, { type: "pass" });
      expect(pass.received.envelope).toMatchObject({ from: c.authors[seat]!.sender, phase });
      expect(decodeActionBody(pass.received.envelope.body)).toEqual({ kind: "pass", data: {}, reveal: [], shares: [] });
    }
    expect(c.game.snapshot.hand).toMatchObject({ phase: "choosing_trump", turn: 0, highestBid: { seat: 0, value } });
    const choice = await act(c, 0, { type: "choose_trump", suit: "hearts" });
    expect(decodeActionBody(choice.received.envelope.body)).toEqual({ kind: "choose_trump", data: { suit: "hearts" }, reveal: [], shares: [] });
    expect(c.game.snapshot.hand.contract).toEqual({ kind: "named", declarerSeat: 0, suit: "hearts" });
    expect(rng).not.toHaveBeenCalled();
    const playing = c.game.snapshot;
    const play = await act(c, 0, { type: "play", position: 0 });
    expect(play.status).toBe("accepted");
    if (play.status === "rejected") throw new Error("Legal local play was rejected");
    expect(play.snapshot).toBe(c.game.snapshot);
    expect(play.received.envelope).toMatchObject({ phase: playing.ledger.phase, seq: choice.received.envelope.seq + 1, prev: choice.received.hash });
    const body = decodeActionBody(play.received.envelope.body);
    expect(body).toMatchObject({ kind: "play", data: {}, reveal: [0] });
    expect(body.shares).toHaveLength(1);
    const share = body.shares[0]!;
    const proofContext = { gameId: c.f.gameId, round: c.f.round, phase: playing.ledger.phase };
    expect(verifyProvenDecryptionShare(proofContext, 0, c.f.setup.publicKeyAt(0)!, c.f.deck[0]!.A, share)).toBe(true);
    expect(verifyProvenDecryptionShare({ ...proofContext, phase: choice.received.envelope.phase }, 0, c.f.setup.publicKeyAt(0)!, c.f.deck[0]!.A, share)).toBe(false);
    expect(verifyProvenDecryptionShare(proofContext, 1, c.f.setup.publicKeyAt(0)!, c.f.deck[0]!.A, share)).toBe(false);
    expect(guard).toHaveBeenCalledTimes(3);
    expect(rng).toHaveBeenCalledOnce();
    expect(c.game.snapshot.ledger).toMatchObject({ actionIndex: 6, revealed: { 0: hand.dealt[0] } });
    expect(c.game.snapshot.history.at(-1)).toEqual({ type: "play", seat: 0, card: hand.dealt[0] });
    expect(c.game.readPrivateHand(c.author.sender, c.f.secrets[0]!)!.remaining).not.toHaveProperty("0");
    expect(c.store.head(c.f.gameId, c.author.sender)).toEqual(play.received);
    expect(c.game.failure).toBeNull();
  });

  it("rejects false bids and public phase/turn violations before authoring or proof randomness", async () => {
    const c = await context();
    const before = c.game.snapshot;
    const value = saskuBidStrength(Object.values(c.game.readPrivateHand(c.author.sender, c.f.secrets[0]!)!.dealt));
    const append = vi.spyOn(c.store, "appendNext");
    const author = vi.spyOn(c.author, "author");
    const rng = vi.spyOn(c.f.source, "fill");
    await expect(act(c, 0, { type: "bid", value: value === 3 ? 4 : 3 })).rejects.toMatchObject({ rule: "bid_strength" });
    await expect(act(c, 0, { type: "choose_trump", suit: "clubs" })).rejects.toThrow(/during bidding/);
    await expect(act(c, 0, { type: "play", position: 0 })).rejects.toThrow(/during bidding/);
    await expect(act(c, 1, { type: "pass" })).rejects.toThrow(/expected seat/);
    expect(author).not.toHaveBeenCalled();
    expect(append).not.toHaveBeenCalled();
    expect(rng).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    expect(c.game.failure).toBeNull();
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
    await expect(act(c, 0, { type: "bid", value })).resolves.toMatchObject({ status: "accepted" });
  });

  it("enforces effective trump following privately before append or RNG, not printed-suit following", async () => {
    const c = await context();
    await act(c, 0, { type: "diamonds" });
    await act(c, 0, { type: "play", position: c.f.cards.indexOf("JC") });
    const before = c.game.snapshot;
    const hand = c.game.readPrivateHand(c.authors[1]!.sender, c.f.secrets[1]!)!;
    const legal = legalSaskuCards(Object.values(hand.remaining), before.hand.trick, "diamonds");
    expect(saskuEffectiveSuit("JC", "diamonds")).toBe("trump");
    expect(legal).toContain("JS");
    expect(legal).not.toContain("7S");
    const append = vi.spyOn(c.store, "appendNext");
    const rng = vi.spyOn(c.f.source, "fill");
    await expect(act(c, 1, { type: "play", position: c.f.cards.indexOf("7S") })).rejects.toMatchObject({ rule: "follow_suit" });
    expect(append).not.toHaveBeenCalled();
    expect(rng).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    expect(c.game.readPrivateHand(c.authors[1]!.sender, c.f.secrets[1]!)).toEqual(hand);
    expect(c.game.failure).toBeNull();
    await expect(act(c, 1, { type: "play", position: c.f.cards.indexOf("JS") })).resolves.toMatchObject({ status: "accepted" });
    expect(append).toHaveBeenCalledOnce();
    expect(rng).toHaveBeenCalledOnce();
  });

  it("rejects wrong ownership, already revealed positions and off-turn owned cards without consuming them", async () => {
    const c = await context();
    await act(c, 0, { type: "diamonds" });
    await act(c, 0, { type: "play", position: 0 });
    const before = c.game.snapshot;
    const append = vi.spyOn(c.store, "appendNext");
    const rng = vi.spyOn(c.f.source, "fill");
    await expect(act(c, 1, { type: "play", position: 0 })).rejects.toMatchObject({ code: "wrong_owner" });
    await expect(act(c, 0, { type: "play", position: 0 })).rejects.toMatchObject({ code: "already_revealed" });
    await expect(act(c, 2, { type: "play", position: 18 })).rejects.toThrow(/expected seat/);
    await expect(act(c, 0, { type: "play", position: 1 })).rejects.toThrow(/expected seat/);
    expect(append).not.toHaveBeenCalled();
    expect(rng).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    expect(c.game.failure).toBeNull();
    expect(c.game.pendingBytes).toBe(0);
    await expect(act(c, 1, { type: "play", position: 9 })).resolves.toMatchObject({ status: "accepted" });
  });

  it("derives identity from a real author and rejects wrong game, sender and local keys nonterminally", async () => {
    const c = await context();
    const before = c.game.snapshot;
    const append = vi.spyOn(c.store, "appendNext");
    const rng = vi.spyOn(c.f.source, "fill");
    const fake = { gameId: c.f.gameId, sender: c.author.sender, author: vi.fn() };
    await expect(c.game.authorAction(fake as unknown as PersistentEnvelopeAuthor, c.f.secrets[0]!, before, { type: "pass" }))
      .rejects.toBeInstanceOf(TypeError);
    const wrongGame = new PersistentEnvelopeAuthor(parseGameId(new Uint8Array(16).fill(7)), c.f.identities[0]!.secretKey, c.store);
    const stranger = new PersistentEnvelopeAuthor(c.f.gameId, c.f.identities[4]!.secretKey, c.store);
    for (const [author, code] of [[wrongGame, "wrong_game"], [stranger, "unknown_sender"]] as const) {
      await expect(c.game.authorAction(author, c.f.secrets[0]!, before, { type: "pass" }, c.f.source)).rejects.toMatchObject({ code });
    }
    for (const key of [c.f.secrets[1], 0n, -1n, 1, null]) {
      await expect(c.game.authorAction(c.author, key as never, before, { type: "pass" }, c.f.source))
        .rejects.toMatchObject({ code: "invalid_local_key" });
      expect(c.game.pendingEnvelopes).toBe(0);
      expect(c.game.pendingBytes).toBe(0);
    }
    expect(fake.author).not.toHaveBeenCalled();
    expect(append).not.toHaveBeenCalled();
    expect(rng).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    expect(c.game.failure).toBeNull();
    await expect(act(c, 0, { type: "diamonds" })).resolves.toMatchObject({ status: "accepted" });
  });

  it("strictly snapshots plain intents, rejecting malformed fields without invoking accessors", async () => {
    const c = await context();
    const before = c.game.snapshot;
    const getter = vi.fn(() => "pass");
    const invalid: unknown[] = [
      null, undefined, "pass", [], new Map([["type", "pass"]]), Object.create({ type: "pass" }),
      {}, { type: "PASS" }, { type: "bid" }, { type: "bid", value: 2 }, { type: "bid", value: 10 },
      { type: "bid", value: 3.5 }, { type: "bid", value: "3" }, { type: "bid", value: NaN },
      { type: "choose_trump", suit: "stars" }, { type: "choose_trump", suit: 0 },
      ...[-0, -1, 36, 0.5, Infinity, Number.MAX_SAFE_INTEGER + 1, "0"].map((position) => ({ type: "play", position })),
      { type: "diamonds", seat: 0 }, { type: "pass", from: c.author.sender }, { type: "play", position: 0, actor: 0 },
      { type: "pass", [Symbol("actor")]: 0 }, Object.defineProperty({}, "type", { enumerable: true, get: getter }),
      Object.defineProperty({ type: "play" }, "position", { enumerable: true, get: getter }),
      Object.defineProperty({}, "type", { value: "pass", enumerable: false }),
    ];
    const author = vi.spyOn(c.author, "author");
    const append = vi.spyOn(c.store, "appendNext");
    const rng = vi.spyOn(c.f.source, "fill");
    for (const intent of invalid) {
      await expect(act(c, 0, intent as SaskuActionIntent)).rejects.toBeInstanceOf(SaskuHandError);
      expect(c.game.snapshot).toBe(before);
      expect(c.game.pendingEnvelopes).toBe(0);
      expect(c.game.pendingBytes).toBe(0);
    }
    expect(getter).not.toHaveBeenCalled();
    expect(author).not.toHaveBeenCalled();
    expect(append).not.toHaveBeenCalled();
    expect(rng).not.toHaveBeenCalled();
    expect(c.game.failure).toBeNull();
    const plain = Object.create(null, { type: { value: "pass", enumerable: true } }) as SaskuActionIntent;
    await expect(act(c, 0, plain)).resolves.toMatchObject({ status: "accepted" });
  });

  it("requires the exact cached snapshot, not a clone, another receiver's equal view or an old local view", async () => {
    const c = await context();
    const before = c.game.snapshot;
    const other = new PersistentSaskuRoundReceiver(c.options);
    for (const deal of c.deals) await other.receive(deal);
    expect(other.snapshot).toEqual(before);
    expect(other.snapshot).not.toBe(before);
    const author = vi.spyOn(c.author, "author");
    for (const view of [{ ...before }, other.snapshot]) {
      await expect(act(c, 0, { type: "diamonds" }, view)).rejects.toMatchObject({ code: "stale_action" });
      expect(c.game.pendingBytes).toBe(0);
    }
    expect(author).not.toHaveBeenCalled();
    await act(c, 0, { type: "diamonds" });
    const current = c.game.snapshot;
    await expect(act(c, 0, { type: "play", position: 0 }, before)).rejects.toMatchObject({ code: "stale_action" });
    expect(author).toHaveBeenCalledOnce();
    expect(c.game.snapshot).toBe(current);
    expect(c.game.failure).toBeNull();
    await expect(act(c, 0, { type: "play", position: 0 })).resolves.toMatchObject({ status: "accepted" });
  });

  it("copies queued intents and receipt buffers, publishing only after both commits and isolating returned artifacts", async () => {
    const c = await context();
    await act(c, 0, { type: "diamonds" });
    const before = c.game.snapshot;
    const duplicateGate = deferred();
    const duplicateEntered = deferred();
    const receiptGate = deferred();
    const receiptEntered = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope")
      .mockImplementationOnce(async (argument) => { duplicateEntered.resolve(); await duplicateGate.promise; return persist(argument); })
      .mockImplementationOnce(async (argument) => { receiptEntered.resolve(); await receiptGate.promise; return persist(argument); });
    const duplicate = c.game.receive(c.deals[0]!);
    await duplicateEntered.promise;
    const receive = c.durable.receive.bind(c.durable);
    vi.spyOn(c.durable, "receive").mockImplementationOnce(async (argument) => {
      const receipt = await receive(argument);
      argument.canonicalBytes.fill(0xff);
      argument.hash.fill(0xee);
      (argument.envelope.body as Record<string, unknown>)["kind"] = "pass";
      return receipt;
    });
    const intent = { type: "play" as const, position: 0 };
    const published = vi.fn();
    const pending = act(c, 0, intent);
    void pending.then(published, () => undefined);
    intent.position = 1;
    expect(c.game.pendingBytes).toBe(MAX_ROUND_REVEAL_ENVELOPE_BYTES + c.deals[0]!.canonicalBytes.length);
    duplicateGate.resolve();
    await duplicate;
    await receiptEntered.promise;
    expect(c.store.head(c.f.gameId, c.author.sender)!.envelope.body).toMatchObject({ kind: "play", reveal: [0] });
    expect(c.game.snapshot).toBe(before);
    expect(c.game.readPrivateHand(c.author.sender, c.f.secrets[0]!)!.remaining[0]).toBe(c.f.cards[0]);
    expect(published).not.toHaveBeenCalled();
    receiptGate.resolve();
    const result = await pending;
    expect(result.status).toBe("accepted");
    expect(result.received.envelope.body).toMatchObject({ kind: "play", reveal: [0] });
    const original = decodeAndVerifyEnvelope(result.received.canonicalBytes);
    const committed = c.game.snapshot;
    result.received.canonicalBytes.fill(0xff);
    result.received.hash.fill(0xee);
    result.received.envelope.from.fill(0xdd);
    const body = result.received.envelope.body as CborMap;
    (body["reveal"] as number[])[0] = 1;
    ((body["shares"] as CborMap[])[0]!["S"] as Uint8Array).fill(0xcc);
    expect(c.store.head(c.f.gameId, c.author.sender)).toEqual(original);
    expect(c.store.artifacts().at(-1)).toEqual({ artifact: original, authored: true });
    expect(c.session.readRange(c.author.sender, original.envelope.seq, original.envelope.seq)).toEqual({ status: "complete", envelopes: [original] });
    await expect(c.game.receive(original)).resolves.toMatchObject({ status: "duplicate" });
    expect(c.game.snapshot).toBe(committed);
    expect(c.game.snapshot.ledger.revealed).toEqual({ 0: c.f.cards[0] });
    expect(c.game.failure).toBeNull();
    expect(c.game.pendingBytes).toBe(0);
  });

  it.each(["count", "bytes"] as const)("reserves 64 KiB and one slot per local operation against shared %s quotas, then releases them", async (limit) => {
    const size = MAX_ROUND_REVEAL_ENVELOPE_BYTES;
    expect(size).toBe(64 * 1024);
    const c = await context(limit === "count" ? { maxPendingEnvelopes: 2 } : { maxPendingBytes: size * 2 });
    const gate = deferred();
    const entered = deferred();
    const append = c.store.appendNext.bind(c.store);
    const writes = vi.spyOn(c.store, "appendNext").mockImplementationOnce(async (...args) => {
      entered.resolve(); await gate.promise; return append(...args);
    });
    const active = act(c, 0, { type: "diamonds" });
    const queued = expect(act(c, 0, { type: "play", position: 0 })).rejects.toMatchObject({ code: "stale_action" });
    await entered.promise;
    const getter = vi.fn(() => "pass");
    const invalid = Object.defineProperty({}, "type", { enumerable: true, get: getter }) as SaskuActionIntent;
    await expect(act(c, 0, invalid)).rejects.toMatchObject({ code: "queue_limit" });
    await expect(c.game.receive(c.deals[0]!)).rejects.toMatchObject({ code: "queue_limit" });
    expect(getter).not.toHaveBeenCalled();
    expect(c.game.pendingEnvelopes).toBe(2);
    expect(c.game.pendingBytes).toBe(size * 2);
    expect(writes).toHaveBeenCalledOnce();
    gate.resolve();
    await expect(active).resolves.toMatchObject({ status: "accepted" });
    await queued;
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
    await expect(act(c, 0, { type: "play", position: 0 })).resolves.toMatchObject({ status: "accepted" });
    expect(writes).toHaveBeenCalledTimes(2);
    expect(c.game.pendingBytes).toBe(0);
  });

  it("never retargets concurrent local requests from one view to a newly legal turn or phase", async () => {
    const c = await context();
    const view = c.game.snapshot;
    const author = vi.spyOn(c.author, "author");
    const rng = vi.spyOn(c.f.source, "fill");
    const results = await Promise.allSettled([
      act(c, 0, { type: "diamonds" }, view), act(c, 0, { type: "play", position: 0 }, view),
    ]);
    expect(results[0]).toMatchObject({ status: "fulfilled", value: { status: "accepted" } });
    expect(results[1]).toMatchObject({ status: "rejected", reason: { code: "stale_action" } });
    expect(author).toHaveBeenCalledOnce();
    expect(rng).not.toHaveBeenCalled();
    expect(c.game.snapshot.hand).toMatchObject({ phase: "playing", turn: 0 });
    expect(c.game.snapshot.ledger.revealed).toEqual({});
    expect(c.game.pendingBytes).toBe(0);
    expect(c.game.failure).toBeNull();
  });

  it("invalidates a queued local view after receiving a self-authored action ahead of it", async () => {
    const c = await context();
    const view = c.game.snapshot;
    const incoming = await c.author.author({
      round: c.f.round, phase: view.ledger.phase, type: "ACTION",
      body: encodeActionBody({ kind: "diamonds", data: {}, reveal: [], shares: [] }),
    });
    const gate = deferred();
    const entered = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (argument) => {
      entered.resolve(); await gate.promise; return persist(argument);
    });
    const author = vi.spyOn(c.author, "author");
    const received = c.game.receive(incoming);
    const queued = expect(act(c, 0, { type: "play", position: 0 }, view)).rejects.toMatchObject({ code: "stale_action" });
    await entered.promise;
    expect(c.game.snapshot).toBe(view);
    gate.resolve();
    await expect(received).resolves.toMatchObject({ status: "accepted" });
    await queued;
    expect(author).not.toHaveBeenCalled();
    expect(c.store.head(c.f.gameId, c.author.sender)).toEqual(incoming);
    expect(c.game.failure).toBeNull();
    await expect(act(c, 0, { type: "play", position: 0 })).resolves.toMatchObject({ status: "accepted" });
  });

  it("requires recovery before signing when the native authored head is ahead of the accepted prefix", async () => {
    const c = await context();
    const before = c.game.snapshot;
    const ahead = await c.author.author({ round: c.f.round, phase: before.ledger.phase, type: "WITNESS", body: { heads: [] } });
    const records = c.store.artifacts();
    const sign = vi.spyOn(protocol, "signEnvelope");
    const receive = vi.spyOn(c.durable, "receive");
    await expect(act(c, 0, { type: "diamonds" })).rejects.toMatchObject({ code: "recovery_required" });
    expect(sign).not.toHaveBeenCalled();
    expect(receive).not.toHaveBeenCalled();
    expect(c.store.head(c.f.gameId, c.author.sender)).toEqual(ahead);
    expect(c.store.artifacts()).toEqual(records);
    expect(c.game.snapshot).toBe(before);
    expect(c.game.pendingBytes).toBe(0);
    await expect(act(c, 0, { type: "pass" })).rejects.toBe(c.game.failure);
  });

  it("uses the latest matching housekeeping heads when they advance before the signing callback", async () => {
    const c = await context();
    const before = c.game.snapshot;
    const gate = deferred();
    const entered = deferred();
    const append = c.store.appendNext.bind(c.store);
    vi.spyOn(c.store, "appendNext").mockImplementationOnce(async (...args) => {
      entered.resolve(); await gate.promise; return append(...args);
    });
    const active = act(c, 0, { type: "diamonds" });
    await entered.promise;
    const housekeeping = new PersistentEnvelopeAuthor(c.f.gameId, c.f.identities[0]!.secretKey, c.store);
    const witness = await housekeeping.author({ round: c.f.round, phase: before.ledger.phase, type: "WITNESS", body: { heads: [] } });
    await expect(c.durable.receive(witness)).resolves.toMatchObject({ status: "accepted" });
    expect(c.game.snapshot).toBe(before);
    gate.resolve();
    const result = await active;
    expect(result).toMatchObject({ status: "accepted", received: { envelope: { seq: witness.envelope.seq + 1, prev: witness.hash } } });
    expect(c.store.head(c.f.gameId, c.author.sender)).toEqual(result.received);
    expect(c.session.classify(result.received).status).toBe("duplicate");
    expect(c.game.failure).toBeNull();
  });

  it("finishes an already signed active action when closed before the authored store writes it", async () => {
    const c = await context();
    const before = c.game.snapshot;
    const records = c.store.artifacts();
    const head = c.store.head(c.f.gameId, c.author.sender)!;
    const append = c.store.appendNext.bind(c.store);
    vi.spyOn(c.store, "appendNext").mockImplementationOnce((game, sender, create) => append(game, sender, (prior) => {
      const signed = create(prior);
      expect(decodeAndVerifyEnvelope(signed.canonicalBytes)).toEqual(signed);
      expect(c.store.head(game, sender)).toEqual(head);
      expect(c.store.artifacts()).toEqual(records);
      c.game.close();
      expect(c.game.snapshot).toBe(before);
      return signed;
    }));
    const active = act(c, 0, { type: "diamonds" });
    const queued = expect(act(c, 1, { type: "pass" })).rejects.toMatchObject({ code: "closed" });
    await expect(active).resolves.toMatchObject({ status: "accepted", persistenceStatus: "duplicate" });
    await queued;
    expect(c.game.closed).toBe(true);
    expect(c.game.failure).toBeNull();
    expect(c.game.snapshot.hand.phase).toBe("playing");
    expect(c.store.artifacts()).toHaveLength(records.length + 1);
    expect(c.store.head(c.f.gameId, c.author.sender)!.envelope.seq).toBe(head.envelope.seq + 1);
    expect(c.game.pendingBytes).toBe(0);
    expect(c.game.pendingEnvelopes).toBe(0);
  });

  it.each(["before guard", "after commit"] as const)("cancels queued work on close %s, but finishes a durably authored active action", async (boundary) => {
    const c = await context();
    const before = c.game.snapshot;
    const head = c.store.head(c.f.gameId, c.author.sender)!;
    const records = c.store.artifacts();
    const gate = deferred();
    const entered = deferred();
    const append = c.store.appendNext.bind(c.store);
    const writes = vi.spyOn(c.store, "appendNext").mockImplementationOnce(async (...args) => {
      if (boundary === "after commit") await append(...args);
      entered.resolve(); await gate.promise;
      if (boundary === "before guard") await append(...args);
    });
    const sign = vi.spyOn(protocol, "signEnvelope");
    const receive = vi.spyOn(c.durable, "receive");
    const published = vi.fn();
    const active = act(c, 0, { type: "diamonds" });
    void active.then(published, () => undefined);
    const queued = expect(act(c, 1, { type: "pass" })).rejects.toMatchObject({ code: "closed" });
    const remote = expect(c.game.receive(c.deals[0]!)).rejects.toMatchObject({ code: "closed" });
    await entered.promise;
    expect(published).not.toHaveBeenCalled();
    expect(receive).not.toHaveBeenCalled();
    c.game.close();
    await Promise.all([queued, remote]);
    expect(c.game.snapshot).toBe(before);
    expect(c.game.pendingEnvelopes).toBe(1);
    expect(c.game.pendingBytes).toBe(MAX_ROUND_REVEAL_ENVELOPE_BYTES);
    gate.resolve();
    if (boundary === "before guard") {
      await expect(active).rejects.toMatchObject({ code: "closed" });
      expect(sign).not.toHaveBeenCalled();
      expect(receive).not.toHaveBeenCalled();
      expect(published).not.toHaveBeenCalled();
      expect(c.store.head(c.f.gameId, c.author.sender)).toEqual(head);
      expect(c.store.artifacts()).toEqual(records);
      expect(c.game.snapshot).toBe(before);
    } else {
      await expect(active).resolves.toMatchObject({ status: "accepted", persistenceStatus: "duplicate" });
      expect(sign).toHaveBeenCalledOnce();
      expect(receive).toHaveBeenCalledOnce();
      expect(published).toHaveBeenCalledOnce();
      expect(c.game.snapshot.history).toEqual([{ type: "diamonds", seat: 0 }]);
      expect(c.store.head(c.f.gameId, c.author.sender)!.envelope.seq).toBe(head.envelope.seq + 1);
    }
    expect(writes).toHaveBeenCalledOnce();
    expect(c.game.closed).toBe(true);
    expect(c.game.failure).toBeNull();
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
    await expect(act(c, 0, { type: "play", position: 0 })).rejects.toMatchObject({ code: "closed" });
  });

  it("keeps a pre-guard generic store failure retryable and generates a fresh proof nonce on retry", async () => {
    const c = await context();
    await act(c, 0, { type: "diamonds" });
    const before = c.game.snapshot;
    const head = c.store.head(c.f.gameId, c.author.sender)!;
    const error = new Error("store open failed before create");
    vi.spyOn(c.store, "appendNext").mockRejectedValueOnce(error);
    const author = vi.spyOn(c.author, "author");
    const sign = vi.spyOn(protocol, "signEnvelope");
    const rng = vi.spyOn(c.f.source, "fill");
    await expect(act(c, 0, { type: "play", position: 0 })).rejects.toBe(error);
    expect(sign).not.toHaveBeenCalled();
    expect(rng).toHaveBeenCalledOnce();
    expect(c.store.head(c.f.gameId, c.author.sender)).toEqual(head);
    expect(c.game.snapshot).toBe(before);
    expect(c.game.failure).toBeNull();
    expect(c.game.pendingBytes).toBe(0);
    const retried = await act(c, 0, { type: "play", position: 0 }, before);
    expect(retried).toMatchObject({ status: "accepted", received: { envelope: { seq: head.envelope.seq + 1, prev: head.hash } } });
    expect(rng).toHaveBeenCalledTimes(2);
    expect(sign).toHaveBeenCalledOnce();
    const first = decodeActionBody(author.mock.calls[0]![0].body).shares[0]!;
    const second = decodeActionBody(author.mock.calls[1]![0].body).shares[0]!;
    expect(first.S.toBytes()).toEqual(second.S.toBytes());
    expect(first.proof.R1.toBytes()).not.toEqual(second.proof.R1.toBytes());
    expect(first.proof.R2.toBytes()).not.toEqual(second.proof.R2.toBytes());
    const proofContext = { gameId: c.f.gameId, round: c.f.round, phase: before.ledger.phase };
    for (const share of [first, second]) {
      expect(verifyProvenDecryptionShare(proofContext, 0, c.f.setup.publicKeyAt(0)!, c.f.deck[0]!.A, share)).toBe(true);
    }
  });

  it.each(["aborted", "committed"] as const)("treats a post-permission %s append error as terminal without publishing an artifact", async (outcome) => {
    const c = await context();
    const before = c.game.snapshot;
    const head = c.store.head(c.f.gameId, c.author.sender)!;
    const records = c.store.artifacts();
    const error = new Error(outcome === "aborted" ? "known transaction abort" : "uncertain committed append");
    if (outcome === "aborted") error.name = "AbortError";
    const append = c.store.appendNext.bind(c.store);
    const writes = vi.spyOn(c.store, "appendNext").mockImplementationOnce(async (game, sender, create) => {
      if (outcome === "committed") await append(game, sender, create);
      else create(c.store.head(game, sender));
      throw error;
    });
    const sign = vi.spyOn(protocol, "signEnvelope");
    const receive = vi.spyOn(c.durable, "receive");
    const published = vi.fn();
    const active = act(c, 0, { type: "diamonds" });
    void active.then(published, () => undefined);
    const failed = expect(active).rejects.toMatchObject({ code: "recovery_required", cause: error });
    const queued = expect(act(c, 0, { type: "play", position: 0 })).rejects.toMatchObject({ code: "recovery_required", cause: error });
    await Promise.all([failed, queued]);
    expect(sign).toHaveBeenCalledOnce();
    expect(receive).not.toHaveBeenCalled();
    expect(published).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
    if (outcome === "aborted") {
      expect(c.store.head(c.f.gameId, c.author.sender)).toEqual(head);
      expect(c.store.artifacts()).toEqual(records);
    } else {
      expect(c.store.head(c.f.gameId, c.author.sender)!.envelope.seq).toBe(head.envelope.seq + 1);
      expect(c.store.artifacts()).toHaveLength(records.length + 1);
    }
    await expect(act(c, 0, { type: "pass" })).rejects.toBe(c.game.failure);
    await expect(c.game.receive(c.deals[0]!)).rejects.toBe(c.game.failure);
    expect(writes).toHaveBeenCalledOnce();
  });

  it("treats AuthoredEnvelopeStoreError as terminal even before the signing guard ran", async () => {
    const c = await context();
    const before = c.game.snapshot;
    const records = c.store.artifacts();
    const error = new AuthoredEnvelopeStoreError("invalid native checkpoint");
    const append = vi.spyOn(c.store, "appendNext").mockRejectedValueOnce(error);
    const sign = vi.spyOn(protocol, "signEnvelope");
    await expect(act(c, 0, { type: "diamonds" })).rejects.toMatchObject({ code: "recovery_required", cause: error });
    expect(sign).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    expect(c.store.artifacts()).toEqual(records);
    expect(c.game.pendingBytes).toBe(0);
    await expect(act(c, 0, { type: "pass" })).rejects.toBe(c.game.failure);
    expect(append).toHaveBeenCalledOnce();
  });

  it("stops queued signing when a store masks a callback invariant failure with a generic rejection", async () => {
    const c = await context();
    const before = c.game.snapshot;
    const records = c.store.artifacts();
    const head = c.store.head(c.f.gameId, c.author.sender)!;
    const masked = new Error("generic transaction abort");
    const append = vi.spyOn(c.store, "appendNext").mockImplementationOnce(async (_game, _sender, create) => {
      try { create({ ...head, canonicalBytes: new Uint8Array([0xff]) } as EnvelopeArtifact); }
      catch { throw masked; }
      throw new Error("Invalid head was unexpectedly accepted");
    });
    const sign = vi.spyOn(protocol, "signEnvelope");
    const receive = vi.spyOn(c.durable, "receive");
    const active = expect(act(c, 0, { type: "diamonds" })).rejects.toMatchObject({ code: "recovery_required" });
    const queued = expect(act(c, 0, { type: "diamonds" })).rejects.toMatchObject({ code: "recovery_required" });
    await Promise.all([active, queued]);
    expect(c.game.failure?.cause).toBeInstanceOf(AuthoredEnvelopeStoreError);
    expect(c.game.failure?.cause).not.toBe(masked);
    expect(sign).not.toHaveBeenCalled();
    expect(receive).not.toHaveBeenCalled();
    expect(append).toHaveBeenCalledOnce();
    expect(c.game.snapshot).toBe(before);
    expect(c.store.artifacts()).toEqual(records);
    expect(c.game.pendingBytes).toBe(0);
    expect(c.game.pendingEnvelopes).toBe(0);
    await expect(act(c, 0, { type: "pass" })).rejects.toBe(c.game.failure);
  });

  it("requires recovery when internal receipt rejects a durably authored action for a chain gap", async () => {
    const c = await context();
    const before = c.game.snapshot;
    const heads = c.session.heads();
    const append = vi.spyOn(c.store, "appendNext");
    const receive = vi.spyOn(c.durable, "receive").mockImplementationOnce(async (received) => ({
      status: "rejected", reason: "gap", received, expectedSeq: received.envelope.seq - 1, actualSeq: received.envelope.seq,
    }));
    const published = vi.fn();
    const active = act(c, 0, { type: "diamonds" });
    void active.then(published, () => undefined);
    await expect(active).rejects.toMatchObject({ code: "recovery_required" });
    expect(published).not.toHaveBeenCalled();
    expect(c.store.head(c.f.gameId, c.author.sender)!.envelope.body).toMatchObject({ kind: "diamonds" });
    expect(c.session.heads()).toEqual(heads);
    expect(c.game.snapshot).toBe(before);
    expect(c.game.pendingBytes).toBe(0);
    await expect(act(c, 0, { type: "pass" })).rejects.toBe(c.game.failure);
    expect(append).toHaveBeenCalledOnce();
    expect(receive).toHaveBeenCalledOnce();
  });

  it("rejects a substituted, validly signed returned body as invalid_receipt before local receipt", async () => {
    const c = await context();
    const before = c.game.snapshot;
    const native = c.author.author.bind(c.author);
    vi.spyOn(c.author, "author").mockImplementationOnce(async (content, guard) => {
      const committed = await native(content, guard);
      const substituted = protocol.signEnvelope({
        ...committed.envelope, body: encodeActionBody({ kind: "pass", data: {}, reveal: [], shares: [] }),
      }, c.f.identities[0]!.secretKey);
      expect(decodeAndVerifyEnvelope(substituted.canonicalBytes)).toEqual(substituted);
      return substituted;
    });
    const receive = vi.spyOn(c.durable, "receive");
    await expect(act(c, 0, { type: "diamonds" })).rejects.toMatchObject({ code: "invalid_receipt" });
    expect(receive).not.toHaveBeenCalled();
    expect(c.store.head(c.f.gameId, c.author.sender)!.envelope.body).toMatchObject({ kind: "diamonds" });
    expect(c.game.snapshot).toBe(before);
    expect(c.game.pendingBytes).toBe(0);
    await expect(act(c, 0, { type: "pass" })).rejects.toBe(c.game.failure);
  });

  it.each(["before", "after"] as const)("isolates private intended bytes from dependency body mutation %s the native author's snapshot", async (timing) => {
    const c = await context();
    await act(c, 0, { type: "diamonds" });
    const before = c.game.snapshot;
    const native = c.author.author.bind(c.author);
    vi.spyOn(c.author, "author").mockImplementationOnce((content, guard) => {
      const proofBytes = ((content.body as CborMap)["shares"] as CborMap[])[0]!["R1"] as Uint8Array;
      if (timing === "before") proofBytes.fill(0xff);
      const pending = native(content, guard);
      if (timing === "after") proofBytes.fill(0xff);
      return pending;
    });
    const receive = vi.spyOn(c.durable, "receive");
    const pending = act(c, 0, { type: "play", position: 0 });
    if (timing === "before") {
      await expect(pending).rejects.toMatchObject({ code: "invalid_receipt" });
      expect(receive).not.toHaveBeenCalled();
      expect(c.game.snapshot).toBe(before);
      expect(c.store.head(c.f.gameId, c.author.sender)!.envelope.body).toMatchObject({ shares: [{ R1: new Uint8Array(32).fill(0xff) }] });
      await expect(act(c, 0, { type: "play", position: 0 })).rejects.toBe(c.game.failure);
    } else {
      const result = await pending;
      expect(result.status).toBe("accepted");
      const body = decodeActionBody(result.received.envelope.body);
      expect(body.reveal).toEqual([0]);
      expect(verifyProvenDecryptionShare(
        { gameId: c.f.gameId, round: c.f.round, phase: before.ledger.phase }, 0, c.f.setup.publicKeyAt(0)!, c.f.deck[0]!.A, body.shares[0]!,
      )).toBe(true);
      expect(c.game.snapshot.ledger.revealed).toEqual({ 0: c.f.cards[0] });
      expect(c.game.failure).toBeNull();
      expect(receive).toHaveBeenCalledOnce();
    }
    expect(c.game.pendingBytes).toBe(0);
  });

  it("refuses even matching authored bytes when the dependency skipped the native beforeSign guard", async () => {
    const c = await context();
    const before = c.game.snapshot;
    const native = c.author.author.bind(c.author);
    vi.spyOn(c.author, "author").mockImplementationOnce((content, guard) => {
      expect(guard).toBeTypeOf("function");
      return native(content);
    });
    const receive = vi.spyOn(c.durable, "receive");
    await expect(act(c, 0, { type: "diamonds" })).rejects.toMatchObject({ code: "invalid_receipt" });
    expect(receive).not.toHaveBeenCalled();
    expect(c.store.head(c.f.gameId, c.author.sender)!.envelope.body).toMatchObject({ kind: "diamonds" });
    expect(c.game.snapshot).toBe(before);
    expect(c.game.pendingBytes).toBe(0);
    await expect(act(c, 0, { type: "pass" })).rejects.toBe(c.game.failure);
  });

  it.each(["closed", "recovery_required"] as const)("stops nonce rejection sampling immediately after a reentrant %s condition", async (code) => {
    const c = await context({}, code === "recovery_required" ? 9 : undefined);
    await act(c, 0, { type: "diamonds" });
    const before = c.game.snapshot;
    const records = c.store.artifacts();
    const author = vi.spyOn(c.author, "author");
    const source = { fill: vi.fn((bytes: Uint8Array) => {
      if (source.fill.mock.calls.length > 1) { throw new Error("Sampler retried after the receiver stopped"); }
      if (code === "closed") c.game.close();
      else expect(() => c.game.readPrivateHand(c.authors[1]!.sender, c.f.secrets[1]!))
        .toThrow(expect.objectContaining({ code: "recovery_required" }));
      bytes.fill(0);
    }) };
    await expect(c.game.authorAction(c.author, c.f.secrets[0]!, before, { type: "play", position: 0 }, source))
      .rejects.toMatchObject({ code });
    expect(source.fill).toHaveBeenCalledOnce();
    expect(author).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    expect(c.store.artifacts()).toEqual(records);
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
  });

  it("never publishes an active local play after a private read discovers corruption during internal persistence", async () => {
    const c = await context({}, 9);
    await act(c, 0, { type: "diamonds" });
    const before = c.game.snapshot;
    const gate = deferred();
    const entered = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    const writes = vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (argument) => {
      entered.resolve(); await gate.promise; return persist(argument);
    });
    const published = vi.fn();
    const active = act(c, 0, { type: "play", position: 0 });
    void active.then(published, () => undefined);
    const failed = expect(active).rejects.toMatchObject({ code: "recovery_required", cause: { code: "inconsistent_deck" } });
    const queued = expect(act(c, 1, { type: "play", position: 9 })).rejects.toMatchObject({ code: "recovery_required" });
    await entered.promise;
    const authored = c.store.head(c.f.gameId, c.author.sender)!;
    expect(authored.envelope.body).toMatchObject({ kind: "play", reveal: [0] });
    expect(() => c.game.readPrivateHand(c.authors[1]!.sender, c.f.secrets[1]!))
      .toThrow(expect.objectContaining({ code: "recovery_required" }));
    await queued;
    expect(c.game.pendingEnvelopes).toBe(1);
    expect(c.game.snapshot).toBe(before);
    gate.resolve();
    await failed;
    expect(published).not.toHaveBeenCalled();
    expect(writes).toHaveBeenCalledOnce();
    expect(c.session.classify(authored).status).toBe("duplicate");
    expect(c.game.snapshot).toBe(before);
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
    await expect(act(c, 0, { type: "play", position: 1 })).rejects.toBe(c.game.failure);
  });
});
