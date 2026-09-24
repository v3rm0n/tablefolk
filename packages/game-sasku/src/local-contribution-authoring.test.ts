import type { RandomSource } from "@p2pcards/crypto";
import * as deck from "@p2pcards/deck";
import { decodeAuditDiscloseBody, decodeSharesBody, encodeActionBody, encodeAuditDiscloseBody, encodeSharesBody, verifyProvenDecryptionShare } from "@p2pcards/deck";
import type { CborMap } from "@p2pcards/encoding";
import { MAX_ROUND_REVEAL_ENVELOPE_BYTES, RoundRevealError, RoundRevealLedger } from "@p2pcards/engine";
import * as protocol from "@p2pcards/protocol";
import { decodeAndVerifyEnvelope, parseGameId } from "@p2pcards/protocol";
import { legalSaskuCards, saskuBidStrength, type SaskuSeat } from "@p2pcards/rules-sasku";
import { PersistentEnvelopeAuthor } from "@p2pcards/session";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as protocolRandom from "../../crypto/src/random";
import { act, context, deferred } from "./local-authoring.test-fixture";
import { PersistentSaskuRoundReceiver, type SaskuRoundSnapshot } from "./persistent-round-receiver";

type Context = Awaited<ReturnType<typeof context>>;

describe("local Sasku deal contribution authoring", () => {
  afterEach(() => vi.restoreAllMocks());

  it("queues all three donors from one snapshot, derives the exact batch and isolates returned proof buffers", async () => {
    const c = await context({}, undefined, false);
    const before = c.game.snapshot;
    const donors = [1, 2, 3] as const;
    const heads = donors.map((seat) => c.store.head(c.f.gameId, c.authors[seat]!.sender)!);
    for (const seat of donors) expect(c.game.readPrivateHand(c.authors[seat]!.sender, c.f.secrets[seat]!)).toBeNull();
    const rng = vi.spyOn(c.f.source, "fill");
    const pending = donors.map((seat) => shares(c, seat, before));
    expect(c.game.snapshot).toBe(before);
    expect(c.game.pendingEnvelopes).toBe(3);
    expect(c.game.pendingBytes).toBe(3 * MAX_ROUND_REVEAL_ENVELOPE_BYTES);
    const results = await Promise.all(pending);
    for (const [index, result] of results.entries()) {
      const seat = donors[index]!;
      expect(result).toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "duplicate" });
      expect(result.received.envelope).toMatchObject({
        game: c.f.gameId, from: c.authors[seat]!.sender, seq: heads[index]!.envelope.seq + 1, prev: heads[index]!.hash,
        round: c.f.round, phase: before.ledger.phase, type: "SHARES",
      });
      const body = decodeSharesBody(result.received.envelope.body);
      expect(body.to).toBe(0);
      expect(body.items.map(({ pos }) => pos)).toEqual(c.f.plans[0]!.positions);
      expect(result.received.envelope.body).toEqual(encodeSharesBody({ to: 0, items: body.items }));
      const proofContext = { gameId: c.f.gameId, round: c.f.round, phase: before.ledger.phase };
      for (const item of body.items) {
        expect(item.S.toBytes()).toEqual(c.f.deck[item.pos]!.A.multiply(c.f.secrets[seat]!).toBytes());
        expect(verifyProvenDecryptionShare(proofContext, item.pos, c.f.setup.publicKeyAt(seat)!, c.f.deck[item.pos]!.A, item)).toBe(true);
      }
      const first = body.items[0]!;
      expect(verifyProvenDecryptionShare({ ...proofContext, phase: c.game.snapshot.ledger.phase }, 0, c.f.setup.publicKeyAt(seat)!, c.f.deck[0]!.A, first)).toBe(false);
      expect(verifyProvenDecryptionShare(proofContext, 1, c.f.setup.publicKeyAt(seat)!, c.f.deck[0]!.A, first)).toBe(false);
      expect(c.store.head(c.f.gameId, c.authors[seat]!.sender)).toEqual(result.received);
      expect(c.session.classify(result.received).status).toBe("duplicate");
    }
    expect(rng).toHaveBeenCalledTimes(27);
    expect(c.game.snapshot.ledger.deal).toEqual({ ...c.f.plans[1], pendingSenders: [0, 2, 3] });
    expect(c.game.snapshot.history).toEqual([]);
    expect(c.game.snapshot.ledger.revealed).toEqual({});
    const returned = results[0]!.received;
    const original = decodeAndVerifyEnvelope(returned.canonicalBytes);
    const committed = c.game.snapshot;
    returned.canonicalBytes.fill(0xff);
    returned.hash.fill(0xee);
    returned.envelope.from.fill(0xdd);
    const body = returned.envelope.body as Record<string, unknown>;
    body["to"] = 3;
    const item = (body["items"] as Record<string, unknown>[])[0]!;
    item["pos"] = 35;
    for (const key of ["S", "R1", "R2", "z"]) (item[key] as Uint8Array).fill(0xcc);
    expect(c.store.head(c.f.gameId, c.authors[1]!.sender)).toEqual(original);
    expect(c.store.artifacts()).toContainEqual({ artifact: original, authored: true });
    expect(c.session.readRange(c.authors[1]!.sender, original.envelope.seq, original.envelope.seq)).toEqual({ status: "complete", envelopes: [original] });
    await expect(c.game.receive(original)).resolves.toMatchObject({ status: "duplicate", chainStatus: "duplicate", persistenceStatus: "duplicate" });
    expect(c.game.snapshot).toBe(committed);
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
    expect(c.game.failure).toBeNull();
  });

  it("rejects the recipient, wrong local keys and unbound authors before proofs or signing while private hands are null", async () => {
    const c = await context({}, undefined, false);
    const before = c.game.snapshot;
    expect(c.game.readPrivateHand(c.authors[1]!.sender, c.f.secrets[1]!)).toBeNull();
    const author = vi.spyOn(PersistentEnvelopeAuthor.prototype, "author");
    const prove = vi.spyOn(deck, "createProvenDecryptionShare");
    const rng = vi.spyOn(c.f.source, "fill");
    const sign = vi.spyOn(protocol, "signEnvelope");
    const append = vi.spyOn(c.store, "appendNext");
    await expect(shares(c, 0)).rejects.toMatchObject({ code: "unexpected_sender" });
    for (const key of [c.f.secrets[2], 0n, -1n, 1, null]) {
      await expect(c.game.authorDealShares(c.authors[1]!, key as never, before, c.f.source)).rejects.toMatchObject({ code: "invalid_local_key" });
      expect(c.game.pendingBytes).toBe(0);
    }
    const wrongGame = new PersistentEnvelopeAuthor(parseGameId(new Uint8Array(16).fill(7)), c.f.identities[1]!.secretKey, c.store);
    const stranger = new PersistentEnvelopeAuthor(c.f.gameId, c.f.identities[4]!.secretKey, c.store);
    for (const [candidate, code] of [[wrongGame, "wrong_game"], [stranger, "unknown_sender"]] as const) {
      await expect(c.game.authorDealShares(candidate, c.f.secrets[1]!, before, c.f.source)).rejects.toMatchObject({ code });
      await expect(c.game.authorAuditDisclose(candidate, before)).rejects.toMatchObject({ code });
    }
    const fake = { gameId: c.f.gameId, sender: c.authors[1]!.sender, author: vi.fn() };
    await expect(c.game.authorDealShares(fake as unknown as PersistentEnvelopeAuthor, c.f.secrets[1]!, before, c.f.source)).rejects.toBeInstanceOf(TypeError);
    await expect(c.game.authorAuditDisclose(fake as unknown as PersistentEnvelopeAuthor, before)).rejects.toBeInstanceOf(TypeError);
    await expect(c.game.authorAuditDisclose(c.author, before)).rejects.toMatchObject({ code: "wrong_phase" });
    for (const spy of [author, prove, rng, sign, append, fake.author]) expect(spy).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    expect(c.game.failure).toBeNull();
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
    await expect(shares(c, 1)).resolves.toMatchObject({ status: "accepted" });
  });

  it("requires an active deal for shares and a completed public hand for audit, even after private dealing is complete", async () => {
    const c = await context();
    const author = vi.spyOn(PersistentEnvelopeAuthor.prototype, "author");
    const prove = vi.spyOn(deck, "createProvenDecryptionShare");
    const rng = vi.spyOn(c.f.source, "fill");
    const sign = vi.spyOn(protocol, "signEnvelope");
    for (const phase of ["bidding", "playing"]) {
      if (phase === "playing") await act(c, 0, { type: "diamonds" });
      author.mockClear(); sign.mockClear();
      const before = c.game.snapshot;
      expect(before.hand.phase).toBe(phase);
      expect(before.ledger.deal).toBeNull();
      expect(before.audit).toBeNull();
      await expect(shares(c, 1)).rejects.toMatchObject({ code: "wrong_phase" });
      await expect(c.game.authorAuditDisclose(c.author, before)).rejects.toMatchObject({ code: "wrong_phase" });
      for (const spy of [author, prove, rng, sign]) expect(spy).not.toHaveBeenCalled();
      expect(c.game.snapshot).toBe(before);
      expect(c.game.failure).toBeNull();
      expect(c.game.pendingEnvelopes).toBe(0);
      expect(c.game.pendingBytes).toBe(0);
    }
  });

  it("requires the exact current snapshot at admission and refuses repeated authorship even within the same phase", async () => {
    const c = await context({}, undefined, false);
    const before = c.game.snapshot;
    const other = new PersistentSaskuRoundReceiver(c.options);
    expect(other.snapshot).toEqual(before);
    expect(other.snapshot).not.toBe(before);
    const author = vi.spyOn(PersistentEnvelopeAuthor.prototype, "author");
    const rng = vi.spyOn(c.f.source, "fill");
    for (const view of [{ ...before }, other.snapshot]) {
      await expect(shares(c, 1, view)).rejects.toMatchObject({ code: "stale_contribution" });
      await expect(c.game.authorAuditDisclose(c.author, view)).rejects.toMatchObject({ code: "stale_contribution" });
      expect(c.game.pendingBytes).toBe(0);
    }
    expect(author).not.toHaveBeenCalled();
    expect(rng).not.toHaveBeenCalled();
    const original = await shares(c, 1, before);
    const current = c.game.snapshot;
    expect(current.ledger.phase).toBe(before.ledger.phase);
    await expect(shares(c, 2, before)).rejects.toMatchObject({ code: "stale_contribution" });
    await expect(shares(c, 1, current)).rejects.toMatchObject({ code: "conflicting_contribution" });
    await expect(c.game.receive(original.received)).resolves.toMatchObject({ status: "duplicate" });
    expect(author).toHaveBeenCalledOnce();
    expect(rng).toHaveBeenCalledTimes(9);
    expect(c.game.snapshot).toBe(current);
    expect(c.game.failure).toBeNull();
    expect(c.game.pendingBytes).toBe(0);
    await expect(shares(c, 2)).resolves.toMatchObject({ status: "accepted" });
  });

  it("allows a remote contribution to commit durably ahead of a queued donor and its native presign guard", async () => {
    const c = await context({}, undefined, false);
    const incoming = await nativeDeal(c, 0, 2);
    const before = c.game.snapshot;
    const gate = deferred();
    const entered = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (argument) => {
      entered.resolve(); await gate.promise; return persist(argument);
    });
    const native = c.authors[1]!.author.bind(c.authors[1]!);
    const guard = vi.fn();
    const author = vi.spyOn(c.authors[1]!, "author").mockImplementation((content, beforeSign) => native(content, (head) => {
      expect(c.game.snapshot).not.toBe(before);
      expect(c.game.snapshot.ledger.deal?.pendingSenders).toEqual([1, 3]);
      expect(c.session.classify(incoming).status).toBe("duplicate");
      guard();
      return beforeSign!(head);
    }));
    const rng = vi.spyOn(c.f.source, "fill");
    const received = c.game.receive(incoming);
    await entered.promise;
    const local = shares(c, 1, before);
    expect(author).not.toHaveBeenCalled();
    expect(rng).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    gate.resolve();
    await expect(received).resolves.toMatchObject({ status: "accepted" });
    await expect(local).resolves.toMatchObject({ status: "accepted", received: { envelope: { phase: before.ledger.phase } } });
    expect(guard).toHaveBeenCalledOnce();
    expect(rng).toHaveBeenCalledTimes(9);
    expect(c.game.snapshot.ledger.deal?.pendingSenders).toEqual([3]);
    expect(c.game.pendingBytes).toBe(0);
    expect(c.game.failure).toBeNull();
  });

  it.each(["same phase", "step advanced"] as const)("does not regenerate an original self contribution received ahead of local work: %s", async (boundary) => {
    const c = await context({}, undefined, false);
    if (boundary === "step advanced") {
      await shares(c, 2); await shares(c, 3);
    }
    const original = await nativeDeal(c, 0, 1);
    const before = c.game.snapshot;
    const gate = deferred();
    const entered = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (argument) => {
      entered.resolve(); await gate.promise; return persist(argument);
    });
    const author = vi.spyOn(c.authors[1]!, "author");
    const prove = vi.spyOn(deck, "createProvenDecryptionShare");
    const rng = vi.spyOn(c.f.source, "fill");
    const sign = vi.spyOn(protocol, "signEnvelope");
    const received = c.game.receive(original);
    await entered.promise;
    const code = boundary === "same phase" ? "conflicting_contribution" : "stale_contribution";
    const queued = expect(shares(c, 1, before)).rejects.toMatchObject({ code });
    expect(c.game.snapshot).toBe(before);
    gate.resolve();
    await expect(received).resolves.toMatchObject({ status: "accepted" });
    await queued;
    for (const spy of [author, prove, rng, sign]) expect(spy).not.toHaveBeenCalled();
    expect(c.game.snapshot.ledger.dealIndex).toBe(boundary === "same phase" ? 0 : 1);
    expect(c.store.head(c.f.gameId, c.authors[1]!.sender)).toEqual(original);
    const current = c.game.snapshot;
    await expect(c.game.receive(original)).resolves.toMatchObject({ status: "duplicate" });
    expect(c.game.snapshot).toBe(current);
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
    expect(c.game.failure).toBeNull();
  });

  it.each(["count", "bytes"] as const)("shares the 64 KiB authoring reservation with audit, actions and receipt under the %s quota", async (limit) => {
    const size = MAX_ROUND_REVEAL_ENVELOPE_BYTES;
    expect(size).toBe(64 * 1024);
    const c = await context(limit === "count" ? { maxPendingEnvelopes: 3 } : { maxPendingBytes: size * 3 }, undefined, false);
    const incoming = await nativeDeal(c, 0, 3);
    const before = c.game.snapshot;
    const gate = deferred();
    const entered = deferred();
    const append = c.store.appendNext.bind(c.store);
    const writes = vi.spyOn(c.store, "appendNext").mockImplementationOnce(async (...args) => {
      entered.resolve(); await gate.promise; return append(...args);
    });
    const rng = vi.spyOn(c.f.source, "fill");
    const active = shares(c, 1, before);
    const audit = expect(c.game.authorAuditDisclose(c.author, before)).rejects.toMatchObject({ code: "wrong_phase" });
    const action = expect(act(c, 0, { type: "diamonds" }, before)).rejects.toMatchObject({ code: "stale_action" });
    await entered.promise;
    await expect(c.game.authorDealShares(c.authors[2]!, null as never, before, c.f.source)).rejects.toMatchObject({ code: "queue_limit" });
    await expect(c.game.authorAuditDisclose(c.author, before)).rejects.toMatchObject({ code: "queue_limit" });
    await expect(c.game.receive(incoming)).rejects.toMatchObject({ code: "queue_limit" });
    expect(c.game.pendingEnvelopes).toBe(3);
    expect(c.game.pendingBytes).toBe(size * 3);
    expect(writes).toHaveBeenCalledOnce();
    expect(rng).toHaveBeenCalledTimes(9);
    gate.resolve();
    await expect(active).resolves.toMatchObject({ status: "accepted" });
    await Promise.all([audit, action]);
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
    await expect(c.game.receive(incoming)).resolves.toMatchObject({ status: "accepted" });
    await expect(shares(c, 2)).resolves.toMatchObject({ status: "accepted" });
    expect(writes).toHaveBeenCalledTimes(2);
    expect(c.game.snapshot.ledger.dealIndex).toBe(1);
    expect(c.game.pendingBytes).toBe(0);
    expect(c.game.failure).toBeNull();
  });

  it("retries pre-permission author failure with fresh proofs for every position without consuming the contribution", async () => {
    const c = await context({}, undefined, false);
    const before = c.game.snapshot;
    const head = c.store.head(c.f.gameId, c.authors[1]!.sender);
    const error = new Error("store unavailable before signing permission");
    vi.spyOn(c.store, "appendNext").mockRejectedValueOnce(error);
    const author = vi.spyOn(c.authors[1]!, "author");
    const sign = vi.spyOn(protocol, "signEnvelope");
    const rng = vi.spyOn(c.f.source, "fill");
    await expect(shares(c, 1, before)).rejects.toBe(error);
    expect(sign).not.toHaveBeenCalled();
    expect(rng).toHaveBeenCalledTimes(9);
    expect(c.store.head(c.f.gameId, c.authors[1]!.sender)).toEqual(head);
    expect(c.game.snapshot).toBe(before);
    expect(c.game.failure).toBeNull();
    expect(c.game.pendingBytes).toBe(0);
    await expect(shares(c, 1, before)).resolves.toMatchObject({ status: "accepted" });
    expect(sign).toHaveBeenCalledOnce();
    expect(rng).toHaveBeenCalledTimes(18);
    const first = decodeSharesBody(author.mock.calls[0]![0].body);
    const second = decodeSharesBody(author.mock.calls[1]![0].body);
    for (const [index, item] of first.items.entries()) {
      const retried = second.items[index]!;
      expect(retried.pos).toBe(item.pos);
      expect(retried.S.toBytes()).toEqual(item.S.toBytes());
      expect(retried.proof.R1.toBytes()).not.toEqual(item.proof.R1.toBytes());
      expect(retried.proof.R2.toBytes()).not.toEqual(item.proof.R2.toBytes());
      for (const proof of [item, retried]) expect(verifyProvenDecryptionShare(
        { gameId: c.f.gameId, round: c.f.round, phase: before.ledger.phase }, item.pos, c.f.setup.publicKeyAt(1)!, c.f.deck[item.pos]!.A, proof,
      )).toBe(true);
    }
  });

  it("keeps first-draw and mid-batch source failures nonterminal without handing a partial body to the author", async () => {
    const c = await context({}, undefined, false);
    const before = c.game.snapshot;
    const records = c.store.artifacts();
    const author = vi.spyOn(c.authors[1]!, "author");
    const sign = vi.spyOn(protocol, "signEnvelope");
    const append = vi.spyOn(c.store, "appendNext");
    for (const stopAt of [1, 4]) {
      const error = new Error(`source failed on draw ${stopAt}`);
      const fill = vi.fn((bytes: Uint8Array) => {
        if (fill.mock.calls.length === stopAt) throw error;
        c.f.source.fill(bytes);
      });
      await expect(shares(c, 1, before, { fill })).rejects.toBe(error);
      expect(fill).toHaveBeenCalledTimes(stopAt);
      for (const spy of [author, sign, append]) expect(spy).not.toHaveBeenCalled();
      expect(c.game.snapshot).toBe(before);
      expect(c.store.artifacts()).toEqual(records);
      expect(c.game.failure).toBeNull();
      expect(c.game.pendingEnvelopes).toBe(0);
      expect(c.game.pendingBytes).toBe(0);
    }
    await expect(shares(c, 1, before)).resolves.toMatchObject({ status: "accepted" });
    expect(decodeSharesBody(author.mock.calls[0]![0].body).items.map(({ pos }) => pos)).toEqual(c.f.plans[0]!.positions);
    expect(author).toHaveBeenCalledOnce();
    expect(sign).toHaveBeenCalledOnce();
  });

  it.each(["close with nonzero", "close with rejected zero", "failure with rejected zero"] as const)("stops a reentrant RNG callback after its first draw: %s", async (mode) => {
    const c = await context({}, undefined, false);
    const before = c.game.snapshot;
    const records = c.store.artifacts();
    const author = vi.spyOn(PersistentEnvelopeAuthor.prototype, "author");
    const sign = vi.spyOn(protocol, "signEnvelope");
    const append = vi.spyOn(c.store, "appendNext");
    const code = mode.startsWith("failure") ? "recovery_required" : "closed";
    if (code === "recovery_required") {
      // Inject a ledger inconsistency so a reentrant private read latches a real receiver failure.
      vi.spyOn(RoundRevealLedger.prototype, "readPrivateHand").mockImplementationOnce(() => { throw new RoundRevealError("inconsistent_deck"); });
    }
    let cancelled: Promise<void> | undefined;
    const fill = vi.fn((bytes: Uint8Array) => {
      if (fill.mock.calls.length > 1) throw new Error("Guard allowed another nonce draw");
      cancelled = expect(c.game.authorAuditDisclose(c.author, before)).rejects.toMatchObject({ code });
      if (code === "closed") c.game.close();
      else expect(() => c.game.readPrivateHand(c.authors[1]!.sender, c.f.secrets[1]!)).toThrow(expect.objectContaining({ code }));
      if (mode === "close with nonzero") c.f.source.fill(bytes);
      else bytes.fill(0);
    });
    await expect(shares(c, 1, before, { fill })).rejects.toMatchObject({ code });
    await cancelled;
    expect(fill).toHaveBeenCalledOnce();
    for (const spy of [author, sign, append]) expect(spy).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    expect(c.store.artifacts()).toEqual(records);
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
    if (code === "closed") expect(c.game.failure).toBeNull();
    else expect(c.game.failure).toMatchObject({ code, cause: { code: "inconsistent_deck" } });
    await expect(shares(c, 1)).rejects.toMatchObject({ code });
  });

  it.each(["before guard", "after commit"] as const)("honors close around a delayed native contribution author: %s", async (boundary) => {
    const c = await context({}, undefined, false);
    const before = c.game.snapshot;
    const head = c.store.head(c.f.gameId, c.authors[1]!.sender)!;
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
    const active = shares(c, 1, before);
    void active.then(published, () => undefined);
    const queued = expect(shares(c, 2, before)).rejects.toMatchObject({ code: "closed" });
    await entered.promise;
    expect(published).not.toHaveBeenCalled();
    expect(receive).not.toHaveBeenCalled();
    c.game.close();
    await queued;
    expect(c.game.snapshot).toBe(before);
    expect(c.game.pendingEnvelopes).toBe(1);
    expect(c.game.pendingBytes).toBe(MAX_ROUND_REVEAL_ENVELOPE_BYTES);
    gate.resolve();
    if (boundary === "before guard") {
      await expect(active).rejects.toMatchObject({ code: "closed" });
      for (const spy of [sign, receive, published]) expect(spy).not.toHaveBeenCalled();
      expect(c.store.head(c.f.gameId, c.authors[1]!.sender)).toEqual(head);
      expect(c.store.artifacts()).toEqual(records);
      expect(c.game.snapshot).toBe(before);
    } else {
      await expect(active).resolves.toMatchObject({ status: "accepted", persistenceStatus: "duplicate" });
      for (const spy of [sign, receive, published]) expect(spy).toHaveBeenCalledOnce();
      expect(c.game.snapshot.ledger.deal?.pendingSenders).toEqual([2, 3]);
      expect(c.store.head(c.f.gameId, c.authors[1]!.sender)!.envelope.seq).toBe(head.envelope.seq + 1);
    }
    expect(writes).toHaveBeenCalledOnce();
    expect(c.game.closed).toBe(true);
    expect(c.game.failure).toBeNull();
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
  });

  it.each(["post-permission author", "after-commit receipt"] as const)("makes a %s failure terminal without publishing or signing queued contributions", async (boundary) => {
    const c = await context({}, undefined, false);
    const before = c.game.snapshot;
    const head = c.store.head(c.f.gameId, c.authors[1]!.sender)!;
    const records = c.store.artifacts();
    const error = new Error(boundary);
    if (boundary === "post-permission author") {
      vi.spyOn(c.store, "appendNext").mockImplementationOnce(async (game, sender, create) => {
        create(c.store.head(game, sender));
        throw error;
      });
    } else vi.spyOn(c.store, "persistAcceptedEnvelope").mockRejectedValueOnce(error);
    const sign = vi.spyOn(protocol, "signEnvelope");
    const receive = vi.spyOn(c.durable, "receive");
    const rng = vi.spyOn(c.f.source, "fill");
    const published = vi.fn();
    const active = shares(c, 1, before);
    void active.then(published, () => undefined);
    const failed = expect(active).rejects.toMatchObject({ code: "recovery_required", cause: error });
    const queued = expect(shares(c, 2, before)).rejects.toMatchObject({ code: "recovery_required", cause: error });
    await Promise.all([failed, queued]);
    expect(sign).toHaveBeenCalledOnce();
    expect(rng).toHaveBeenCalledTimes(9);
    expect(published).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
    if (boundary === "post-permission author") {
      expect(receive).not.toHaveBeenCalled();
      expect(c.store.head(c.f.gameId, c.authors[1]!.sender)).toEqual(head);
      expect(c.store.artifacts()).toEqual(records);
    } else {
      expect(receive).toHaveBeenCalledOnce();
      expect(c.store.head(c.f.gameId, c.authors[1]!.sender)!.envelope.seq).toBe(head.envelope.seq + 1);
      expect(c.store.artifacts()).toHaveLength(records.length + 1);
    }
    await expect(shares(c, 1)).rejects.toBe(c.game.failure);
    await expect(c.game.authorAuditDisclose(c.author, before)).rejects.toBe(c.game.failure);
    await expect(act(c, 0, { type: "diamonds" })).rejects.toBe(c.game.failure);
  });

  it.each(["returned body", "argument buffer"] as const)("detects %s tampering through the shared author/receipt correlation guard", async (target) => {
    const c = await context({}, undefined, false);
    const before = c.game.snapshot;
    const native = c.authors[1]!.author.bind(c.authors[1]!);
    vi.spyOn(c.authors[1]!, "author").mockImplementationOnce(async (content, guard) => {
      if (target === "argument buffer") (((content.body as CborMap)["items"] as CborMap[])[0]!["R1"] as Uint8Array).fill(0xff);
      const committed = await native(content, guard);
      if (target === "argument buffer") return committed;
      const substituted = protocol.signEnvelope({ ...committed.envelope, body: { ...committed.envelope.body as CborMap, to: 3 } }, c.f.identities[1]!.secretKey);
      expect(decodeAndVerifyEnvelope(substituted.canonicalBytes)).toEqual(substituted);
      return substituted;
    });
    const receive = vi.spyOn(c.durable, "receive");
    await expect(shares(c, 1)).rejects.toMatchObject({ code: "invalid_receipt" });
    expect(receive).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    expect(c.store.head(c.f.gameId, c.authors[1]!.sender)!.envelope).toMatchObject({ type: "SHARES", body: { to: 0 } });
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
    await expect(shares(c, 2)).rejects.toBe(c.game.failure);
  });
});

describe("local Sasku audit contribution authoring", () => {
  afterEach(() => vi.restoreAllMocks());

  it("requires all four empty disclosures, without game-key access or proof RNG, and distinguishes reauthoring from replay", async () => {
    const c = await context();
    await completeHand(c);
    const before = c.game.snapshot;
    const rng = vi.spyOn(protocolRandom, "randomBytes");
    const prove = vi.spyOn(deck, "createProvenDecryptionShare");
    const privateRead = vi.spyOn(RoundRevealLedger.prototype, "readPrivateHand").mockImplementation(() => { throw new Error("Audit must not read a game key"); });
    const author = vi.spyOn(PersistentEnvelopeAuthor.prototype, "author");
    const sign = vi.spyOn(protocol, "signEnvelope");
    for (const view of [{ ...before }, { ...before, audit: { ...before.audit! } }]) {
      await expect(c.game.authorAuditDisclose(c.author, view)).rejects.toMatchObject({ code: "stale_contribution" });
    }
    const first = await Promise.all([0, 1, 2].map((seat) => c.game.authorAuditDisclose(c.authors[seat]!, before)));
    for (const [seat, result] of first.entries()) {
      expect(result).toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "duplicate" });
      expect(result.received.envelope).toMatchObject({
        from: c.authors[seat]!.sender, round: c.f.round, phase: before.audit!.phase, type: "AUDIT_DISCLOSE", body: { items: [] },
      });
      expect(decodeAuditDiscloseBody(result.received.envelope.body)).toEqual({ items: [] });
      if (result.status === "rejected") throw new Error("Audit contribution was rejected");
      expect(result.snapshot.audit).toEqual({ phase: before.audit!.phase, pendingSenders: [0, 1, 2, 3].slice(seat + 1), result: null });
    }
    await expect(c.game.authorAuditDisclose(c.authors[3]!, before)).rejects.toMatchObject({ code: "stale_contribution" });
    await expect(c.game.authorAuditDisclose(c.author, c.game.snapshot)).rejects.toMatchObject({ code: "conflicting_contribution" });
    expect(sign).toHaveBeenCalledTimes(3);
    const last = await c.game.authorAuditDisclose(c.authors[3]!, c.game.snapshot);
    expect(last).toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "duplicate" });
    expect(last.received.envelope.body).toEqual({ items: [] });
    expect(c.game.snapshot.audit).toEqual({ phase: before.audit!.phase, pendingSenders: [], result: { status: "valid", score: before.hand.provisionalScore } });
    expect(c.game.snapshot.hand).toBe(before.hand);
    expect(c.game.snapshot.history).toBe(before.history);
    expect(c.game.snapshot.ledger).toBe(before.ledger);
    const final = c.game.snapshot;
    const records = c.store.artifacts();
    for (const [seat, original] of [...first, last].entries()) {
      await expect(c.game.authorAuditDisclose(c.authors[seat]!, final)).rejects.toMatchObject({ code: "conflicting_contribution" });
      await expect(c.game.receive(original.received)).resolves.toMatchObject({ status: "duplicate", chainStatus: "duplicate", persistenceStatus: "duplicate" });
    }
    expect(author).toHaveBeenCalledTimes(4);
    expect(sign).toHaveBeenCalledTimes(4);
    for (const spy of [rng, prove, privateRead]) expect(spy).not.toHaveBeenCalled();
    expect(c.store.artifacts()).toEqual(records);
    expect(c.game.snapshot).toBe(final);
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
    expect(c.game.failure).toBeNull();
  }, 15_000);

  it("allows other audit members to commit ahead of an admitted local discloser without retargeting its phase", async () => {
    const c = await context();
    await completeHand(c);
    const before = c.game.snapshot;
    const incoming = await Promise.all([0, 2].map((seat) => c.authors[seat]!.author({
      round: c.f.round, phase: before.audit!.phase, type: "AUDIT_DISCLOSE", body: encodeAuditDiscloseBody({ items: [] }),
    })));
    const gate = deferred();
    const entered = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (argument) => {
      entered.resolve(); await gate.promise; return persist(argument);
    });
    const native = c.authors[3]!.author.bind(c.authors[3]!);
    const guard = vi.fn();
    const author = vi.spyOn(c.authors[3]!, "author").mockImplementation((content, beforeSign) => native(content, (head) => {
      expect(c.game.snapshot).not.toBe(before);
      expect(c.game.snapshot.audit).toEqual({ phase: before.audit!.phase, pendingSenders: [1, 3], result: null });
      for (const original of incoming) expect(c.session.classify(original).status).toBe("duplicate");
      guard();
      return beforeSign!(head);
    }));
    const remote = Promise.all(incoming.map((original) => c.game.receive(original)));
    await entered.promise;
    const local = c.game.authorAuditDisclose(c.authors[3]!, before);
    expect(author).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    gate.resolve();
    await remote;
    await expect(local).resolves.toMatchObject({ status: "accepted", received: { envelope: { phase: before.audit!.phase, body: { items: [] } } } });
    expect(guard).toHaveBeenCalledOnce();
    expect(c.game.snapshot.audit).toEqual({ phase: before.audit!.phase, pendingSenders: [1], result: null });
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
    expect(c.game.failure).toBeNull();
  }, 15_000);

  it.each([false, true])("does not reauthor a self-disclosure received ahead of queued work (completes audit: %s)", async (completes) => {
    const c = await context();
    await completeHand(c);
    if (completes) {
      for (const seat of [1, 2, 3]) await c.game.authorAuditDisclose(c.authors[seat]!, c.game.snapshot);
    }
    const before = c.game.snapshot;
    const original = await c.author.author({
      round: c.f.round, phase: before.audit!.phase, type: "AUDIT_DISCLOSE", body: encodeAuditDiscloseBody({ items: [] }),
    });
    const records = c.store.artifacts();
    const gate = deferred();
    const entered = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (argument) => {
      entered.resolve(); await gate.promise; return persist(argument);
    });
    const author = vi.spyOn(c.author, "author");
    const sign = vi.spyOn(protocol, "signEnvelope");
    const append = vi.spyOn(c.store, "appendNext");
    const received = c.game.receive(original);
    await entered.promise;
    const queued = expect(c.game.authorAuditDisclose(c.author, before)).rejects.toMatchObject({ code: "conflicting_contribution" });
    expect(c.game.snapshot).toBe(before);
    gate.resolve();
    await expect(received).resolves.toMatchObject({ status: "accepted" });
    await queued;
    for (const spy of [author, sign, append]) expect(spy).not.toHaveBeenCalled();
    expect(c.store.artifacts()).toEqual(records);
    expect(c.store.head(c.f.gameId, c.author.sender)).toEqual(original);
    expect(c.game.snapshot.audit?.pendingSenders).toEqual(completes ? [] : [1, 2, 3]);
    expect(c.game.snapshot.audit?.result).toEqual(completes ? { status: "valid", score: before.hand.provisionalScore } : null);
    expect(c.game.failure).toBeNull();
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
    const after = c.game.snapshot;
    await expect(c.game.receive(original)).resolves.toMatchObject({ status: "duplicate" });
    expect(c.game.snapshot).toBe(after);
  }, 15_000);

  it("accepts the last disclosure but attributes a malicious peer's earlier false bid to that action, not the last discloser", async () => {
    const c = await context();
    await completeHand(c, true);
    const before = c.game.snapshot;
    for (const seat of [0, 1, 2]) {
      await expect(c.game.authorAuditDisclose(c.authors[seat]!, c.game.snapshot)).resolves.toMatchObject({ status: "accepted" });
      expect(c.game.snapshot.audit?.result).toBeNull();
    }
    const last = await c.game.authorAuditDisclose(c.authors[3]!, c.game.snapshot);
    expect(last).toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "duplicate" });
    expect(last.received.envelope).toMatchObject({ from: c.authors[3]!.sender, type: "AUDIT_DISCLOSE", body: { items: [] } });
    expect(c.game.snapshot.audit).toEqual({
      phase: before.audit!.phase, pendingSenders: [], result: { status: "violation", seat: 0, at: 0, rule: "bid_strength" },
    });
    expect(c.store.head(c.f.gameId, c.authors[3]!.sender)).toEqual(last.received);
    expect(c.session.classify(last.received).status).toBe("duplicate");
    expect(c.game.failure).toBeNull();
    const final = c.game.snapshot;
    await expect(c.game.receive(last.received)).resolves.toMatchObject({ status: "duplicate" });
    await expect(c.game.authorAuditDisclose(c.authors[3]!, final)).rejects.toMatchObject({ code: "conflicting_contribution" });
    expect(c.game.snapshot).toBe(final);
    expect(c.game.pendingBytes).toBe(0);
  }, 15_000);
});

function shares(c: Context, seat: SaskuSeat, expected: SaskuRoundSnapshot = c.game.snapshot, source: RandomSource = c.f.source) {
  return c.game.authorDealShares(c.authors[seat]!, c.f.secrets[seat]!, expected, source);
}

async function nativeDeal(c: Context, step: number, seat: SaskuSeat) {
  // Reuse only fixture content: native authors own the current signed chain headers.
  const { round, phase, type, body } = c.f.deal(step, seat).envelope;
  return c.authors[seat]!.author({ round, phase, type, body });
}

async function completeHand(c: Context, falseBid = false) {
  if (falseBid) {
    const hand = c.game.readPrivateHand(c.author.sender, c.f.secrets[0]!)!;
    const value = saskuBidStrength(Object.values(hand.dealt)) + 1;
    // Simulate a malicious peer bypassing local preflight, but keep its real durable signing head.
    const malicious = await c.author.author({
      round: c.f.round, phase: c.game.snapshot.ledger.phase, type: "ACTION",
      body: encodeActionBody({ kind: "bid", data: { value }, reveal: [], shares: [] }),
    });
    await expect(c.game.receive(malicious)).resolves.toMatchObject({ status: "accepted" });
  }
  await expect(act(c, c.game.snapshot.hand.turn!, { type: "diamonds" })).resolves.toMatchObject({ status: "accepted" });
  for (let play = 0; play < 36; play += 1) {
    const state = c.game.snapshot;
    const seat = state.hand.turn!;
    const hand = c.game.readPrivateHand(c.authors[seat]!.sender, c.f.secrets[seat]!)!;
    const legal = legalSaskuCards(Object.values(hand.remaining), state.hand.trick, "diamonds");
    const [position] = Object.entries(hand.remaining).find(([, card]) => legal.includes(card))!;
    await expect(act(c, seat, { type: "play", position: Number(position) })).resolves.toMatchObject({ status: "accepted" });
  }
  expect(c.game.snapshot.hand.phase).toBe("complete");
  expect(Object.keys(c.game.snapshot.ledger.revealed)).toHaveLength(36);
  expect(c.game.snapshot.audit).toEqual({ phase: `round.${c.f.round}.audit`, pendingSenders: [0, 1, 2, 3], result: null });
}
