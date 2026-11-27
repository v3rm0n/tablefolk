import { scalarFromBigInt } from "@p2pcards/crypto";
import * as deck from "@p2pcards/deck";
import { decodeSharesBody, encodeAuditDiscloseBody, encodeSharesBody } from "@p2pcards/deck";
import { MAX_ROUND_REVEAL_ENVELOPE_BYTES } from "@p2pcards/engine";
import {
  DEFAULT_MAX_PENDING_SASKU_INBOX_BYTES, DEFAULT_MAX_PENDING_SASKU_INBOX_ENVELOPES,
  SaskuRoundInbox, SaskuRoundInboxError,
  type SaskuRoundInboxErrorCode, type SaskuRoundInboxOptions,
} from "@p2pcards/game-sasku";
import * as protocol from "@p2pcards/protocol";
import {
  parseGameId, parseHash256, parseIdentityPublicKey, signEnvelope,
  type EnvelopeArtifact, type IdentityPublicKey, type UnsignedEnvelope,
} from "@p2pcards/protocol";
import { MAX_SASKU_HAND_ACTIONS } from "@p2pcards/rules-sasku";
import { PersistentSessionReceiverError, SessionChainRegistry } from "@p2pcards/session";
import { afterEach, describe, expect, it, vi } from "vitest";

import { act, context, deferred } from "./local-authoring.test-fixture";

afterEach(() => vi.restoreAllMocks());

describe("Sasku round inbox admission", () => {
  it("requires concrete matching bindings, a local roster identity, and positive safe limits", async () => {
    const c = await context({}, undefined, false);
    const other = new SessionChainRegistry(c.f.gameId, c.f.roster);
    expect(c.game.round).toBe(c.f.round);
    expect(c.game.dealCount).toBe(c.f.plans.length);
    expect(c.game.isBoundTo(c.session)).toBe(true);
    expect(c.game.isBoundTo(other)).toBe(false);
    for (const changes of [
      { session: other }, { session: {} }, { receiver: {} },
      { self: c.f.identities[4]!.publicKey },
    ]) expect(() => inboxFor(c, changes as Partial<SaskuRoundInboxOptions>)).toThrow(TypeError);
    expect(() => inboxFor(c, { self: new Uint8Array(31) as IdentityPublicKey })).toThrow(/exactly 32 bytes/);
    for (const value of [0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      for (const key of ["maxPendingEnvelopes", "maxPendingBytes"] as const) {
        expect(() => inboxFor(c, { [key]: value })).toThrow(RangeError);
      }
    }
    const inbox = inboxFor(c);
    expect(inbox.pendingEnvelopes).toBe(0);
    expect(inbox.pendingBytes).toBe(0);
    expect(inbox.closed).toBe(false);
    expect(inbox.failure).toBeNull();
    await expect(inbox.whenIdle()).resolves.toBeUndefined();
    await expect(inbox.processPending()).resolves.toBeUndefined();
  });

  it("captures constructor scope and identity instead of following mutated options or metadata views", async () => {
    const c = await context({}, undefined, false);
    const self = parseIdentityPublicKey(c.f.roster[0]!);
    const roster = c.session.roster;
    const gameId = c.session.gameId;
    const rosterRead = vi.spyOn(c.session, "roster", "get").mockReturnValue(roster);
    const gameRead = vi.spyOn(c.session, "gameId", "get").mockReturnValue(gameId);
    const roundRead = vi.spyOn(c.game, "round", "get");
    const dealCountRead = vi.spyOn(c.game, "dealCount", "get");
    const options = { receiver: c.game, session: c.session, self, maxPendingEnvelopes: 1 };
    const inbox = new SaskuRoundInbox(options);
    const message = await native(c, c.f.deal(0, 1));
    self.fill(0xff);
    roster.forEach((identity) => identity.fill(0xee));
    gameId.fill(0xdd);
    options.self = c.f.roster[1]!;
    options.session = new SessionChainRegistry(c.f.gameId, c.f.roster);
    options.maxPendingEnvelopes = 0;
    roundRead.mockReturnValue(c.f.round + 1);
    dealCountRead.mockReturnValue(0);
    rosterRead.mockRestore();
    gameRead.mockRestore();
    await expect(inbox.receive(c.f.roster[1]!, message.canonicalBytes)).resolves.toMatchObject({ status: "accepted" });
    expect(roundRead).toHaveBeenCalledOnce();
    expect(dealCountRead).toHaveBeenCalledOnce();
    expect(inbox.failure).toBeNull();
  });

  it("rejects self, nonroster, malformed, and forwarded peer identities before round receipt", async () => {
    const c = await context({}, undefined, false);
    const inbox = inboxFor(c);
    const message = await native(c, c.f.deal(0, 1));
    const self = signEnvelope({ ...message.envelope, from: c.f.roster[0]! }, c.f.identities[0]!.secretKey);
    const stranger = signEnvelope({ ...message.envelope, from: c.f.identities[4]!.publicKey }, c.f.identities[4]!.secretKey);
    const receive = vi.spyOn(c.game, "receive");
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope");
    const before = c.game.snapshot;
    for (const [peer, bytes] of [
      [c.f.roster[0], self.canonicalBytes], [c.f.roster[2], message.canonicalBytes],
      [c.f.identities[4]!.publicKey, stranger.canonicalBytes], [c.f.roster[1], stranger.canonicalBytes],
      [new Uint8Array(31), message.canonicalBytes], [null, message.canonicalBytes],
    ] as const) {
      await expect(inbox.receive(peer as IdentityPublicKey, bytes)).rejects.toMatchObject({ code: "wrong_peer" });
      expect(inbox.pendingEnvelopes).toBe(0);
      expect(inbox.pendingBytes).toBe(0);
    }
    expect(receive).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    await expect(inbox.receive(c.f.roster[1]!, message.canonicalBytes)).resolves.toMatchObject({ status: "accepted" });
  });

  it("rejects wrong scope, control types, phase aliases, and out-of-range indices before admission", async () => {
    const c = await context({}, undefined, false);
    const inbox = inboxFor(c);
    const message = await native(c, c.f.deal(0, 1));
    const receive = vi.spyOn(c.game, "receive");
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope");
    const before = c.game.snapshot;
    const variants: readonly (readonly [Partial<UnsignedEnvelope>, SaskuRoundInboxErrorCode])[] = [
      [{ game: parseGameId(new Uint8Array(16).fill(0x7f)) }, "wrong_game"],
      [{ round: c.f.round + 1 }, "wrong_round"],
      [{ type: "WITNESS", body: { heads: [] } }, "wrong_type"],
      [{ type: "KEY_SHARE", body: {} }, "wrong_type"],
      ...["00", "-0", "+0", "0.0", "0e0", "", "-1", "4"].map((suffix) =>
        [{ phase: `round.${c.f.round}.deal.${suffix}` }, "wrong_phase"] as const),
      [{ phase: `round.0${c.f.round}.deal.0` }, "wrong_phase"],
      [{ phase: `round.${c.f.round}.play.0` }, "wrong_phase"],
      [{ type: "ACTION", phase: `round.${c.f.round}.play.00` }, "wrong_phase"],
      [{ type: "ACTION", phase: `round.${c.f.round}.play.${MAX_SASKU_HAND_ACTIONS}` }, "wrong_phase"],
      [{ type: "AUDIT_DISCLOSE", phase: `round.${c.f.round}.audit.0`, body: { items: [] } }, "wrong_phase"],
      [{ type: "AUDIT_DISCLOSE", phase: `round.0${c.f.round}.audit`, body: { items: [] } }, "wrong_phase"],
    ];
    for (const [changes, code] of variants) {
      const invalid = signEnvelope({ ...message.envelope, ...changes }, c.f.identities[1]!.secretKey);
      await expect(inbox.receive(c.f.roster[1]!, invalid.canonicalBytes)).rejects.toMatchObject({ code });
      expect(inbox.pendingBytes).toBe(0);
      expect(inbox.pendingEnvelopes).toBe(0);
    }
    expect(receive).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    expect(inbox.failure).toBeNull();
  });

  it("rejects malformed bodies and frames, enforcing the 64 KiB ceiling before copying or verifying", async () => {
    const c = await context({}, undefined, false);
    const inbox = inboxFor(c);
    const message = await native(c, c.f.deal(0, 1));
    const receive = vi.spyOn(c.game, "receive");
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope");
    const variants: readonly Partial<UnsignedEnvelope>[] = [
      { body: {} }, { body: { to: 0, items: [] } },
      { type: "ACTION", phase: `round.${c.f.round}.play.0`, body: {} },
      { type: "ACTION", phase: `round.${c.f.round}.play.0`, body: { kind: "play", data: {}, reveal: [0], shares: [] } },
      { type: "AUDIT_DISCLOSE", phase: `round.${c.f.round}.audit`, body: { items: [], result: "valid" } },
      { type: "AUDIT_DISCLOSE", phase: `round.${c.f.round}.audit`, body: encodeAuditDiscloseBody({ items: decodeSharesBody(message.envelope.body).items.slice(0, 1) }) },
    ];
    for (const changes of variants) {
      const invalid = signEnvelope({ ...message.envelope, ...changes }, c.f.identities[1]!.secretKey);
      await expect(inbox.receive(c.f.roster[1]!, invalid.canonicalBytes)).rejects.toMatchObject({ code: "invalid_envelope" });
    }
    const verify = vi.spyOn(protocol, "decodeAndVerifyEnvelope");
    const copy = vi.spyOn(Uint8Array.prototype, "set");
    expect(MAX_ROUND_REVEAL_ENVELOPE_BYTES).toBe(64 * 1024);
    const oversized = new Uint8Array(MAX_ROUND_REVEAL_ENVELOPE_BYTES + 1);
    class OtherBytes extends Uint8Array {}
    for (const bytes of [new Uint8Array(), oversized, new OtherBytes(1), new ArrayBuffer(1), null]) {
      await expect(inbox.receive(c.f.roster[1]!, bytes as Uint8Array)).rejects.toMatchObject({ code: "invalid_envelope" });
    }
    expect(verify).not.toHaveBeenCalled();
    expect(copy).not.toHaveBeenCalled();
    copy.mockRestore();
    const forged = message.canonicalBytes.slice();
    forged[forged.length - 1]! ^= 1;
    for (const bytes of [new Uint8Array([0xff]), forged]) {
      await expect(inbox.receive(c.f.roster[1]!, bytes)).rejects.toBeInstanceOf(SaskuRoundInboxError);
    }
    expect(receive).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
    expect(inbox.pendingEnvelopes).toBe(0);
    expect(inbox.pendingBytes).toBe(0);
    expect(inbox.failure).toBeNull();
  });
});

describe("Sasku round inbox scheduling", () => {
  it("holds a chain-ready future deal without receipt or persistence, then wakes on other seats' prerequisites", async () => {
    const c = await context({}, undefined, false);
    const inbox = inboxFor(c);
    const first = await native(c, c.f.deal(0, 2));
    const future = await native(c, c.f.deal(1, 2));
    const one = await native(c, c.f.deal(0, 1));
    const three = await native(c, c.f.deal(0, 3));
    await expect(inbox.receive(c.f.roster[2]!, first.canonicalBytes)).resolves.toMatchObject({ status: "accepted" });
    await inbox.whenIdle();
    expect(c.session.classify(future).status).toBe("accepted");
    const receive = vi.spyOn(c.game, "receive");
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope");
    const proof = vi.spyOn(deck, "verifyProvenDecryptionShare");
    const before = c.game.snapshot;
    const heads = c.session.heads();
    const settled = vi.fn();
    const pending = inbox.receive(c.f.roster[2]!, future.canonicalBytes);
    void pending.then(settled, settled);
    await inbox.whenIdle();
    expect(settled).not.toHaveBeenCalled();
    expect(inbox.pendingEnvelopes).toBe(1);
    expect(inbox.pendingBytes).toBe(future.canonicalBytes.length);
    expect(receive).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
    expect(proof).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    expect(c.session.heads()).toEqual(heads);
    expect(c.game.readPrivateHand(c.f.roster[0]!, c.f.secrets[0]!)).toBeNull();
    await inbox.receive(c.f.roster[1]!, one.canonicalBytes);
    await inbox.whenIdle();
    expect(settled).not.toHaveBeenCalled();
    await inbox.receive(c.f.roster[3]!, three.canonicalBytes);
    await expect(pending).resolves.toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "duplicate" });
    await inbox.whenIdle();
    expect(receive.mock.calls.map(([artifact]) => artifact.canonicalBytes)).toEqual([one.canonicalBytes, three.canonicalBytes, future.canonicalBytes]);
    expect(write).toHaveBeenCalledTimes(3);
    expect(c.game.snapshot.ledger).toMatchObject({ dealIndex: 1, deal: { pendingSenders: [0, 3] } });
    expect(inbox.pendingEnvelopes).toBe(0);
    expect(inbox.pendingBytes).toBe(0);
  });

  it("leaves gaps pending and requires explicit notification after out-of-band WITNESS receipt", async () => {
    const c = await context({}, undefined, false);
    const inbox = inboxFor(c);
    const control = await c.authors[1]!.author({ round: c.f.round, phase: c.game.snapshot.ledger.phase, type: "WITNESS", body: { heads: [] } });
    const message = await native(c, c.f.deal(0, 1));
    const receive = vi.spyOn(c.game, "receive");
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope");
    const before = c.game.snapshot;
    const settled = vi.fn();
    const pending = inbox.receive(c.f.roster[1]!, message.canonicalBytes);
    void pending.then(settled, settled);
    await inbox.whenIdle();
    await expect(inbox.receive(c.f.roster[1]!, control.canonicalBytes)).rejects.toMatchObject({ code: "wrong_type" });
    expect(receive).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    await expect(c.durable.receive(control)).resolves.toMatchObject({ status: "accepted" });
    await inbox.whenIdle();
    expect(settled).not.toHaveBeenCalled();
    expect(inbox.pendingEnvelopes).toBe(1);
    expect(receive).not.toHaveBeenCalled();
    await inbox.processPending();
    await expect(pending).resolves.toMatchObject({ status: "accepted", received: { canonicalBytes: message.canonicalBytes } });
    expect(receive).toHaveBeenCalledOnce();
    expect(write).toHaveBeenCalledTimes(2);
    expect(inbox.pendingBytes).toBe(0);
  });

  it("sorts each seat by signed sequence and never skips a future low sequence for a later current phase", async () => {
    const c = await context({}, undefined, false);
    const inbox = inboxFor(c);
    const future = await native(c, c.f.deal(1, 2));
    const current = await native(c, c.f.deal(0, 2));
    expect(current.envelope.seq).toBe(future.envelope.seq + 1);
    const receive = vi.spyOn(c.game, "receive");
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope");
    const classify = vi.spyOn(c.session, "classify");
    const before = c.game.snapshot;
    const pending = Promise.allSettled([
      inbox.receive(c.f.roster[2]!, current.canonicalBytes),
      inbox.receive(c.f.roster[2]!, future.canonicalBytes),
    ]);
    await inbox.whenIdle();
    await inbox.processPending();
    expect(classify.mock.calls.map(([artifact]) => artifact.envelope.seq)).toEqual([future.envelope.seq, future.envelope.seq]);
    expect(receive).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    expect(inbox.pendingEnvelopes).toBe(2);
    inbox.close();
    await expect(pending).resolves.toMatchObject([
      { status: "rejected", reason: { code: "closed" } }, { status: "rejected", reason: { code: "closed" } },
    ]);
  });

  it("rotates eligible seats fairly and sends each charged duplicate through ordinary idempotent receipt", async () => {
    const c = await context({}, undefined, false);
    const inbox = inboxFor(c);
    const one = await native(c, c.f.deal(0, 1));
    const two = await native(c, c.f.deal(0, 2));
    const three = await native(c, c.f.deal(0, 3));
    const receive = vi.spyOn(c.game, "receive");
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope");
    const jobs = [one, one, one, two, three].map((message) => inbox.receive(message.envelope.from, message.canonicalBytes));
    expect(new Set(jobs).size).toBe(5);
    expect(inbox.pendingEnvelopes).toBe(5);
    expect(inbox.pendingBytes).toBe(3 * one.canonicalBytes.length + two.canonicalBytes.length + three.canonicalBytes.length);
    const results = await Promise.all(jobs);
    await inbox.whenIdle();
    expect(receive.mock.calls.map(([message]) => c.session.seatOf(message.envelope.from))).toEqual([1, 2, 3, 1, 1]);
    expect(results.map(({ status }) => status)).toEqual(["accepted", "duplicate", "duplicate", "accepted", "accepted"]);
    expect(results[1]).toMatchObject({ chainStatus: "duplicate", persistenceStatus: "duplicate" });
    expect(results[2]).toMatchObject({ chainStatus: "duplicate", persistenceStatus: "duplicate" });
    expect(write).toHaveBeenCalledTimes(5);
    const cached = c.game.snapshot;
    expect(cached.ledger.dealIndex).toBe(1);
    await expect(inbox.receive(c.f.roster[1]!, one.canonicalBytes)).resolves.toMatchObject({ status: "duplicate", snapshot: cached });
    expect(c.game.snapshot).toBe(cached);
    expect(inbox.pendingBytes).toBe(0);
  });

  it("requires local-progress wakes for future play and changes no private or public cards before commit", async () => {
    const c = await context();
    const inbox = inboxFor(c, { self: c.f.roster[3]! });
    const future = await native(c, c.f.action(1, [9], 2));
    const receive = vi.spyOn(c.game, "receive");
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope");
    const before = c.game.snapshot;
    const hand = c.game.readPrivateHand(c.f.roster[1]!, c.f.secrets[1]!);
    const settled = vi.fn();
    const pending = inbox.receive(c.f.roster[1]!, future.canonicalBytes);
    void pending.then(settled, settled);
    await inbox.whenIdle();
    expect(receive).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    expect(c.game.readPrivateHand(c.f.roster[1]!, c.f.secrets[1]!)).toEqual(hand);
    await act(c, 0, { type: "diamonds" });
    await inbox.processPending();
    expect(settled).not.toHaveBeenCalled();
    await act(c, 0, { type: "play", position: 0 });
    await inbox.whenIdle();
    expect(settled).not.toHaveBeenCalled();
    expect(receive).not.toHaveBeenCalled();
    const gate = deferred();
    const entered = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    write.mockImplementationOnce(async (argument) => { entered.resolve(); await gate.promise; return persist(argument); });
    const waiting = c.game.snapshot;
    const draining = inbox.processPending();
    await entered.promise;
    expect(c.game.snapshot).toBe(waiting);
    expect(c.game.readPrivateHand(c.f.roster[1]!, c.f.secrets[1]!)).toEqual(hand);
    expect(settled).not.toHaveBeenCalled();
    gate.resolve();
    await draining;
    const result = await pending;
    expect(result).toMatchObject({ status: "accepted", received: { canonicalBytes: future.canonicalBytes } });
    expect(c.game.snapshot.ledger).toMatchObject({ actionIndex: 3, revealed: { 9: c.f.cards[9] } });
    expect(c.game.readPrivateHand(c.f.roster[1]!, c.f.secrets[1]!)!.remaining).not.toHaveProperty("9");
    expect(c.game.snapshot.history).toHaveLength(3);
    expect(inbox.pendingEnvelopes).toBe(0);
    expect(inbox.failure).toBeNull();
  }, 15_000);

  it("waits for unrelated receiver work to become idle before reading its scheduling snapshot", async () => {
    const c = await context({}, undefined, false);
    const one = await native(c, c.f.deal(0, 1));
    const two = await native(c, c.f.deal(0, 2));
    const three = await native(c, c.f.deal(0, 3));
    const future = await native(c, c.f.deal(1, 2));
    const gate = deferred();
    const entered = deferred();
    const waiting = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (argument) => {
      entered.resolve(); await gate.promise; return persist(argument);
    });
    const unrelated = Promise.all([one, two, three].map((message) => c.game.receive(message)));
    await entered.promise;
    const inbox = inboxFor(c);
    const idle = c.game.whenIdle.bind(c.game);
    vi.spyOn(c.game, "whenIdle").mockImplementation(() => { waiting.resolve(); return idle(); });
    const snapshot = vi.spyOn(c.game, "snapshot", "get");
    const receive = vi.spyOn(c.game, "receive");
    const pending = inbox.receive(c.f.roster[2]!, future.canonicalBytes);
    await waiting.promise;
    expect(snapshot).not.toHaveBeenCalled();
    expect(receive).not.toHaveBeenCalled();
    expect(inbox.pendingEnvelopes).toBe(1);
    gate.resolve();
    await unrelated;
    await expect(pending).resolves.toMatchObject({ status: "accepted" });
    await inbox.whenIdle();
    expect(receive).toHaveBeenCalledOnce();
    expect(c.game.snapshot.ledger).toMatchObject({ dealIndex: 1, deal: { pendingSenders: [0, 3] } });
  });


});

describe("Sasku round inbox budgets and isolation", () => {
  it("defaults to 32 jobs and 1 MiB, charging every future-audit duplicate separately", async () => {
    const c = await context({}, undefined, false);
    const inbox = inboxFor(c);
    expect(DEFAULT_MAX_PENDING_SASKU_INBOX_ENVELOPES).toBe(32);
    expect(DEFAULT_MAX_PENDING_SASKU_INBOX_BYTES).toBe(1024 * 1024);
    const message = await audit(c, 1);
    const receive = vi.spyOn(c.game, "receive");
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope");
    const jobs = Array.from({ length: 32 }, () => inbox.receive(c.f.roster[1]!, message.canonicalBytes));
    const cancelled = Promise.allSettled(jobs);
    await inbox.whenIdle();
    expect(new Set(jobs).size).toBe(32);
    expect(inbox.pendingEnvelopes).toBe(32);
    expect(inbox.pendingBytes).toBe(32 * message.canonicalBytes.length);
    const verify = vi.spyOn(protocol, "decodeAndVerifyEnvelope");
    await expect(inbox.receive(c.f.roster[1]!, message.canonicalBytes)).rejects.toMatchObject({ code: "queue_limit" });
    expect(verify).not.toHaveBeenCalled();
    expect(receive).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
    expect(c.game.snapshot.audit).toBeNull();
    inbox.close();
    const results = await cancelled;
    expect(results).toHaveLength(32);
    for (const result of results) expect(result).toMatchObject({ status: "rejected", reason: { code: "closed" } });
    expect(inbox.pendingEnvelopes).toBe(0);
    expect(inbox.pendingBytes).toBe(0);
  });

  it.each(["count", "bytes"] as const)("bounds active plus future %s before copying, signatures, or body codecs and releases capacity", async (limit) => {
    const c = await context({}, undefined, false);
    const current = await native(c, c.f.deal(0, 1));
    const future = await audit(c, 2);
    const size = current.canonicalBytes.length + future.canonicalBytes.length;
    const inbox = inboxFor(c, limit === "count" ? { maxPendingEnvelopes: 2 } : { maxPendingBytes: size });
    const gate = deferred();
    const entered = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (argument) => {
      entered.resolve(); await gate.promise; return persist(argument);
    });
    const active = inbox.receive(c.f.roster[1]!, current.canonicalBytes);
    await entered.promise;
    const pending = Promise.allSettled([inbox.receive(c.f.roster[2]!, future.canonicalBytes)]);
    expect(inbox.pendingEnvelopes).toBe(2);
    expect(inbox.pendingBytes).toBe(size);
    const verify = vi.spyOn(protocol, "decodeAndVerifyEnvelope");
    const codec = vi.spyOn(deck, "decodeSharesBody");
    const copy = vi.spyOn(Uint8Array.prototype, "set");
    await expect(inbox.receive(c.f.roster[1]!, new Uint8Array(current.canonicalBytes.length))).rejects.toMatchObject({ code: "queue_limit" });
    expect(verify).not.toHaveBeenCalled();
    expect(codec).not.toHaveBeenCalled();
    expect(copy).not.toHaveBeenCalled();
    copy.mockRestore();
    gate.resolve();
    await active;
    await inbox.whenIdle();
    expect(inbox.pendingEnvelopes).toBe(1);
    expect(inbox.pendingBytes).toBe(future.canonicalBytes.length);
    await expect(inbox.receive(c.f.roster[1]!, current.canonicalBytes)).resolves.toMatchObject({ status: "duplicate" });
    inbox.close();
    await pending;
    expect(inbox.pendingBytes).toBe(0);
  });

  it("rejects conflicting active and queued sequence bytes without replacing or uncharging originals", async () => {
    const c = await context({}, undefined, false);
    const inbox = inboxFor(c);
    const current = await native(c, c.f.deal(0, 1));
    const queued = await native(c, c.f.deal(0, 2));
    const gate = deferred();
    const entered = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (argument) => {
      entered.resolve(); await gate.promise; return persist(argument);
    });
    const active = inbox.receive(c.f.roster[1]!, current.canonicalBytes);
    await entered.promise;
    const pending = inbox.receive(c.f.roster[2]!, queued.canonicalBytes);
    for (const [message, seat] of [[current, 1], [queued, 2]] as const) {
      const conflict = signEnvelope({ ...message.envelope, phase: `round.${c.f.round}.deal.1` }, c.f.identities[seat]!.secretKey);
      await expect(inbox.receive(c.f.roster[seat]!, conflict.canonicalBytes)).rejects.toMatchObject({ code: "conflicting_pending" });
      expect(inbox.pendingEnvelopes).toBe(2);
      expect(inbox.pendingBytes).toBe(current.canonicalBytes.length + queued.canonicalBytes.length);
    }
    gate.resolve();
    await expect(active).resolves.toMatchObject({ status: "accepted", received: { canonicalBytes: current.canonicalBytes } });
    await expect(pending).resolves.toMatchObject({ status: "accepted", received: { canonicalBytes: queued.canonicalBytes } });
    await inbox.whenIdle();
    expect(write).toHaveBeenCalledTimes(2);
    expect(c.game.snapshot.ledger.deal?.pendingSenders).toEqual([3]);
    expect(inbox.pendingEnvelopes).toBe(0);
    expect(inbox.failure).toBeNull();
    expect(inbox.pendingBytes).toBe(0);
  });


});

describe("Sasku round inbox failures and lifecycle", () => {
  it("returns known broken-link and equivocation rejections without calling the round receiver", async () => {
    const c = await context({}, undefined, false);
    const inbox = inboxFor(c);
    const message = await native(c, c.f.deal(0, 1));
    const broken = signEnvelope({ ...message.envelope, prev: parseHash256(new Uint8Array(32).fill(0xaa)) }, c.f.identities[1]!.secretKey);
    const control = await c.authors[2]!.author({ round: c.f.round, phase: c.game.snapshot.ledger.phase, type: "WITNESS", body: { heads: [] } });
    await c.durable.receive(control);
    const body = c.f.deal(0, 2).envelope.body;
    const equivocation = signEnvelope({ ...control.envelope, type: "SHARES", body }, c.f.identities[2]!.secretKey);
    const before = c.game.snapshot;
    const receive = vi.spyOn(c.game, "receive");
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope");
    for (const [artifact, reason] of [[broken, "broken_prev"], [equivocation, "equivocation"]] as const) {
      const result = await inbox.receive(artifact.envelope.from, artifact.canonicalBytes);
      expect(result).toMatchObject({ status: "rejected", reason, received: { canonicalBytes: artifact.canonicalBytes } });
      expect(result.received.canonicalBytes).not.toBe(artifact.canonicalBytes);
      result.received.canonicalBytes.fill(0xff);
    }
    expect(receive).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    expect(inbox.failure).toBeNull();
    expect(inbox.pendingBytes).toBe(0);
    await expect(inbox.receive(c.f.roster[1]!, message.canonicalBytes)).resolves.toMatchObject({ status: "accepted" });
  });

  it("recognizes fulfilled chain rejections from the receiver without retrying or treating them as success", async () => {
    const c = await context({}, undefined, false);
    const inbox = inboxFor(c);
    const message = await native(c, c.f.deal(0, 1));
    const before = c.game.snapshot;
    const receive = vi.spyOn(c.game, "receive");
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope");
    for (const reason of ["gap", "broken_prev", "equivocation", "durable_conflict"] as const) {
      receive.mockImplementationOnce(async (received) => ({ status: "rejected", received, reason }));
      await expect(inbox.receive(c.f.roster[1]!, message.canonicalBytes)).resolves.toMatchObject({ status: "rejected", reason });
      await inbox.processPending();
      expect(inbox.pendingEnvelopes).toBe(0);
      expect(inbox.failure).toBeNull();
    }
    expect(receive).toHaveBeenCalledTimes(4);
    expect(write).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    await expect(inbox.receive(c.f.roster[1]!, message.canonicalBytes)).resolves.toMatchObject({ status: "accepted" });
  });

  it("does not automatically retry ordinary disk errors and keeps later jobs usable", async () => {
    const c = await context({}, undefined, false);
    const inbox = inboxFor(c);
    const first = await native(c, c.f.deal(0, 1));
    const second = await native(c, c.f.deal(0, 2));
    const before = c.game.snapshot;
    const error = new Error("disk failure");
    const receive = vi.spyOn(c.game, "receive");
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope").mockRejectedValueOnce(error);
    await expect(inbox.receive(c.f.roster[1]!, first.canonicalBytes)).rejects.toBe(error);
    await inbox.processPending();
    expect(c.game.snapshot).toBe(before);
    expect(receive).toHaveBeenCalledOnce();
    expect(write).toHaveBeenCalledOnce();
    expect(c.session.classify(first).status).toBe("accepted");
    expect(inbox.pendingEnvelopes).toBe(0);
    expect(inbox.failure).toBeNull();
    expect(c.game.failure).toBeNull();
    await expect(inbox.receive(c.f.roster[2]!, second.canonicalBytes)).resolves.toMatchObject({ status: "accepted" });
    await expect(inbox.receive(c.f.roster[1]!, first.canonicalBytes)).resolves.toMatchObject({ status: "accepted" });
    expect(write).toHaveBeenCalledTimes(3);
    expect(inbox.pendingBytes).toBe(0);
  });

  it("rejects a current invalid proof only when attempted, without persisting, retrying, or poisoning other jobs", async () => {
    const c = await context({}, undefined, false);
    const inbox = inboxFor(c);
    const first = await native(c, c.f.deal(0, 1));
    const second = await native(c, c.f.deal(0, 2));
    const body = decodeSharesBody(first.envelope.body);
    const bad = signEnvelope({ ...first.envelope, body: encodeSharesBody({ ...body,
      items: body.items.map((item, index) => index === 0 ? { ...item, proof: { ...item.proof, z: scalarFromBigInt(1n) } } : item),
    }) }, c.f.identities[1]!.secretKey);
    const receive = vi.spyOn(c.game, "receive");
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope");
    const before = c.game.snapshot;
    const invalid = inbox.receive(c.f.roster[1]!, bad.canonicalBytes);
    expect(inbox.pendingEnvelopes).toBe(1);
    expect(receive).not.toHaveBeenCalled();
    await expect(invalid).rejects.toMatchObject({ code: "invalid_share_proof" });
    await inbox.processPending();
    expect(write).not.toHaveBeenCalled();
    expect(receive).toHaveBeenCalledOnce();
    expect(c.game.snapshot).toBe(before);
    expect(inbox.failure).toBeNull();
    expect(c.game.failure).toBeNull();
    await expect(inbox.receive(c.f.roster[2]!, second.canonicalBytes)).resolves.toMatchObject({ status: "accepted" });
    await expect(inbox.receive(c.f.roster[1]!, first.canonicalBytes)).resolves.toMatchObject({ status: "accepted" });
    expect(write).toHaveBeenCalledTimes(2);
    expect(inbox.pendingBytes).toBe(0);
  });

  it("submits current rules violations and nonduplicate past phases to normal receiver validation", async () => {
    const c = await context();
    const inbox = inboxFor(c, { self: c.f.roster[3]! });
    const opening = await native(c, c.f.action(0, [], 0, "diamonds"));
    const play = await native(c, c.f.action(0, [0], 1));
    const illegal = signEnvelope({ ...opening.envelope,
      body: { kind: "choose_trump", data: { suit: "clubs" }, reveal: [], shares: [] },
    }, c.f.identities[0]!.secretKey);
    const past = signEnvelope({ ...play.envelope, phase: opening.envelope.phase, body: opening.envelope.body }, c.f.identities[0]!.secretKey);
    const receive = vi.spyOn(c.game, "receive");
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope");
    const before = c.game.snapshot;
    await expect(inbox.receive(c.f.roster[0]!, illegal.canonicalBytes)).rejects.toThrow(/during bidding/);
    expect(write).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    await expect(inbox.receive(c.f.roster[0]!, opening.canonicalBytes)).resolves.toMatchObject({ status: "accepted" });
    const playing = c.game.snapshot;
    await expect(inbox.receive(c.f.roster[0]!, past.canonicalBytes)).rejects.toMatchObject({ code: "wrong_phase" });
    await inbox.processPending();
    expect(receive).toHaveBeenCalledTimes(3);
    expect(write).toHaveBeenCalledOnce();
    expect(c.game.snapshot).toBe(playing);
    expect(c.game.readPrivateHand(c.f.roster[0]!, c.f.secrets[0]!)!.remaining).toHaveProperty("0");
    expect(inbox.pendingEnvelopes).toBe(0);
    expect(inbox.pendingBytes).toBe(0);
    expect(inbox.failure).toBeNull();
    await expect(inbox.receive(c.f.roster[0]!, play.canonicalBytes)).resolves.toMatchObject({ status: "accepted" });
  }, 15_000);

  it("propagates fatal receiver recovery failure to all remaining jobs and future admissions", async () => {
    const c = await context({}, undefined, false);
    const inbox = inboxFor(c);
    const first = await native(c, c.f.deal(0, 1));
    const second = await native(c, c.f.deal(0, 2));
    const future = await audit(c, 3);
    const gate = deferred();
    const entered = deferred();
    vi.spyOn(c.durable, "receiveVerified").mockImplementationOnce(async () => {
      entered.resolve(); await gate.promise; throw new PersistentSessionReceiverError("invalid stored artifact");
    });
    const receive = vi.spyOn(c.game, "receive");
    const before = c.game.snapshot;
    const jobs = Promise.allSettled([first, second, future].map((message) => inbox.receive(message.envelope.from, message.canonicalBytes)));
    await entered.promise;
    expect(inbox.pendingEnvelopes).toBe(3);
    gate.resolve();
    const results = await jobs;
    await inbox.whenIdle();
    expect(c.game.failure).toMatchObject({ code: "recovery_required" });
    expect(inbox.failure).toBe(c.game.failure);
    for (const result of results) {
      expect(result).toMatchObject({ status: "rejected", reason: { code: "recovery_required" } });
      if (result.status === "rejected") expect(result.reason).toBe(c.game.failure);
    }
    expect(receive).toHaveBeenCalledOnce();
    expect(c.game.snapshot).toBe(before);
    expect(inbox.pendingBytes).toBe(0);
    expect(inbox.pendingEnvelopes).toBe(0);
    await expect(inbox.receive(c.f.roster[1]!, first.canonicalBytes)).rejects.toBe(c.game.failure);
  });

  it("closes deferred work idempotently without closing the receiver and observes receiver closure on wake", async () => {
    const c = await context({}, undefined, false);
    const inbox = inboxFor(c);
    const future = await audit(c, 1);
    const receive = vi.spyOn(c.game, "receive");
    const pending = Promise.allSettled([inbox.receive(c.f.roster[1]!, future.canonicalBytes)]);
    await inbox.whenIdle();
    inbox.close();
    inbox.close();
    await expect(pending).resolves.toMatchObject([{ status: "rejected", reason: { code: "closed" } }]);
    await inbox.whenIdle();
    await inbox.processPending();
    expect(inbox.closed).toBe(true);
    expect(inbox.failure).toBeNull();
    expect(inbox.pendingEnvelopes).toBe(0);
    expect(inbox.pendingBytes).toBe(0);
    expect(c.game.closed).toBe(false);
    expect(receive).not.toHaveBeenCalled();
    await expect(inbox.receive(c.f.roster[1]!, future.canonicalBytes)).rejects.toMatchObject({ code: "closed" });
    const other = inboxFor(c);
    const queued = Promise.allSettled([other.receive(c.f.roster[1]!, future.canonicalBytes)]);
    await other.whenIdle();
    c.game.close();
    await other.processPending();
    await expect(queued).resolves.toMatchObject([{ status: "rejected", reason: { code: "closed" } }]);
    expect(other.closed).toBe(true);
    expect(other.pendingBytes).toBe(0);
  });

  it("unblocks its own idle on close while unrelated receiver work is still awaiting storage", async () => {
    const c = await context({}, undefined, false);
    const first = await native(c, c.f.deal(0, 1));
    const second = await native(c, c.f.deal(0, 2));
    const gate = deferred();
    const entered = deferred();
    const waiting = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (argument) => {
      entered.resolve(); await gate.promise; return persist(argument);
    });
    const unrelated = c.game.receive(first);
    await entered.promise;
    const inbox = inboxFor(c);
    const whenIdle = c.game.whenIdle.bind(c.game);
    vi.spyOn(c.game, "whenIdle").mockImplementation(() => { waiting.resolve(); return whenIdle(); });
    const receive = vi.spyOn(c.game, "receive");
    const pending = Promise.allSettled([inbox.receive(c.f.roster[2]!, second.canonicalBytes)]);
    await waiting.promise;
    const idle = inbox.whenIdle();
    inbox.close();
    try {
      await expect(pending).resolves.toMatchObject([{ status: "rejected", reason: { code: "closed" } }]);
      await idle;
      expect(c.game.pendingEnvelopes).toBe(1);
      expect(c.game.closed).toBe(false);
      expect(receive).not.toHaveBeenCalled();
      expect(inbox.pendingEnvelopes).toBe(0);
      expect(inbox.pendingBytes).toBe(0);
    } finally { gate.resolve(); }
    await expect(unrelated).resolves.toMatchObject({ status: "accepted" });
    await expect(c.game.receive(second)).resolves.toMatchObject({ status: "accepted" });
  });

  it("cancels only unsubmitted work on close and lets an active actual receipt commit before becoming idle", async () => {
    const c = await context({}, undefined, false);
    const inbox = inboxFor(c);
    const first = await native(c, c.f.deal(0, 1));
    const second = await native(c, c.f.deal(0, 2));
    const gate = deferred();
    const entered = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    const write = vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (argument) => {
      entered.resolve(); await gate.promise; return persist(argument);
    });
    const before = c.game.snapshot;
    const active = inbox.receive(c.f.roster[1]!, first.canonicalBytes);
    const queued = Promise.allSettled([inbox.receive(c.f.roster[2]!, second.canonicalBytes)]);
    await entered.promise;
    const settled = vi.fn();
    const idle = inbox.whenIdle().then(settled);
    inbox.close();
    await expect(queued).resolves.toMatchObject([{ status: "rejected", reason: { code: "closed" } }]);
    expect(settled).not.toHaveBeenCalled();
    expect(inbox.pendingEnvelopes).toBe(1);
    expect(inbox.pendingBytes).toBe(first.canonicalBytes.length);
    expect(c.game.snapshot).toBe(before);
    expect(c.game.closed).toBe(false);
    gate.resolve();
    await expect(active).resolves.toMatchObject({ status: "accepted", received: { canonicalBytes: first.canonicalBytes } });
    await idle;
    expect(settled).toHaveBeenCalledOnce();
    expect(write).toHaveBeenCalledOnce();
    expect(c.game.snapshot.ledger.deal?.pendingSenders).toEqual([2, 3]);
    expect(inbox.pendingEnvelopes).toBe(0);
    expect(inbox.pendingBytes).toBe(0);
    expect(inbox.failure).toBeNull();
    await expect(c.game.receive(second)).resolves.toMatchObject({ status: "accepted" });
  });
});

type Context = Awaited<ReturnType<typeof context>>;

function inboxFor(c: Context, options: Partial<SaskuRoundInboxOptions> = {}): SaskuRoundInbox {
  return new SaskuRoundInbox({ receiver: c.game, session: c.session, self: c.f.roster[0]!, ...options });
}

function native(c: Context, fixture: EnvelopeArtifact): Promise<EnvelopeArtifact> {
  // Fixture proofs are reusable, but only native authors own the current signed chain headers.
  const { round, phase, type, body, from } = fixture.envelope;
  return c.authors[c.session.seatOf(from)!]!.author({ round, phase, type, body });
}

function audit(c: Context, seat: number): Promise<EnvelopeArtifact> {
  return c.authors[seat]!.author({ round: c.f.round, phase: `round.${c.f.round}.audit`, type: "AUDIT_DISCLOSE", body: { items: [] } });
}
