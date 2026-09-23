import { bytesEqual, RistrettoPoint, scalarFromBigInt } from "@p2pcards/crypto";
import * as deck from "@p2pcards/deck";
import { decodeSharesBody, encodeActionBody, encodeAuditDiscloseBody, encodeSharesBody, verifyProvenDecryptionShare } from "@p2pcards/deck";
import { encodeCanonical } from "@p2pcards/encoding";
import { MAX_ROUND_REVEAL_ENVELOPE_BYTES, RoundRevealLedger, SetupEnvelopeCoordinator } from "@p2pcards/engine";
import * as protocol from "@p2pcards/protocol";
import { decodeAndVerifyEnvelope, parseGameId, parseHash256, signEnvelope, type EnvelopeArtifact, type UnsignedEnvelope } from "@p2pcards/protocol";
import * as rules from "@p2pcards/rules-sasku";
import { legalSaskuCards, SaskuHandError, saskuBidStrength } from "@p2pcards/rules-sasku";
import { PersistentEnvelopeAuthor, PersistentSessionReceiver, SessionChainRegistry, type EnvelopeContent } from "@p2pcards/session";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import * as protocolRandom from "../../crypto/src/random";
import {
  DEFAULT_MAX_SASKU_RECOVERY_BYTES, DEFAULT_MAX_SASKU_RECOVERY_ENVELOPES,
  PersistentSaskuRoundReceiver, SaskuRoundRecoveryError, type PersistentSaskuRoundOptions, type SaskuRoundRecoveryLimits,
} from "./index";
import { act, context } from "./local-authoring.test-fixture";

type Context = Awaited<ReturnType<typeof context>>;

// Fixture signing heads are stale after context(): only reuse content, never its headers.
async function append(c: Context, seat: number, { round, phase, type, body }: EnvelopeContent) {
  const artifact = await c.authors[seat]!.author({ round, phase, type, body });
  await expect(c.durable.receive(artifact)).resolves.toMatchObject({ status: "accepted", persistenceStatus: "duplicate" });
  return artifact;
}

describe("Sasku round recovery", () => {
  afterEach(() => vi.restoreAllMocks());

  it("synchronously returns a fresh, open setup-only receiver without advancing the original", async () => {
    const c = await context({}, undefined, false);
    const before = c.game.snapshot;
    const recovered = PersistentSaskuRoundReceiver.recover(c.options);
    expect(recovered).toBeInstanceOf(PersistentSaskuRoundReceiver);
    expect(recovered).not.toBeInstanceOf(Promise);
    expect(recovered).not.toBe(c.game);
    expect(recovered.snapshot).toEqual(before);
    expect(recovered.snapshot).not.toBe(before);
    expect(recovered).toMatchObject({ closed: false, failure: null, pendingEnvelopes: 0, pendingBytes: 0 });
    expect(recovered.snapshot.ledger.deal?.pendingSenders).toEqual([1, 2, 3]);
    for (let seat = 0; seat < 4; seat += 1) {
      expect(recovered.readPrivateHand(c.f.roster[seat]!, c.f.secrets[seat]!)).toBeNull();
    }
    recovered.close();
    expect(c.game.closed).toBe(false);
    expect(c.game.snapshot).toBe(before);
  });

  it("restores a partial batch and the prefix immediately before initial-hand readiness", async () => {
    const c = await context({}, undefined, false);
    let count = 0;
    for (let step = 0; step < 4; step += 1) {
      for (let seat = 0; seat < 4; seat += 1) {
        if (seat === c.f.plans[step]!.to) continue;
        const artifact = await append(c, seat, c.f.deal(step, seat).envelope);
        await c.game.receive(artifact);
        count += 1;
        if (count !== 2 && count !== 11) continue;
        const recovered = PersistentSaskuRoundReceiver.recover(c.options);
        expect(recovered.snapshot).toEqual(c.game.snapshot);
        expect(recovered.snapshot.ledger.deal?.pendingSenders).toEqual(count === 2 ? [3] : [2]);
        for (let owner = 0; owner < 4; owner += 1) {
          expect(recovered.readPrivateHand(c.f.roster[owner]!, c.f.secrets[owner]!)).toBeNull();
        }
        if (count === 11) {
          const last = await recovered.authorDealShares(c.authors[2]!, c.f.secrets[2]!, recovered.snapshot, c.f.source);
          await c.game.receive(last.received);
          expect(recovered.snapshot).toEqual(c.game.snapshot);
          expect(recovered.snapshot.ledger.deal).toBeNull();
          return;
        }
      }
    }
    throw new Error("Did not reach the last initial-deal contribution");
  });

  it("merges sender-grouped full-deal history deterministically and restores private hands", async () => {
    const c = await context({}, undefined, false);
    const messages: EnvelopeArtifact[] = [];
    for (const seat of [3, 2, 1, 0]) {
      for (let step = 0; step < 4; step += 1) {
        if (seat !== c.f.plans[step]!.to) messages.push(await append(c, seat, c.f.deal(step, seat).envelope));
      }
    }
    for (let step = 0; step < 4; step += 1) {
      for (const message of messages.filter(({ envelope }) => envelope.phase === `round.${c.f.round}.deal.${step}`)) {
        await c.game.receive(message);
      }
    }
    const commit = vi.spyOn(RoundRevealLedger.prototype, "commit");
    const recovered = PersistentSaskuRoundReceiver.recover(c.options);
    expect(commit.mock.calls.map(([artifact]) => [artifact.envelope.phase, c.session.seatOf(artifact.envelope.from)]))
      .toEqual(c.f.plans.flatMap((plan, step) => [0, 1, 2, 3].filter((seat) => seat !== plan.to)
        .map((seat) => [`round.${c.f.round}.deal.${step}`, seat])));
    expect(recovered.snapshot).toEqual(c.game.snapshot);
    expect(recovered.snapshot.ledger).toMatchObject({ dealIndex: 4, actionIndex: 0, deal: null, revealed: {} });
    for (let seat = 0; seat < 4; seat += 1) {
      expect(recovered.readPrivateHand(c.f.roster[seat]!, c.f.secrets[seat]!))
        .toEqual(c.game.readPrivateHand(c.f.roster[seat]!, c.f.secrets[seat]!));
      expect(Object.keys(recovered.readPrivateHand(c.f.roster[seat]!, c.f.secrets[seat]!)!.remaining)).toHaveLength(9);
    }
  });

  it("replays partial play with zero I/O, authoring, key reads or protocol RNG, then continues on the live binding", async () => {
    const c = await context();
    const opening = await act(c, 0, { type: "diamonds" });
    const play = await act(c, 0, { type: "play", position: 0 });
    const before = c.game.snapshot;
    const records = c.store.artifacts();
    const heads = c.session.heads();
    const forbidden = () => { throw new Error("Recovery must be synchronous and read-only"); };
    const spies = [
      vi.spyOn(PersistentSaskuRoundReceiver.prototype, "receive").mockImplementation(forbidden),
      vi.spyOn(PersistentSessionReceiver.prototype, "receive").mockImplementation(forbidden),
      vi.spyOn(c.session, "ingest").mockImplementation(forbidden),
      vi.spyOn(c.options.setup, "ingest").mockImplementation(forbidden),
      vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementation(forbidden),
      vi.spyOn(c.store, "appendNext").mockImplementation(forbidden),
      vi.spyOn(c.store, "head").mockImplementation(forbidden),
      vi.spyOn(c.store, "artifacts").mockImplementation(forbidden),
      vi.spyOn(PersistentEnvelopeAuthor.prototype, "author").mockImplementation(forbidden),
      vi.spyOn(protocol, "signEnvelope").mockImplementation(forbidden),
      vi.spyOn(deck, "createProvenDecryptionShare").mockImplementation(forbidden),
      vi.spyOn(deck, "createGameKeyShare").mockImplementation(forbidden),
      vi.spyOn(RoundRevealLedger.prototype, "readPrivateHand").mockImplementation(forbidden),
      vi.spyOn(RoundRevealLedger.prototype, "createActionShare").mockImplementation(forbidden),
      vi.spyOn(RoundRevealLedger.prototype, "createDealShares").mockImplementation(forbidden),
      // Verification may blind inside the crypto library; protocol randomness must remain unused.
      vi.spyOn(protocolRandom, "randomBytes").mockImplementation(forbidden),
      vi.spyOn(c.f.source, "fill").mockImplementation(forbidden),
    ];
    const recovered = PersistentSaskuRoundReceiver.recover(c.options);
    expect(recovered.snapshot).toEqual(before);
    expect(c.game.snapshot).toBe(before);
    for (const spy of spies) { expect(spy).not.toHaveBeenCalled(); spy.mockRestore(); }
    expect(c.store.artifacts()).toEqual(records);
    expect(c.session.heads()).toEqual(heads);

    const stable = recovered.snapshot;
    for (const original of [play.received, ...c.deals.slice().reverse(), opening.received, play.received]) {
      await expect(recovered.receive(original)).resolves.toMatchObject({ status: "duplicate", chainStatus: "duplicate", persistenceStatus: "duplicate" });
      expect(recovered.snapshot).toBe(stable);
    }
    const author = c.authors[1]!;
    const head = c.store.head(c.f.gameId, author.sender)!;
    const continued = await recovered.authorAction(author, c.f.secrets[1]!, stable, { type: "play", position: 9 }, c.f.source);
    expect(continued).toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "duplicate" });
    expect(continued.received.envelope).toMatchObject({ seq: head.envelope.seq + 1, prev: head.hash, phase: stable.ledger.phase });
    expect(c.session.classify(continued.received).status).toBe("duplicate");
    expect(c.game.snapshot).toBe(before);
    await c.game.receive(continued.received);
    expect(recovered.snapshot).toEqual(c.game.snapshot);
    expect(PersistentSaskuRoundReceiver.recover(c.options).snapshot).toEqual(c.game.snapshot);
    expect(recovered.readPrivateHand(author.sender, c.f.secrets[1]!)!.remaining).not.toHaveProperty("9");
  }, 15_000);

  it("never sorts a sender's valid deal-1 proofs ahead of its earlier deal-0 prerequisite", async () => {
    const c = await context({}, undefined, false);
    const later = await append(c, 2, c.f.deal(1, 2).envelope);
    const earlier = await append(c, 2, c.f.deal(0, 2).envelope);
    for (const artifact of [later, earlier]) {
      for (const item of decodeSharesBody(artifact.envelope.body).items) {
        expect(verifyProvenDecryptionShare(
          { gameId: c.f.gameId, round: c.f.round, phase: artifact.envelope.phase }, item.pos,
          c.f.setup.publicKeyAt(2)!, c.f.deck[item.pos]!.A, item,
        )).toBe(true);
      }
    }
    for (const [step, seat] of [[0, 1], [0, 3], [1, 0], [1, 3]] as const) {
      await append(c, seat, c.f.deal(step, seat).envelope);
    }
    expect(earlier.envelope).toMatchObject({ seq: later.envelope.seq + 1, prev: later.hash });
    expect(() => PersistentSaskuRoundReceiver.recover(c.options)).toThrow(SaskuRoundRecoveryError);
    expect(c.game.snapshot.ledger.dealIndex).toBe(0);
    expect(c.game.failure).toBeNull();
  });

  it("never skips a sender's play-1 to recover its later-authored play-0 diamonds action", async () => {
    const c = await context();
    const play = await append(c, 0, c.f.action(0, [0], 1).envelope);
    const opening = await append(c, 0, c.f.action(0, [], 0, "diamonds").envelope);
    const share = deck.decodeActionBody(play.envelope.body).shares[0]!;
    expect(verifyProvenDecryptionShare(
      { gameId: c.f.gameId, round: c.f.round, phase: play.envelope.phase }, 0, c.f.setup.publicKeyAt(0)!, c.f.deck[0]!.A, share,
    )).toBe(true);
    expect(opening.envelope).toMatchObject({ seq: play.envelope.seq + 1, prev: play.hash });
    expect(() => PersistentSaskuRoundReceiver.recover(c.options)).toThrow(SaskuRoundRecoveryError);
    expect(c.game.snapshot.history).toEqual([]);
  });

  it("rejects deal phase aliases, gaps and selected messages of the wrong type", async () => {
    for (const changes of [
      { phase: "round.02.deal.0" }, { phase: "round.2.deal.00" }, { phase: "round.2.deal.1" },
      { phase: "round.2.deal.-1" }, { phase: "round.2.deal.9007199254740992" },
      { type: "ACTION" }, { type: "AUDIT_DISCLOSE" },
    ] as const) {
      const c = await context({}, undefined, false);
      await append(c, 1, { ...c.f.deal(0, 1).envelope, ...changes });
      expect(() => PersistentSaskuRoundReceiver.recover(c.options), JSON.stringify(changes)).toThrow(SaskuRoundRecoveryError);
    }
  });

  it("revalidates deal body shape, donor, recipient, positions and DLEQ proofs", async () => {
    for (const mode of ["body", "recipient", "positions", "donor", "proof"]) {
      const c = await context({}, undefined, false);
      const seat = mode === "donor" ? 0 : 1;
      const fixture = c.f.deal(0, seat).envelope;
      const body = decodeSharesBody(fixture.body);
      const changes = mode === "body" ? {}
        : mode === "recipient" ? encodeSharesBody({ ...body, to: 2 })
        : mode === "positions" ? encodeSharesBody({ ...body, items: body.items.slice(1) })
        : mode === "proof" ? encodeSharesBody({ ...body, items: body.items.map((item, index) => index === 0
          ? { ...item, S: item.S.add(RistrettoPoint.base()) } : item) })
        : fixture.body;
      await append(c, seat, { ...fixture, body: changes });
      expect(() => PersistentSaskuRoundReceiver.recover(c.options), mode).toThrow(expect.objectContaining({
        name: "SaskuRoundRecoveryError", cause: expect.objectContaining({ code: mode === "body" ? "malformed_body" : mode === "recipient" ? "wrong_recipient"
          : mode === "positions" ? "wrong_positions" : mode === "donor" ? "unexpected_sender" : "invalid_share_proof" }),
      }));
    }
  });

  it("rejects a fresh envelope repeating a contribution without mutating the bound receiver or store", async () => {
    const c = await context({}, undefined, false);
    const first = await append(c, 1, c.f.deal(0, 1).envelope);
    await c.game.receive(first);
    const repeated = await append(c, 1, first.envelope);
    expect(repeated.hash).not.toEqual(first.hash);
    const before = c.game.snapshot;
    const heads = c.session.heads();
    const records = c.store.artifacts();
    const forbidden = () => { throw new Error("Failure must not write or receive"); };
    const spies = [
      vi.spyOn(c.session, "ingest").mockImplementation(forbidden),
      vi.spyOn(c.durable, "receive").mockImplementation(forbidden),
      vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementation(forbidden),
      vi.spyOn(c.store, "appendNext").mockImplementation(forbidden),
    ];
    expect(() => PersistentSaskuRoundReceiver.recover(c.options)).toThrow(expect.objectContaining({
      name: "SaskuRoundRecoveryError", cause: expect.objectContaining({ code: "conflicting_contribution" }),
    }));
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
    expect(c.game.snapshot).toBe(before);
    expect(c.game).toMatchObject({ closed: false, failure: null, pendingBytes: 0, pendingEnvelopes: 0 });
    expect(c.session.heads()).toEqual(heads);
    expect(c.store.artifacts()).toEqual(records);
  });

  it("allows an incomplete semantic prefix only when no later selected traffic remains", async () => {
    const c = await context({}, undefined, false);
    const first = await append(c, 1, c.f.deal(0, 1).envelope);
    await c.game.receive(first);
    expect(PersistentSaskuRoundReceiver.recover(c.options).snapshot).toEqual(c.game.snapshot);
    await append(c, 0, c.f.action(0, [], 0, "diamonds").envelope);
    expect(() => PersistentSaskuRoundReceiver.recover(c.options)).toThrow(SaskuRoundRecoveryError);
    expect(c.game.snapshot.ledger.deal?.pendingSenders).toEqual([2, 3]);
  });

  it("rejects action aliases, counters, wrong types, off-turn actions and public rule violations", async () => {
    const base = await context();
    for (const [seat, changes] of [
      [0, { phase: "round.2.play.00" }], [0, { phase: "round.2.play.1" }],
      [0, { type: "SHARES" }], [1, {}],
      [0, { body: encodeActionBody({ kind: "choose_trump", data: { suit: "clubs" }, reveal: [], shares: [] }) }],
      [0, { body: { kind: "diamonds", data: {}, reveal: [], shares: [], extra: true } }],
    ] as const) {
      const c = await context({}, undefined, false);
      for (const message of base.deals) await append(c, c.session.seatOf(message.envelope.from)!, message.envelope);
      await append(c, seat, { round: c.f.round, phase: "round.2.play.0", type: "ACTION",
        body: encodeActionBody({ kind: "diamonds", data: {}, reveal: [], shares: [] }), ...changes });
      expect(() => PersistentSaskuRoundReceiver.recover(c.options), JSON.stringify(changes)).toThrow(SaskuRoundRecoveryError);
    }
  }, 15_000);

  it("rechecks action ownership and proof context instead of trusting chain-valid card reveals", async () => {
    const base = await context();
    for (const mode of ["owner", "proof", "public rule"]) {
      const c = await context({}, undefined, false);
      for (const message of base.deals) await append(c, c.session.seatOf(message.envelope.from)!, message.envelope);
      await append(c, 0, c.f.action(0, [], 0, "diamonds").envelope);
      const fixture = c.f.action(0, [mode === "owner" ? 9 : 0], mode === "proof" ? 2 : 1).envelope;
      await append(c, 0, { ...fixture, phase: "round.2.play.1", ...(mode === "public rule"
        ? { body: encodeActionBody({ kind: "pass", data: {}, reveal: [], shares: [] }) } : {}) });
      expect(() => PersistentSaskuRoundReceiver.recover(c.options), mode).toThrow(expect.objectContaining({
        name: "SaskuRoundRecoveryError", cause: mode === "public rule" ? expect.any(SaskuHandError)
          : expect.objectContaining({ code: mode === "owner" ? "wrong_owner" : "invalid_share_proof" }),
      }));
    }
  }, 15_000);

  it("rejects other-round SHARES, ACTION, AUDIT_DISCLOSE and SHUFFLE rather than dropping them", async () => {
    for (const type of ["SHARES", "ACTION", "AUDIT_DISCLOSE", "SHUFFLE"] as const) {
      for (const round of [1, 3]) {
        const c = await context({}, undefined, false);
        await append(c, 0, { round, phase: `round.${round}.play.0`, type, body: {} });
        expect(() => PersistentSaskuRoundReceiver.recover(c.options), `${type}:${round}`).toThrow(SaskuRoundRecoveryError);
      }
    }
  });

  it("ignores explicit lobby/housekeeping bodies and current-round shuffle provenance, including nested SYNC traffic", async () => {
    const c = await context({}, undefined, false);
    const nested = c.f.action(0, [], 20, "diamonds");
    for (const type of ["JOIN", "ROSTER", "READY", "WITNESS", "SYNC_REQ", "SYNC_RESP", "TIMEOUT_VOTE", "VIOLATION", "SHUFFLE"] as const) {
      await append(c, 0, { round: type === "SHUFFLE" ? c.f.round : 99, phase: "external.prerequisite", type,
        body: type === "SYNC_RESP" ? { envelopes: [nested.canonicalBytes, new Uint8Array([0xff])] } : { deliberately: "not a valid control body" } });
    }
    const contribution = await append(c, 1, c.f.deal(0, 1).envelope);
    await c.game.receive(contribution);
    expect(PersistentSaskuRoundReceiver.recover(c.options).snapshot).toEqual(c.game.snapshot);
    expect(c.session.classify(nested).status).not.toBe("duplicate");
  });

  it("charges exact envelope limits for setup and ignored control traffic before allocating ranges", async () => {
    const c = await context({}, undefined, false);
    await append(c, 0, { round: 99, phase: "control", type: "WITNESS", body: {} });
    const count = c.store.artifacts().length;
    expect(count).toBe(13);
    expect(DEFAULT_MAX_SASKU_RECOVERY_ENVELOPES).toBe(1024);
    expect(PersistentSaskuRoundReceiver.recover(c.options, { maxEnvelopes: count }).snapshot).toEqual(c.game.snapshot);
    const range = vi.spyOn(c.session, "readRange");
    expect(() => PersistentSaskuRoundReceiver.recover(c.options, { maxEnvelopes: count - 1 })).toThrow(SaskuRoundRecoveryError);
    expect(range).not.toHaveBeenCalled();
    const heads = c.session.heads();
    vi.spyOn(c.session, "heads").mockReturnValue(heads.map((head, seat) => seat === 3 ? { ...head, seq: 1024 } : head));
    expect(() => PersistentSaskuRoundReceiver.recover(c.options)).toThrow(SaskuRoundRecoveryError);
    expect(range).not.toHaveBeenCalled();
  });

  it("charges exact byte limits across every prefix, including ignored control payloads", async () => {
    const c = await context({}, undefined, false);
    const control = await append(c, 0, { round: 99, phase: "control", type: "SYNC_RESP", body: { padding: new Uint8Array(4096) } });
    const bytes = c.store.artifacts().reduce((sum, { artifact }) => sum + artifact.canonicalBytes.length, 0);
    expect(DEFAULT_MAX_SASKU_RECOVERY_BYTES).toBe(16 * 1024 * 1024);
    expect(PersistentSaskuRoundReceiver.recover(c.options, { maxBytes: bytes }).snapshot).toEqual(c.game.snapshot);
    for (const maxBytes of [bytes - 1, bytes - control.canonicalBytes.length]) {
      expect(() => PersistentSaskuRoundReceiver.recover(c.options, { maxBytes })).toThrow(SaskuRoundRecoveryError);
    }
  });

  it("rejects oversized and non-plain raw views before copying or decoding them", async () => {
    const c = await context({}, undefined, false);
    const range = c.session.readRange(c.f.roster[0]!, 0, 2);
    if (range.status !== "complete") throw new Error("Missing test prefix");
    class ByteSubclass extends Uint8Array {}
    const oversized = Object.defineProperty(new Uint8Array(1), "length", { value: DEFAULT_MAX_SASKU_RECOVERY_BYTES + 1 });
    const read = vi.spyOn(c.session, "readRange");
    const decode = vi.spyOn(protocol, "decodeAndVerifyEnvelope");
    const copy = vi.spyOn(Uint8Array.prototype, "set");
    for (const source of [oversized, new Uint8Array(), new ByteSubclass(1), new Uint16Array(1), null]) {
      read.mockReturnValueOnce({ status: "complete", envelopes: [{ ...range.envelopes[0]!, canonicalBytes: source }, ...range.envelopes.slice(1)] } as never);
      expect(() => PersistentSaskuRoundReceiver.recover(c.options)).toThrow(SaskuRoundRecoveryError);
      expect(copy.mock.calls.some(([argument]) => argument === source)).toBe(false);
      expect(decode).not.toHaveBeenCalled();
    }
    vi.restoreAllMocks();
    const body = { padding: new Uint8Array(MAX_ROUND_REVEAL_ENVELOPE_BYTES) };
    const control = await append(c, 0, { round: 99, phase: "control", type: "WITNESS", body });
    expect(control.canonicalBytes.length).toBeGreaterThan(MAX_ROUND_REVEAL_ENVELOPE_BYTES);
    expect(PersistentSaskuRoundReceiver.recover(c.options).snapshot).toEqual(c.game.snapshot);
    await append(c, 1, { round: c.f.round, phase: c.game.snapshot.ledger.phase, type: "SHARES", body });
    expect(() => PersistentSaskuRoundReceiver.recover(c.options)).toThrow(SaskuRoundRecoveryError);
  });

  it("preserves constructor errors for bad options and TypeError/RangeError for invalid limits", async () => {
    const c = await context({}, undefined, false);
    const other = new SessionChainRegistry(c.f.gameId, c.f.roster);
    for (const options of [null, undefined, { ...c.options, session: other }, { ...c.options, setup: new SetupEnvelopeCoordinator(c.f.gameId, 0, c.f.roster) }]) {
      expect(() => PersistentSaskuRoundReceiver.recover(options as PersistentSaskuRoundOptions)).toThrow(TypeError);
    }
    expect(() => PersistentSaskuRoundReceiver.recover({ ...c.options, dealer: 4 as never })).toThrow(SaskuHandError);
    for (const changes of [{ round: -0 }, { schedule: [{ to: 0, count: 9 }] }, { maxPendingBytes: 0 }]) {
      expect(() => PersistentSaskuRoundReceiver.recover({ ...c.options, ...changes } as PersistentSaskuRoundOptions)).toThrow(RangeError);
    }
    const range = vi.spyOn(c.session, "readRange");
    for (const limits of [null, 1, "limits", true]) {
      expect(() => PersistentSaskuRoundReceiver.recover(c.options, limits as SaskuRoundRecoveryLimits)).toThrow(TypeError);
    }
    for (const key of ["maxEnvelopes", "maxBytes"]) {
      for (const value of [0, -0, -1, 0.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1, "12", null]) {
        expect(() => PersistentSaskuRoundReceiver.recover(c.options, { [key]: value } as SaskuRoundRecoveryLimits)).toThrow(RangeError);
      }
    }
    expect(range).not.toHaveBeenCalled();
  });

  it("requires all four ordered, valid heads and complete exact-length prefix ranges", async () => {
    const c = await context({}, undefined, false);
    const heads = c.session.heads();
    const headSpy = vi.spyOn(c.session, "heads");
    const read = vi.spyOn(c.session, "readRange");
    for (const bad of [[], heads.slice(1), [...heads].reverse(), [...heads, heads[0]],
      ...[-1, -0, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1].map((seq) => [{ ...heads[0]!, seq }, ...heads.slice(1)]),
      [{ ...heads[0]!, hash: new Uint8Array(31) }, ...heads.slice(1)],
    ]) {
      headSpy.mockReturnValueOnce(bad as never);
      expect(() => PersistentSaskuRoundReceiver.recover(c.options)).toThrow(SaskuRoundRecoveryError);
      expect(read).not.toHaveBeenCalled();
    }
    const valid = c.session.readRange(c.f.roster[0]!, 0, 2);
    if (valid.status !== "complete") throw new Error("Missing test prefix");
    for (const bad of [null, { status: "missing", firstMissingSeq: 1 }, { status: "unknown_sender" },
      { status: "COMPLETE", envelopes: valid.envelopes }, { status: "complete", envelopes: {} },
      { status: "complete", envelopes: valid.envelopes.slice(1) },
      { status: "complete", envelopes: [...valid.envelopes, valid.envelopes[0]] },
      { status: "complete", envelopes: [undefined, ...valid.envelopes.slice(1)] },
    ]) {
      read.mockReturnValueOnce(bad as never);
      expect(() => PersistentSaskuRoundReceiver.recover(c.options)).toThrow(SaskuRoundRecoveryError);
    }
  });

  it("reverifies ignored records' signatures and canonical encoding rather than trusting cached decoded views", async () => {
    const c = await context({}, undefined, false);
    const control = await append(c, 0, { round: 99, phase: "control", type: "WITNESS", body: {} });
    const prefix = c.session.readRange(c.f.roster[0]!, 0, 3);
    if (prefix.status !== "complete") throw new Error("Missing test prefix");
    expect(control.canonicalBytes[0]).toBe(0xaa);
    const badSignature = encodeCanonical({ ...control.envelope, sig: new Uint8Array(64) });
    // Same signed values, but a non-minimal CBOR map length is not canonical wire history.
    const noncanonical = new Uint8Array([0xb8, 0x0a, ...control.canonicalBytes.slice(1)]);
    const read = vi.spyOn(c.session, "readRange");
    for (const canonicalBytes of [badSignature, noncanonical, new Uint8Array([0xff])]) {
      read.mockReturnValueOnce({ status: "complete", envelopes: [...prefix.envelopes.slice(0, -1), { ...control, canonicalBytes } as EnvelopeArtifact] });
      expect(() => PersistentSaskuRoundReceiver.recover(c.options)).toThrow(expect.objectContaining({
        name: "SaskuRoundRecoveryError", cause: expect.any(Error),
      }));
    }
  });

  it("detects corrupt cached hashes, mismatched head hashes and non-duplicate cache statuses", async () => {
    const c = await context({}, undefined, false);
    const heads = c.session.heads();
    const headSpy = vi.spyOn(c.session, "heads").mockReturnValueOnce(heads.map((head, seat) => seat === 0
      ? { ...head, hash: parseHash256(new Uint8Array(32).fill(0xaa)) } : head));
    expect(() => PersistentSaskuRoundReceiver.recover(c.options)).toThrow(SaskuRoundRecoveryError);
    headSpy.mockRestore();
    const nativeClassify = c.session.classify.bind(c.session);
    const classify = vi.spyOn(c.session, "classify");
    for (const status of ["accepted", "rejected", "DUPLICATE", undefined]) {
      classify.mockReturnValueOnce({ status } as never);
      expect(() => PersistentSaskuRoundReceiver.recover(c.options)).toThrow(SaskuRoundRecoveryError);
    }
    for (const failAt of [13, 25]) {
      let calls = 0;
      classify.mockImplementation((received) => {
        calls += 1;
        return calls === failAt ? { status: "accepted" } as never : nativeClassify(received);
      });
      expect(() => PersistentSaskuRoundReceiver.recover(c.options)).toThrow(SaskuRoundRecoveryError);
      expect(calls).toBe(failAt);
    }
    classify.mockRestore();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (artifact) => {
      const result = await persist(artifact);
      artifact.hash.fill(0xee);
      return result;
    });
    const control = await append(c, 0, { round: 99, phase: "control", type: "WITNESS", body: {} });
    expect(c.session.classify(control)).toMatchObject({ status: "rejected", reason: "equivocation" });
    expect(() => PersistentSaskuRoundReceiver.recover(c.options)).toThrow(SaskuRoundRecoveryError);
  });

  it("checks signed sequence, predecessor, game and sender independently of a cache's duplicate claim", async () => {
    const c = await context({}, undefined, false);
    const control = await append(c, 0, { round: 99, phase: "control", type: "WITNESS", body: {} });
    const prefix = c.session.readRange(c.f.roster[0]!, 0, 3);
    if (prefix.status !== "complete") throw new Error("Missing test prefix");
    const read = vi.spyOn(c.session, "readRange");
    const changes: Partial<UnsignedEnvelope>[] = [
      { seq: 2 }, { seq: 4 }, { prev: parseHash256(new Uint8Array(32)) },
      { game: parseGameId(new Uint8Array(16).fill(7)) }, { from: c.f.roster[1]! },
    ];
    for (const change of changes) {
      const forged = signEnvelope({ ...control.envelope, ...change }, c.f.identities[change.from === undefined ? 0 : 1]!.secretKey);
      expect(decodeAndVerifyEnvelope(forged.canonicalBytes)).toEqual(forged);
      read.mockReturnValueOnce({ status: "complete", envelopes: [...prefix.envelopes.slice(0, -1), forged] });
      const classify = vi.spyOn(c.session, "classify").mockImplementation((received) => ({ status: "duplicate", existing: received, received }));
      expect(() => PersistentSaskuRoundReceiver.recover(c.options)).toThrow(SaskuRoundRecoveryError);
      classify.mockRestore();
    }
  });

  it("ignores mutable decoded bodies, headers and artifact hashes when original canonical bytes are intact", async () => {
    const c = await context();
    await act(c, 0, { type: "diamonds" });
    const read = c.session.readRange.bind(c.session);
    vi.spyOn(c.session, "readRange").mockImplementation((...args) => {
      const result = read(...args);
      if (result.status !== "complete") return result;
      return { status: "complete", envelopes: result.envelopes.map((artifact) => ({ ...artifact,
        hash: parseHash256(new Uint8Array(32).fill(0xff)),
        envelope: { ...artifact.envelope, from: c.f.identities[4]!.publicKey, seq: 999, round: 999,
          phase: "forged.view", type: "AUDIT_DISCLOSE", body: { result: "valid" } },
      })) };
    });
    expect(PersistentSaskuRoundReceiver.recover(c.options).snapshot).toEqual(c.game.snapshot);
  });

  it("isolates private replay history from classify-argument mutation on every stability pass", async () => {
    const c = await context();
    await act(c, 0, { type: "diamonds" });
    const classify = c.session.classify.bind(c.session);
    const spy = vi.spyOn(c.session, "classify").mockImplementation((argument) => {
      const result = classify(argument);
      argument.canonicalBytes.fill(0xff);
      argument.hash.fill(0xee);
      argument.envelope.from.fill(0xdd);
      (argument.envelope.body as Record<string, unknown>)["items"] = [];
      (argument.envelope.body as Record<string, unknown>)["kind"] = "pass";
      return result;
    });
    expect(PersistentSaskuRoundReceiver.recover(c.options).snapshot).toEqual(c.game.snapshot);
    expect(spy).toHaveBeenCalledTimes(c.store.artifacts().length * 3);
  });

  it.each(["classify", "commit"] as const)("regression: protects recovery from a ledger %s argument's valid sender substitution", async (method) => {
    const c = await context({}, undefined, false);
    const recorded = await append(c, 1, c.f.deal(0, 1).envelope);
    await c.game.receive(recorded);
    const { round, phase, type, body } = c.f.deal(0, 2).envelope;
    // This valid alternative is authored, but seat 2's accepted chain still ends at setup.
    const alternate = await c.authors[2]!.author({ round, phase, type, body });
    expect(alternate.canonicalBytes.length).toBe(recorded.canonicalBytes.length);
    expect(c.f.ledger.classify(alternate)).toMatchObject({ status: "accepted", type: "SHARES", seat: 2 });
    expect(c.session.classify(alternate).status).toBe("accepted");
    expect(c.session.heads()[2]!.seq).toBe(2);
    const before = c.game.snapshot;
    const heads = c.session.heads();
    const records = c.store.artifacts();
    const writes = [vi.spyOn(c.durable, "receive"), vi.spyOn(c.session, "ingest"),
      vi.spyOn(c.store, "appendNext"), vi.spyOn(c.store, "persistAcceptedEnvelope")];
    const native = RoundRevealLedger.prototype[method];
    const substituted = vi.spyOn(RoundRevealLedger.prototype, method).mockImplementationOnce(function (this: RoundRevealLedger, argument, expectedSeat) {
      expect(argument.canonicalBytes).toEqual(recorded.canonicalBytes);
      if (method === "commit") {
        argument.canonicalBytes.set(alternate.canonicalBytes);
        return native.call(this, argument, expectedSeat);
      }
      const result = native.call(this, argument, expectedSeat);
      expect(result).toMatchObject({ status: "accepted", seat: 1 });
      argument.canonicalBytes.set(alternate.canonicalBytes);
      return result;
    });
    let recovered: PersistentSaskuRoundReceiver | undefined;
    let failure: unknown;
    try { recovered = PersistentSaskuRoundReceiver.recover(c.options); }
    catch (cause) { failure = cause; }
    expect(substituted).toHaveBeenCalledOnce();
    for (const write of writes) expect(write).not.toHaveBeenCalled();
    expect(c.session.heads()).toEqual(heads);
    expect(c.store.artifacts()).toEqual(records);
    expect(c.session.readRange(recorded.envelope.from, recorded.envelope.seq, recorded.envelope.seq))
      .toEqual({ status: "complete", envelopes: [recorded] });
    expect(c.game.snapshot).toBe(before);
    expect(c.game).toMatchObject({ closed: false, failure: null, pendingEnvelopes: 0, pendingBytes: 0 });
    if (method === "classify") {
      expect(failure).toBeUndefined();
      expect(recovered?.snapshot.ledger.deal?.pendingSenders).toEqual([2, 3]);
      expect(recovered?.snapshot).toEqual(before);
    } else {
      expect(failure).toBeInstanceOf(SaskuRoundRecoveryError);
      expect(recovered).toBeUndefined();
    }
  });

  it("rejects raw-byte mutation during capture and after semantic replay has started", async () => {
    for (const timing of ["capture", "replay"]) {
      const c = await context({}, undefined, false);
      await append(c, 1, c.f.deal(0, 1).envelope);
      const prefix = c.session.readRange(c.f.roster[0]!, 0, 2);
      if (prefix.status !== "complete") throw new Error("Missing test prefix");
      const source = prefix.envelopes[0]!.canonicalBytes;
      const before = c.game.snapshot;
      if (timing === "capture") {
        const read = c.session.readRange.bind(c.session);
        vi.spyOn(c.session, "readRange").mockImplementation((...args) => {
          const result = read(...args);
          if (bytesEqual(args[0], c.f.roster[3]!)) source.fill(0xff);
          return result;
        });
      } else {
        const commit = RoundRevealLedger.prototype.commit;
        vi.spyOn(RoundRevealLedger.prototype, "commit").mockImplementationOnce(function (this: RoundRevealLedger, ...args) {
          const result = commit.apply(this, args);
          source.fill(0xff);
          return result;
        });
      }
      expect(() => PersistentSaskuRoundReceiver.recover(c.options), timing).toThrow(SaskuRoundRecoveryError);
      expect(c.game.snapshot).toBe(before);
      expect(c.game.failure).toBeNull();
      vi.restoreAllMocks();
    }
  });

  it("rejects changed captured heads and real head appends during capture or final replay", async () => {
    for (const mode of ["captured head", "append during capture", "append during replay"]) {
      const c = await context({}, undefined, false);
      await append(c, 1, c.f.deal(0, 1).envelope);
      const ahead = await c.author.author({ round: 99, phase: "control", type: "WITNESS", body: {} });
      const before = c.game.snapshot;
      const captured = c.session.heads().map((head) => ({ ...head }));
      if (mode === "captured head") vi.spyOn(c.session, "heads").mockReturnValueOnce(captured);
      const change = () => {
        if (mode === "captured head") captured[0]!.hash.fill(0xaa);
        else expect(c.session.ingest(ahead).status).toBe("accepted");
      };
      if (mode === "append during replay") {
        const commit = RoundRevealLedger.prototype.commit;
        vi.spyOn(RoundRevealLedger.prototype, "commit").mockImplementationOnce(function (this: RoundRevealLedger, ...args) {
          const result = commit.apply(this, args);
          change();
          return result;
        });
      } else {
        const read = c.session.readRange.bind(c.session);
        vi.spyOn(c.session, "readRange").mockImplementation((...args) => {
          const result = read(...args);
          if (bytesEqual(args[0], c.f.roster[3]!)) change();
          return result;
        });
      }
      expect(() => PersistentSaskuRoundReceiver.recover(c.options), mode).toThrow(SaskuRoundRecoveryError);
      expect(c.game.snapshot).toBe(before);
      expect(c.game).toMatchObject({ closed: false, failure: null });
      vi.restoreAllMocks();
    }
  });

  it("binds supplied completed setup to the recorded seed, aggregate and individual seat keys", async () => {
    const c = await context({}, undefined, false);
    for (const mode of ["seed", "aggregate", "swapped keys"]) {
      const setup = new SetupEnvelopeCoordinator(c.f.gameId, 0, c.f.roster);
      for (let seat = 0; seat < 4; seat += 1) {
        const secret = mode === "aggregate" && seat === 0 ? scalarFromBigInt(7n)
          : c.f.secrets[mode === "swapped keys" && seat < 2 ? 1 - seat : seat]!;
        const body = deck.encodeGameKeyShareBody(deck.createGameKeyShare({ gameId: c.f.gameId, round: 0, phase: "setup.keys" }, secret, c.f.source));
        expect(setup.ingest(await c.authors[seat]!.author({ round: 0, phase: "setup.keys", type: "KEY_SHARE", body })).status).toBe("accepted");
      }
      const secrets = [0, 1, 2, 3].map((seat) => protocol.parseRandomSecret(new Uint8Array(32).fill(seat + (mode === "seed" ? 11 : 1))));
      for (let seat = 0; seat < 4; seat += 1) {
        const cm = parseHash256(protocol.beaconCommitment(c.f.gameId, 0, seat, secrets[seat]!));
        expect(setup.ingest(await c.authors[seat]!.author({ round: 0, phase: "setup.rand", type: "RAND_COMMIT", body: protocol.encodeRandCommitBody({ cm }) })).status).toBe("accepted");
      }
      for (let seat = 0; seat < 4; seat += 1) {
        expect(setup.ingest(await c.authors[seat]!.author({ round: 0, phase: "setup.rand", type: "RAND_REVEAL", body: protocol.encodeRandRevealBody({ s: secrets[seat]! }) })).status).toBe("accepted");
      }
      expect(setup.state).toBe("complete");
      expect(setup.aggregateKey!.equals(c.options.setup.aggregateKey!)).toBe(mode !== "aggregate");
      expect(bytesEqual(setup.seed!, c.options.setup.seed!)).toBe(mode !== "seed");
      expect(() => PersistentSaskuRoundReceiver.recover({ ...c.options, setup }), mode).toThrow(SaskuRoundRecoveryError);
    }
  });

  it("regression: binds history to the setup whose keys were copied before a reentrant options replacement", async () => {
    const c = await context({}, undefined, false);
    const recordedSetup = c.options.setup;
    const otherSetup = new SetupEnvelopeCoordinator(c.f.gameId, 0, c.f.roster);
    for (const { artifact } of c.store.artifacts()) {
      const { round, phase, type } = artifact.envelope;
      const seat = c.session.seatOf(artifact.envelope.from)!;
      const body = type === "KEY_SHARE"
        ? deck.encodeGameKeyShareBody(deck.createGameKeyShare({ gameId: c.f.gameId, round, phase }, c.f.secrets[3 - seat]!, c.f.source))
        : artifact.envelope.body;
      expect(otherSetup.ingest(await c.authors[seat]!.author({ round, phase, type, body })).status).toBe("accepted");
    }
    expect(otherSetup.state).toBe("complete");
    expect(otherSetup.seed).toEqual(recordedSetup.seed);
    expect(otherSetup.aggregateKey!.equals(recordedSetup.aggregateKey!)).toBe(true);
    for (let seat = 0; seat < 4; seat += 1) expect(otherSetup.publicKeyAt(seat)!.equals(recordedSetup.publicKeyAt(seat)!)).toBe(false);
    const options = { ...c.options, setup: otherSetup };
    expect(() => PersistentSaskuRoundReceiver.recover(options)).toThrow(SaskuRoundRecoveryError);
    const before = c.game.snapshot;
    const heads = c.session.heads();
    const records = c.store.artifacts();
    const publicKeyAt = otherSetup.publicKeyAt.bind(otherSetup);
    const lookup = vi.spyOn(otherSetup, "publicKeyAt").mockImplementation((seat) => {
      const key = publicKeyAt(seat);
      if (seat === 3) options.setup = recordedSetup;
      return key;
    });
    let recovered: PersistentSaskuRoundReceiver | undefined;
    let failure: unknown;
    try { recovered = PersistentSaskuRoundReceiver.recover(options); }
    catch (cause) { failure = cause; }
    expect(lookup.mock.calls.slice(0, 4).map(([seat]) => seat)).toEqual([0, 1, 2, 3]);
    expect(options.setup).toBe(recordedSetup);
    expect(c.options.setup).toBe(recordedSetup);
    expect(c.session.heads()).toEqual(heads);
    expect(c.store.artifacts()).toEqual(records);
    expect(c.game.snapshot).toBe(before);
    expect(c.game).toMatchObject({ closed: false, failure: null, pendingEnvelopes: 0, pendingBytes: 0 });
    expect(failure).toBeInstanceOf(SaskuRoundRecoveryError);
    expect(recovered).toBeUndefined();
  });

  it("requires actual completed setup and rejects a sender's round traffic before its first RAND_REVEAL", async () => {
    const c = await context({}, undefined, false);
    const session = new SessionChainRegistry(c.f.gameId, c.f.roster);
    const sessionReceiver = new PersistentSessionReceiver(session, c.store);
    for (const { artifact } of c.store.artifacts().filter(({ artifact }) => artifact.envelope.type === "KEY_SHARE")) {
      await expect(sessionReceiver.receive(artifact)).resolves.toMatchObject({ status: "accepted" });
    }
    expect(session.heads()).toHaveLength(4);
    expect(c.options.setup.state).toBe("complete");
    expect(() => PersistentSaskuRoundReceiver.recover({ ...c.options, session, sessionReceiver })).toThrow(SaskuRoundRecoveryError);

    // Rechain one sender with a native author to place valid deal proofs before its reveal.
    const reordered: EnvelopeArtifact[] = [];
    const author = new PersistentEnvelopeAuthor(c.f.gameId, c.f.identities[1]!.secretKey, {
      async appendNext(_game, _sender, create) { reordered.push(create(reordered.at(-1) ?? null)); },
    });
    const ownSetup = c.store.artifacts().map(({ artifact }) => artifact).filter(({ envelope }) => bytesEqual(envelope.from, author.sender));
    for (const content of [ownSetup[0]!.envelope, ownSetup[1]!.envelope, c.f.deal(0, 1).envelope, ownSetup[2]!.envelope]) {
      const { round, phase, type, body } = content;
      await author.author({ round, phase, type, body });
    }
    const restored = new SessionChainRegistry(c.f.gameId, c.f.roster);
    const persisted: EnvelopeArtifact[] = [];
    const durable = new PersistentSessionReceiver(restored, {
      async persistAcceptedEnvelope(artifact) {
        persisted.push(artifact);
        return { status: "stored", record: { artifact } };
      },
    });
    const others = c.store.artifacts().map(({ artifact }) => artifact).filter(({ envelope }) => !bytesEqual(envelope.from, author.sender));
    for (const artifact of [...others, ...reordered]) await expect(durable.receive(artifact)).resolves.toMatchObject({ status: "accepted" });
    expect(persisted).toHaveLength(13);
    expect(restored.heads()).toHaveLength(4);
    expect(protocol.decodeAndVerifyEnvelope(reordered[2]!.canonicalBytes).envelope.type).toBe("SHARES");
    expect(() => PersistentSaskuRoundReceiver.recover({ ...c.options, session: restored, sessionReceiver: durable })).toThrow(SaskuRoundRecoveryError);
  });
});

describe("Sasku complete-hand recovery", () => {
  let completed: Context;
  let roundMessages: readonly EnvelopeArtifact[];

  beforeAll(async () => {
    completed = await context();
    const hand = completed.game.readPrivateHand(completed.author.sender, completed.f.secrets[0]!)!;
    const falseBid = await append(completed, 0, { round: completed.f.round, phase: completed.game.snapshot.ledger.phase, type: "ACTION",
      body: encodeActionBody({ kind: "bid", data: { value: saskuBidStrength(Object.values(hand.dealt)) === 3 ? 4 : 3 }, reveal: [], shares: [] }) });
    await completed.game.receive(falseBid);
    await act(completed, completed.game.snapshot.hand.turn!, { type: "diamonds" });
    for (let play = 0; play < 36; play += 1) {
      const state = completed.game.snapshot;
      const seat = state.hand.turn!;
      const remaining = completed.game.readPrivateHand(completed.authors[seat]!.sender, completed.f.secrets[seat]!)!.remaining;
      const legal = legalSaskuCards(Object.values(remaining), state.hand.trick, "diamonds");
      const [position] = Object.entries(remaining).find(([, card]) => legal.includes(card))!;
      await act(completed, seat, { type: "play", position: Number(position) });
    }
    expect(completed.game.snapshot.hand.phase).toBe("complete");
    roundMessages = completed.store.artifacts().map(({ artifact }) => artifact)
      .filter(({ envelope }) => envelope.type === "SHARES" || envelope.type === "ACTION");
  }, 15_000);

  afterEach(() => vi.restoreAllMocks());

  it("recovers a partial audit, continues disclosures and preserves hidden-rule violation attribution", async () => {
    const c = completed;
    for (const seat of [2, 0]) await c.game.authorAuditDisclose(c.authors[seat]!, c.game.snapshot);
    const recovered = PersistentSaskuRoundReceiver.recover(c.options);
    expect(recovered.snapshot).toEqual(c.game.snapshot);
    expect(recovered.snapshot.audit).toMatchObject({ pendingSenders: [1, 3], result: null });
    for (const seat of [3, 1]) {
      const result = await recovered.authorAuditDisclose(c.authors[seat]!, recovered.snapshot);
      await c.game.receive(result.received);
    }
    expect(recovered.snapshot).toEqual(c.game.snapshot);
    expect(recovered.snapshot.audit).toEqual({ phase: `round.${c.f.round}.audit`, pendingSenders: [],
      result: { status: "violation", seat: 0, at: 0, rule: "bid_strength" } });
    const replay = PersistentSaskuRoundReceiver.recover(c.options);
    expect(replay.snapshot).toEqual(c.game.snapshot);
    const stable = replay.snapshot;
    for (const { artifact } of c.store.artifacts().filter(({ artifact }) => artifact.envelope.type === "AUDIT_DISCLOSE")) {
      await expect(replay.receive(artifact)).resolves.toMatchObject({ status: "duplicate", chainStatus: "duplicate" });
      expect(replay.snapshot).toBe(stable);
    }
  }, 15_000);

  it("rejects an audit authored before that sender's own final action even with every prerequisite present later", async () => {
    const c = await context({}, undefined, false);
    const lastOwnAction = [...roundMessages].reverse().find(({ envelope }) => envelope.type === "ACTION" && bytesEqual(envelope.from, c.f.roster[0]!))!;
    let earlyAudit: EnvelopeArtifact | undefined;
    for (const message of roundMessages) {
      if (message === lastOwnAction) earlyAudit = await append(c, 0, { round: c.f.round, phase: `round.${c.f.round}.audit`,
        type: "AUDIT_DISCLOSE", body: encodeAuditDiscloseBody({ items: [] }) });
      const authored = await append(c, c.session.seatOf(message.envelope.from)!, message.envelope);
      if (message === lastOwnAction) expect(authored.envelope).toMatchObject({ seq: earlyAudit!.envelope.seq + 1, prev: earlyAudit!.hash });
    }
    for (const seat of [1, 2, 3]) await append(c, seat, { round: c.f.round, phase: `round.${c.f.round}.audit`,
      type: "AUDIT_DISCLOSE", body: encodeAuditDiscloseBody({ items: [] }) });
    expect(() => PersistentSaskuRoundReceiver.recover(c.options)).toThrow(SaskuRoundRecoveryError);
    expect(c.game.snapshot.history).toEqual([]);
    expect(c.game.failure).toBeNull();
  }, 15_000);

  it("regression: restores the canonical bid instead of a mutated ledger classification body.data", () => {
    const c = completed;
    const before = c.game.snapshot;
    const bid = before.history[0]!;
    if (bid.type !== "bid") throw new Error("Missing recorded bid");
    const changedValue = bid.value === 3 ? 4 : 3;
    const heads = c.session.heads();
    const records = c.store.artifacts();
    const native = RoundRevealLedger.prototype.classify;
    let mutations = 0;
    vi.spyOn(RoundRevealLedger.prototype, "classify").mockImplementation(function (this: RoundRevealLedger, argument, expectedSeat) {
      const result = native.call(this, argument, expectedSeat);
      if (result.type === "ACTION" && result.body.kind === "bid") {
        expect(result.body.data).toEqual({ value: bid.value });
        (result.body.data as Record<string, unknown>)["value"] = changedValue;
        mutations += 1;
      }
      return result;
    });
    const recovered = PersistentSaskuRoundReceiver.recover(c.options);
    expect(mutations).toBeGreaterThan(0);
    expect(c.session.heads()).toEqual(heads);
    expect(c.store.artifacts()).toEqual(records);
    expect(c.game.snapshot).toBe(before);
    expect(c.game).toMatchObject({ closed: false, failure: null });
    expect(recovered.snapshot.history[0]).toEqual(bid);
    expect(recovered.snapshot).toEqual(before);
  }, 15_000);

  it("regression: does not return partial recovery when a later ledger commit throws after its native mutation", () => {
    const c = completed;
    const before = c.game.snapshot;
    const heads = c.session.heads();
    const records = c.store.artifacts();
    const injected = new Error("Later replay commit failed after mutating the ledger");
    const native = RoundRevealLedger.prototype.commit;
    const commit = vi.spyOn(RoundRevealLedger.prototype, "commit").mockImplementation(function (this: RoundRevealLedger, argument, expectedSeat) {
      const result = native.call(this, argument, expectedSeat);
      if (argument.envelope.phase === `round.${c.f.round}.deal.1`) {
        expect(this.snapshot).toMatchObject({ dealIndex: 1, deal: { pendingSenders: [2, 3] } });
        throw injected;
      }
      return result;
    });
    const close = vi.spyOn(PersistentSaskuRoundReceiver.prototype, "close");
    let recovered: PersistentSaskuRoundReceiver | undefined;
    let failure: unknown;
    try { recovered = PersistentSaskuRoundReceiver.recover(c.options); }
    catch (cause) { failure = cause; }
    expect(commit).toHaveBeenCalledTimes(4);
    expect(close).toHaveBeenCalledOnce();
    expect(close.mock.contexts[0]).not.toBe(c.game);
    expect(close.mock.contexts[0]).toMatchObject({ closed: true });
    expect(c.session.heads()).toEqual(heads);
    expect(c.store.artifacts()).toEqual(records);
    expect(c.game.snapshot).toBe(before);
    expect(c.game).toMatchObject({ closed: false, failure: null, pendingEnvelopes: 0, pendingBytes: 0 });
    expect(failure).toBeInstanceOf(SaskuRoundRecoveryError);
    expect(failure).toMatchObject({ cause: { code: "commit_failed", cause: injected } });
    expect(recovered).toBeUndefined();
  }, 15_000);

  it("regression: does not publish completed replay when the final audit helper throws", async () => {
    const c = completed;
    for (const seat of c.game.snapshot.audit!.pendingSenders) await c.game.authorAuditDisclose(c.authors[seat]!, c.game.snapshot);
    const before = c.game.snapshot;
    const heads = c.session.heads();
    const records = c.store.artifacts();
    const injected = new Error("Final recovery audit failed");
    const commit = vi.spyOn(RoundRevealLedger.prototype, "commit");
    const audit = vi.spyOn(rules, "auditSaskuHand").mockImplementationOnce((_setup, history) => {
      expect(commit).toHaveBeenCalledTimes(roundMessages.length);
      expect(history).toEqual(before.history);
      throw injected;
    });
    const close = vi.spyOn(PersistentSaskuRoundReceiver.prototype, "close");
    let recovered: PersistentSaskuRoundReceiver | undefined;
    let failure: unknown;
    try { recovered = PersistentSaskuRoundReceiver.recover(c.options); }
    catch (cause) { failure = cause; }
    expect(audit).toHaveBeenCalledOnce();
    expect(close).toHaveBeenCalledOnce();
    expect(close.mock.contexts[0]).not.toBe(c.game);
    expect(close.mock.contexts[0]).toMatchObject({ closed: true });
    expect(c.session.heads()).toEqual(heads);
    expect(c.store.artifacts()).toEqual(records);
    expect(c.game.snapshot).toBe(before);
    expect(c.game).toMatchObject({ closed: false, failure: null, pendingEnvelopes: 0, pendingBytes: 0 });
    expect(failure).toBeInstanceOf(SaskuRoundRecoveryError);
    expect(failure).toMatchObject({ cause: { code: "commit_failed", cause: injected } });
    expect(recovered).toBeUndefined();
  }, 15_000);
});
