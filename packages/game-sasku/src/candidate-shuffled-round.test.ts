import { expect, it, vi } from "vitest";
import { createUnprovenDeckShuffle, decodeCandidateShuffleStatement36, encodeCandidateShuffleStatement36, encodeCandidateShuffleProof36 } from "@p2pcards/deck";
import { PersistentCandidateShuffleReceiver } from "@p2pcards/engine";
import { parseHash256 } from "@p2pcards/protocol";
import { PersistentEnvelopeAuthor, PersistentSessionReceiver, SessionChainRegistry } from "@p2pcards/session";
import { SASKU_DECK_SPEC } from "@p2pcards/rules-sasku";
import { roundRevealFixture } from "../../engine/src/round-reveal.test-fixture";
import { MemoryStore, deferred } from "../../engine/src/persistent-setup.test-fixture";
import { recoverCandidateShuffledSaskuRound } from "./candidate-shuffled-round";

async function fixture(count = 4) {
  const f = roundRevealFixture({ seats: 4, deckSpec: SASKU_DECK_SPEC });
  const store = new MemoryStore(), session = new SessionChainRegistry(f.gameId, f.roster);
  const durable = new PersistentSessionReceiver(session, store);
  const authors = f.identities.slice(0, 4).map(i => new PersistentEnvelopeAuthor(f.gameId, i.secretKey, store));
  for (const a of f.setupEnvelopes) {
    const seat = session.seatOf(a.envelope.from)!;
    await durable.receive(await authors[seat]!.author(a.envelope));
  }
  const verifier = { verify: vi.fn(async () => true) };
  const options = { session, sessionReceiver: durable, roster: { gameId: f.gameId, seats: f.roster,
    rulesHash: parseHash256(new Uint8Array(32)), iceConfigHash: parseHash256(new Uint8Array(32)) }, self: f.roster[0]!,
    setupRound: 0, round: f.round, verifier, dealer: 3 as const, schedule: [0, 1, 2, 3].map(to => ({ to, count: 9 })) };
  const shuffle = await PersistentCandidateShuffleReceiver.open({ ...options, deckSpec: SASKU_DECK_SPEC });
  for (let seat = 0; seat < count; seat++) {
    const s = decodeCandidateShuffleStatement36(shuffle.nextStatement());
    const shuffled = createUnprovenDeckShuffle(s.inputDeck, s.aggregateKey, f.source);
    await shuffle.receive(await authors[seat]!.author({ round: f.round, phase: `round.${f.round}.shuffle.${seat}`, type: "SHUFFLE", body: {
      statement: encodeCandidateShuffleStatement36({ ...s, outputDeck: shuffled.outputDeck }),
      proof: encodeCandidateShuffleProof36(Array.from({ length: 106 }, () => new Uint8Array(32))),
    } }));
  }
  shuffle.close();
  return { f, store, session, durable, authors, verifier, options };
}
it("deals the recovered shuffle deck and reconstructs all private hands from durable contributions", async () => {
  const c = await fixture(), game = await recoverCandidateShuffledSaskuRound(c.options);
  while (game.snapshot.ledger.deal !== null) {
    for (const seat of game.snapshot.ledger.deal.pendingSenders) {
      expect((await game.authorDealShares(c.authors[seat]!, c.f.secrets[seat]!, game.snapshot, c.f.source)).status).toBe("accepted");
    }
  }
  const hands = c.f.roster.map((id, seat) => game.readPrivateHand(id, c.f.secrets[seat]!)!);
  expect(hands.map(h => Object.keys(h.dealt).length)).toEqual([9, 9, 9, 9]);
  expect(hands.flatMap(h => Object.values(h.dealt)).sort()).toEqual([...SASKU_DECK_SPEC.cards].sort());
  const write = vi.spyOn(c.store, "persistAcceptedEnvelope"), before = c.verifier.verify.mock.calls.length;
  game.close();
  const restored = await recoverCandidateShuffledSaskuRound(c.options);
  expect(write).not.toHaveBeenCalled(); expect(c.verifier.verify).toHaveBeenCalledTimes(before + 4);
  expect(c.f.roster.map((id, seat) => restored.readPrivateHand(id, c.f.secrets[seat]!))).toEqual(hands);
  restored.close();
}, 30_000);
it("refuses incomplete or invalid shuffle provenance and invalid deal policy", async () => {
  const c = await fixture(3);
  await expect(recoverCandidateShuffledSaskuRound(c.options)).rejects.toThrow(/all four/);
  c.verifier.verify.mockClear();
  await expect(recoverCandidateShuffledSaskuRound({ ...c.options, schedule: [{ to: 0, count: 36 }] })).rejects.toThrow();
  expect(c.verifier.verify).not.toHaveBeenCalled();
  c.verifier.verify.mockResolvedValueOnce(false);
  await expect(recoverCandidateShuffledSaskuRound(c.options)).rejects.toThrow(/Invalid shuffle proof/);
}, 30_000);
it("captures the caller's policy before asynchronous proof verification", async () => {
  const c = await fixture(), gate = deferred(), started = deferred();
  c.verifier.verify.mockImplementationOnce(async () => { started.resolve(); await gate.promise; return true; });
  const opening = recoverCandidateShuffledSaskuRound(c.options); await started.promise;
  c.options.schedule[0]!.to = 3; gate.resolve();
  const round = await opening; expect(round.ownerAt(0)).toBe(0); round.close();
}, 30_000);
