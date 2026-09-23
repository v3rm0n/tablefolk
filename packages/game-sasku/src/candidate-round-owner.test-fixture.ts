import { vi } from "vitest";
import { createUnprovenDeckShuffle, decodeCandidateShuffleStatement36, encodeCandidateShuffleStatement36, encodeCandidateShuffleProof36 } from "@p2pcards/deck";
import { PersistentCandidateShuffleReceiver } from "@p2pcards/engine";
import { parseHash256, type EnvelopeArtifact } from "@p2pcards/protocol";
import { PersistentEnvelopeAuthor, PersistentSessionReceiver, SessionChainRegistry } from "@p2pcards/session";
import { SASKU_DECK_SPEC } from "@p2pcards/rules-sasku";
import { roundRevealFixture } from "../../engine/src/round-reveal.test-fixture";
import { MemoryStore } from "../../engine/src/persistent-setup.test-fixture";
import { recoverCandidateShuffledSaskuRound } from "./candidate-shuffled-round";
import { CandidateSaskuRoundOwner } from "./candidate-round-owner";

export async function fixture(withDeals = false, maxPendingEnvelopes = 32) {
  const f = roundRevealFixture({ seats: 4, deckSpec: SASKU_DECK_SPEC });
  const sourceStore = new MemoryStore(), source = new SessionChainRegistry(f.gameId, f.roster);
  const sourceDurable = new PersistentSessionReceiver(source, sourceStore);
  const authors = f.identities.slice(0, 4).map(i => new PersistentEnvelopeAuthor(f.gameId, i.secretKey, sourceStore));
  for (const artifact of f.setupEnvelopes) await sourceDurable.receive(await authors[source.seatOf(artifact.envelope.from)!]!.author(artifact.envelope));
  const verifier = { verify: vi.fn(async () => true) };
  const context = { roster: { gameId: f.gameId, seats: f.roster, rulesHash: parseHash256(new Uint8Array(32)), iceConfigHash: parseHash256(new Uint8Array(32)) },
    self: f.roster[0]!, setupRound: 0, round: f.round, verifier, dealer: 3 as const, schedule: [0, 1, 2, 3].map(to => ({ to, count: 9 })) };
  const shuffle = await PersistentCandidateShuffleReceiver.open({ ...context, session: source, sessionReceiver: sourceDurable, deckSpec: SASKU_DECK_SPEC });
  const shuffles: EnvelopeArtifact[] = [], deals: EnvelopeArtifact[] = [];
  for (let seat = 0; seat < 4; seat++) {
    const s = decodeCandidateShuffleStatement36(shuffle.nextStatement());
    const shuffled = createUnprovenDeckShuffle(s.inputDeck, s.aggregateKey, f.source);
    const artifact = await authors[seat]!.author({ round: f.round, phase: `round.${f.round}.shuffle.${seat}`, type: "SHUFFLE", body: {
      statement: encodeCandidateShuffleStatement36({ ...s, outputDeck: shuffled.outputDeck }), proof: encodeCandidateShuffleProof36(Array.from({ length: 106 }, () => new Uint8Array(32))),
    } });
    await shuffle.receive(artifact); shuffles.push(artifact);
  }
  shuffle.close();
  if (withDeals) {
    const round = await recoverCandidateShuffledSaskuRound({ ...context, session: source, sessionReceiver: sourceDurable });
    while (round.snapshot.ledger.deal) for (const seat of round.snapshot.ledger.deal.pendingSenders) {
      deals.push((await round.authorDealShares(authors[seat]!, f.secrets[seat]!, round.snapshot, f.source)).received);
    }
    round.close();
  }
  const store = new MemoryStore(), session = new SessionChainRegistry(f.gameId, f.roster), durable = new PersistentSessionReceiver(session, store);
  // Local authored setup remains a native prefix; received copies never promote it.
  for (const a of f.setupEnvelopes) {
    if (session.seatOf(a.envelope.from) === 0) await store.appendNext(f.gameId, f.roster[0]!, () => a);
    await durable.receive(a);
  }
  verifier.verify.mockClear();
  const options = { ...context, session, sessionReceiver: durable, maxPendingEnvelopes };
  const owner = await CandidateSaskuRoundOwner.open(options);
  return { f, store, session, durable, verifier, options, owner, shuffles, deals,
    local: new PersistentEnvelopeAuthor(f.gameId, f.identities[0]!.secretKey, store) };
}
