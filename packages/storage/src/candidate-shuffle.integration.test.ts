import { IDBFactory } from "fake-indexeddb";
import { expect, it, vi } from "vitest";
import { decodeCandidateShuffleStatement36, createUnprovenDeckShuffle, encodeCandidateShuffleStatement36, encodeCandidateShuffleProof36 } from "@p2pcards/deck";
import { PersistentCandidateShuffleReceiver } from "@p2pcards/engine";
import { parseHash256 } from "@p2pcards/protocol";
import { PersistentSessionReceiver, SessionChainRegistry, recoverSessionChains } from "@p2pcards/session";
import { SASKU_DECK_SPEC } from "@p2pcards/rules-sasku";
import { roundRevealFixture } from "../../engine/src/round-reveal.test-fixture";
import { IndexedDbSessionStore } from "./indexeddb-session-store";

it("rebuilds every verified shuffle prefix from fresh IndexedDB connections", async () => {
  const f = roundRevealFixture({ seats: 4, deckSpec: SASKU_DECK_SPEC });
  const factory = new IDBFactory(), databaseName = "candidate-shuffle-integration";
  let store = new IndexedDbSessionStore({ factory, databaseName });
  let session = new SessionChainRegistry(f.gameId, f.roster);
  let durable = new PersistentSessionReceiver(session, store);
  const verifier = { verify: vi.fn(async () => true) }; // Real proofs are tested by the browser harness.
  const options = { roster: { gameId: f.gameId, seats: f.roster, rulesHash: parseHash256(new Uint8Array(32)), iceConfigHash: parseHash256(new Uint8Array(32)) },
    self: f.roster[0]!, setupRound: 0, round: f.round, deckSpec: SASKU_DECK_SPEC, verifier };
  let receiver: PersistentCandidateShuffleReceiver | undefined;
  try {
    for (const artifact of f.setupEnvelopes) await durable.receive(artifact);
    receiver = await PersistentCandidateShuffleReceiver.open({ ...options, session, sessionReceiver: durable });
    for (let seat = 0; seat < 4; seat++) {
      const template = decodeCandidateShuffleStatement36(receiver.nextStatement());
      const shuffled = createUnprovenDeckShuffle(template.inputDeck, template.aggregateKey, f.source);
      const artifact = f.sign(seat, "SHUFFLE", `round.${f.round}.shuffle.${seat}`, {
        statement: encodeCandidateShuffleStatement36({ ...template, outputDeck: shuffled.outputDeck }),
        proof: encodeCandidateShuffleProof36(Array.from({ length: 106 }, () => new Uint8Array(32))),
      });
      expect((await receiver.receive(artifact)).status).toBe("accepted");
      const expected = receiver.snapshot;
      receiver.close(); await store.close();
      store = new IndexedDbSessionStore({ factory, databaseName });
      const records = await store.loadTranscript(f.gameId);
      expect(records).toHaveLength(12 + seat + 1);
      session = recoverSessionChains(f.gameId, f.roster, records.map(r => r.artifact).reverse()).registry;
      durable = new PersistentSessionReceiver(session, store);
      const write = vi.spyOn(store, "persistAcceptedEnvelope"), before = verifier.verify.mock.calls.length;
      receiver = await PersistentCandidateShuffleReceiver.open({ ...options, session, sessionReceiver: durable });
      expect(receiver.snapshot).toEqual(expected); expect(write).not.toHaveBeenCalled();
      expect(verifier.verify).toHaveBeenCalledTimes(before + seat + 1);
      expect((await receiver.receive(artifact)).status).toBe("duplicate");
      expect(await store.loadTranscript(f.gameId)).toHaveLength(records.length);
    }
    expect(receiver.finalDeck).toHaveLength(36);
  } finally { receiver?.close(); await store.close(); }
}, 30_000);
