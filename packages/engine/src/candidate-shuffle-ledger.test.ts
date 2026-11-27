import { describe, it, expect, vi } from "vitest";
import { decodeCandidateShuffleStatement, encodeCandidateShuffleStatement, encodeCandidateShuffleProof, createUnprovenDeckShuffle, packShuffleDeck } from "@p2pcards/deck";
import type { CborMap } from "@p2pcards/encoding";
import { parseHash256 } from "@p2pcards/protocol";
import { SASKU_DECK_SPEC } from "@p2pcards/rules-sasku";
import { CandidateShuffleLedger } from "./candidate-shuffle-ledger";
import { roundRevealFixture } from "./round-reveal.test-fixture";
import { SetupEnvelopeCoordinator } from "./setup-envelope-coordinator";

function fixture() {
  const f = roundRevealFixture({ seats: 4, deckSpec: SASKU_DECK_SPEC });
  const verifier = { verify: vi.fn(async (_statement: Uint8Array, _proof: Uint8Array) => true) };
  const roster = { gameId: f.gameId, seats: f.roster, rulesHash: parseHash256(new Uint8Array(32)), iceConfigHash: parseHash256(new Uint8Array(32)) };
  const options = { setup: f.setup, roster, round: f.round, deckSpec: SASKU_DECK_SPEC, verifier };
  const ledger = new CandidateShuffleLedger(options);
  // Structural fixture only. This fake proof is accepted only by the injected test verifier.
  const proof = encodeCandidateShuffleProof(Array.from({ length: 106 }, () => new Uint8Array(32)), { rows: 4, columns: 9 });
  const prepare = () => {
    const template = decodeCandidateShuffleStatement(ledger.nextStatement());
    const shuffled = createUnprovenDeckShuffle(template.inputDeck, template.aggregateKey, f.source);
    return encodeCandidateShuffleStatement({ ...template, outputDeck: shuffled.outputDeck });
  };
  const sign = (statement = prepare(), seat = ledger.nextSeat!, overrides = {}) =>
    f.sign(seat, "SHUFFLE", `round.${f.round}.shuffle.${ledger.nextSeat}`,
      { outputDeck: packShuffleDeck(decodeCandidateShuffleStatement(statement).outputDeck, 36), proof }, overrides).canonicalBytes;
  return { ...f, ledger, options, verifier, proof, prepare, signShuffle: sign };
}
describe("candidate shuffle provenance ledger", () => {
  it("requires completed matching four-seat setup and 36-card scope", () => {
    const f = fixture();
    expect(() => new CandidateShuffleLedger({ ...f.options, setup: new SetupEnvelopeCoordinator(f.gameId, 0, f.roster) })).toThrow();
    expect(() => new CandidateShuffleLedger({ ...f.options, roster: { ...f.options.roster, seats: [...f.roster].reverse() } })).toThrow();
    expect(() => new CandidateShuffleLedger({ ...f.options, round: -0 })).toThrow();
    expect(() => new CandidateShuffleLedger({ ...f.options, deckSpec: { id: "short", cards: ["a", "b"] } })).toThrow();
  });
  it("starts at the agreed card table, chains four outputs, and recognizes exact replays", async () => {
    const f = fixture();
    const first = decodeCandidateShuffleStatement(f.ledger.nextStatement());
    first.inputDeck.forEach((card, i) => { expect(card.A.isIdentity()).toBe(true); expect(card.B.equals(f.table.pointAt(i))).toBe(true); });
    expect(() => f.ledger.finalDeck).toThrow();
    for (let seat = 0; seat < 4; seat++) {
      const statement = f.prepare(), bytes = f.signShuffle(statement);
      expect(await f.ledger.accept(bytes)).toBe("accepted");
      expect(f.verifier.verify).toHaveBeenLastCalledWith(statement, f.proof);
      expect(await f.ledger.accept(bytes)).toBe("duplicate");
      if (seat < 3) expect(decodeCandidateShuffleStatement(f.ledger.nextStatement()).inputDeck).toEqual(decodeCandidateShuffleStatement(statement).outputDeck);
      else expect(f.ledger.finalDeck).toEqual(decodeCandidateShuffleStatement(statement).outputDeck);
    }
    expect(f.ledger.complete).toBe(true); expect(f.ledger.nextSeat).toBeNull();
    expect(f.verifier.verify).toHaveBeenCalledTimes(4);
  });
  it("rejects wrong signed scope, legacy bodies, and malformed deck/proof bytes before verification", async () => {
    const f = fixture(), statement = f.prepare(), s = decodeCandidateShuffleStatement(statement);
    for (const overrides of [{ round: f.round + 1 }, { phase: "wrong" }, { type: "ACTION" as const }]) await expect(f.ledger.accept(f.signShuffle(statement, 0, overrides))).rejects.toThrow();
    await expect(f.ledger.accept(f.signShuffle(statement, 1))).rejects.toThrow();
    const packed = packShuffleDeck(s.outputDeck, 36), invalidPoint = packed.slice();
    invalidPoint.fill(255, 0, 32);
    for (const body of [{ statement, proof: f.proof }, { outputDeck: packed, proof: f.proof, statement },
      { outputDeck: packed.slice(1), proof: f.proof }, { outputDeck: invalidPoint, proof: f.proof },
      { outputDeck: packed, proof: f.proof.slice(1) }] as CborMap[]) {
      const bytes = f.sign(0, "SHUFFLE", `round.${f.round}.shuffle.0`, body).canonicalBytes;
      await expect(f.ledger.accept(bytes)).rejects.toThrow();
    }
    const badSignature = f.signShuffle(statement); badSignature[badSignature.length - 1] = badSignature[badSignature.length - 1]! ^ 1;
    await expect(f.ledger.accept(badSignature)).rejects.toThrow();
    expect(f.verifier.verify).not.toHaveBeenCalled(); expect(f.ledger.nextSeat).toBe(0);
  });
  it("does not advance on invalid proof or backend failure and permits retry", async () => {
    const f = fixture(), bytes = f.signShuffle();
    f.verifier.verify.mockResolvedValueOnce(false).mockRejectedValueOnce(new Error("backend offline"));
    await expect(f.ledger.accept(bytes)).rejects.toThrow(); expect(f.ledger.nextSeat).toBe(0);
    await expect(f.ledger.accept(bytes)).rejects.toThrow(); expect(f.ledger.nextSeat).toBe(0);
    expect(await f.ledger.accept(bytes)).toBe("accepted");
  });
  it("rejects concurrent calls and discards completion after close", async () => {
    const f = fixture(), bytes = f.signShuffle();
    let finish!: (valid: boolean) => void;
    f.verifier.verify.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    const pending = f.ledger.accept(bytes);
    await expect(f.ledger.accept(bytes)).rejects.toThrow(/busy/);
    f.ledger.close(); finish(true);
    await expect(pending).rejects.toThrow(/closed/);
    expect(f.ledger.nextSeat).toBe(0); expect(f.ledger.complete).toBe(false);
  });
  it("captures caller and backend buffers across asynchronous verification", async () => {
    const f = fixture(), bytes = f.signShuffle();
    let finish!: (valid: boolean) => void;
    f.verifier.verify.mockImplementationOnce((statement: Uint8Array, proof: Uint8Array) => {
      statement.fill(0); proof.fill(0);
      return new Promise(resolve => { finish = resolve; });
    });
    const pending = f.ledger.accept(bytes); bytes.fill(0); finish(true);
    expect(await pending).toBe("accepted");
    expect(decodeCandidateShuffleStatement(f.ledger.nextStatement()).inputDeck.length).toBe(36);
  });
});
