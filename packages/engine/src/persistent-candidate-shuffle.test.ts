import { describe, it, expect, vi } from "vitest";
import { createUnprovenDeckShuffle, decodeCandidateShuffleStatement36, encodeCandidateShuffleStatement36, encodeCandidateShuffleProof36 } from "@p2pcards/deck";
import { parseHash256, decodeAndVerifyEnvelope } from "@p2pcards/protocol";
import { PersistentEnvelopeAuthor, PersistentSessionReceiver, SessionChainRegistry, recoverSessionChains } from "@p2pcards/session";
import { SASKU_DECK_SPEC } from "@p2pcards/rules-sasku";
import { roundRevealFixture } from "./round-reveal.test-fixture";
import { MemoryStore, deferred } from "./persistent-setup.test-fixture";
import { PersistentCandidateShuffleReceiver } from "./persistent-candidate-shuffle";

async function fixture() {
  const f = roundRevealFixture({ seats: 4, deckSpec: SASKU_DECK_SPEC });
  const store = new MemoryStore(), session = new SessionChainRegistry(f.gameId, f.roster);
  const durable = new PersistentSessionReceiver(session, store);
  for (const artifact of f.setupEnvelopes) await durable.receive(artifact);
  const verifier = { verify: vi.fn(async (_s: Uint8Array, _p: Uint8Array) => true) };
  const options = { session, sessionReceiver: durable, roster: { gameId: f.gameId, seats: f.roster,
    rulesHash: parseHash256(new Uint8Array(32)), iceConfigHash: parseHash256(new Uint8Array(32)) },
    self: f.roster[0]!, setupRound: 0, round: f.round, deckSpec: SASKU_DECK_SPEC, verifier };
  const receiver = await PersistentCandidateShuffleReceiver.open(options);
  const prepare = () => {
    const s = decodeCandidateShuffleStatement36(receiver.nextStatement());
    const shuffled = createUnprovenDeckShuffle(s.inputDeck, s.aggregateKey, f.source);
    return { statement: encodeCandidateShuffleStatement36({ ...s, outputDeck: shuffled.outputDeck }),
      proof: encodeCandidateShuffleProof36(Array.from({ length: 106 }, () => new Uint8Array(32))) };
  };
  const sign = (body = prepare(), overrides = {}) => f.sign(receiver.snapshot.nextSeat!, "SHUFFLE",
    `round.${f.round}.shuffle.${receiver.snapshot.nextSeat}`, body, overrides);
  const reopen = async () => {
    const restored = recoverSessionChains(f.gameId, f.roster, store.artifacts().map(r => r.artifact).reverse()).registry;
    return PersistentCandidateShuffleReceiver.open({ ...options, session: restored, sessionReceiver: new PersistentSessionReceiver(restored, store) });
  };
  return { ...f, store, session, durable, verifier, options, receiver, prepare, signShuffle: sign, reopen };
}
describe("durable candidate shuffle receiver", () => {
  it("persists four contributions and recovers every partial prefix without writing", async () => {
    const f = await fixture(), write = vi.spyOn(f.store, "persistAcceptedEnvelope");
    for (let seat = 0; seat < 4; seat++) {
      const artifact = f.signShuffle();
      expect((await f.receiver.receive(artifact)).status).toBe("accepted");
      const snapshot = f.receiver.snapshot;
      expect((await f.receiver.receive(artifact)).status).toBe("duplicate");
      expect(f.receiver.snapshot).toBe(snapshot);
      const writes = write.mock.calls.length, verified = f.verifier.verify.mock.calls.length;
      const recovered = await f.reopen();
      expect(recovered.snapshot).toEqual(snapshot); expect(write).toHaveBeenCalledTimes(writes);
      expect(f.verifier.verify).toHaveBeenCalledTimes(verified + seat + 1);
      if (seat < 3) expect(recovered.nextStatement()).toEqual(f.receiver.nextStatement());
      else expect(recovered.finalDeck).toEqual(f.receiver.finalDeck);
    }
  }, 30_000);
  it("does not advance deck or chain before storage commit and rejects concurrency", async () => {
    const f = await fixture(), artifact = f.signShuffle(), snapshot = f.receiver.snapshot, heads = f.session.heads();
    const gate = deferred(), started = deferred(), persist = f.store.persistAcceptedEnvelope.bind(f.store);
    vi.spyOn(f.store, "persistAcceptedEnvelope").mockImplementationOnce(async a => { started.resolve(); await gate.promise; return persist(a); });
    const pending = f.receiver.receive(artifact); await started.promise;
    expect(f.receiver.snapshot).toBe(snapshot); expect(f.session.heads()).toEqual(heads);
    await expect(f.receiver.receive(artifact)).rejects.toThrow(/busy/);
    gate.resolve(); expect((await pending).status).toBe("accepted");
  });
  it("retries a storage failure with unchanged state and bytes", async () => {
    const f = await fixture(), artifact = f.signShuffle(), snapshot = f.receiver.snapshot;
    vi.spyOn(f.store, "persistAcceptedEnvelope").mockRejectedValueOnce(new Error("disk failure"));
    await expect(f.receiver.receive(artifact)).rejects.toThrow(/disk failure/);
    expect(f.receiver.failure).toBeNull(); expect(f.receiver.snapshot).toBe(snapshot);
    expect((await f.receiver.receive(artifact)).status).toBe("accepted");
  });
  it("rejects sender gaps before proof work and invalid proofs before storage", async () => {
    const f = await fixture(), body = f.prepare(), write = vi.spyOn(f.store, "persistAcceptedEnvelope");
    const gap = f.signShuffle(body, { seq: 10 });
    expect(await f.receiver.receive(gap)).toMatchObject({ status: "rejected", reason: "gap" });
    expect(f.verifier.verify).not.toHaveBeenCalled(); expect(write).not.toHaveBeenCalled();
    const head = f.session.heads()[0]!;
    const validChain = f.signShuffle(body, { seq: head.seq + 1, prev: head.hash });
    f.verifier.verify.mockResolvedValueOnce(false);
    await expect(f.receiver.receive(validChain)).rejects.toThrow(/Invalid shuffle proof/);
    expect(write).not.toHaveBeenCalled(); expect(f.receiver.snapshot.nextSeat).toBe(0);
  });
  it("fails closed if session state changes during proof verification", async () => {
    const f = await fixture(), artifact = f.signShuffle(), gate = deferred(), started = deferred();
    f.verifier.verify.mockImplementationOnce(async () => { started.resolve(); await gate.promise; return true; });
    const pending = f.receiver.receive(artifact); await started.promise;
    await f.durable.receive(f.sign(1, "ACTION", "unrelated", {}));
    gate.resolve(); await expect(pending).rejects.toThrow(/recovery required/);
    expect(f.receiver.snapshot.nextSeat).toBe(0); expect(f.receiver.failure).not.toBeNull();
  });
  it("requires recovery after close during commit and replays the committed bytes", async () => {
    const f = await fixture(), artifact = f.signShuffle(), gate = deferred(), started = deferred();
    const persist = f.store.persistAcceptedEnvelope.bind(f.store);
    vi.spyOn(f.store, "persistAcceptedEnvelope").mockImplementationOnce(async a => { const result = await persist(a); started.resolve(); await gate.promise; return result; });
    const pending = f.receiver.receive(artifact); await started.promise; f.receiver.close(); gate.resolve();
    await expect(pending).rejects.toThrow(/recovery required/); expect(f.receiver.snapshot.nextSeat).toBe(0);
    expect((await f.reopen()).snapshot.nextSeat).toBe(1);
  });
  it("rejects stored holes, invalid proofs, and round activity without a complete chain", async () => {
    const f = await fixture();
    await f.receiver.receive(f.signShuffle());
    f.verifier.verify.mockResolvedValueOnce(false); await expect(f.reopen()).rejects.toThrow(/Invalid shuffle proof/);
    await f.durable.receive(f.sign(1, "ACTION", `round.${f.round}.action.0`, {}));
    await expect(f.reopen()).rejects.toThrow(/complete shuffle chain/);
    const g = await fixture();
    const body = g.prepare();
    const s = decodeCandidateShuffleStatement36(body.statement);
    await g.durable.receive(g.sign(1, "SHUFFLE", `round.${g.round}.shuffle.1`, { ...body, statement: encodeCandidateShuffleStatement36({ ...s, seat: 1 }) }));
    await expect(g.reopen()).rejects.toThrow(/scope or sender/);
  });
  it("rejects session changes during asynchronous recovery", async () => {
    const f = await fixture(); await f.receiver.receive(f.signShuffle());
    const gate = deferred(), started = deferred();
    f.verifier.verify.mockImplementationOnce(async () => { started.resolve(); await gate.promise; return true; });
    const opening = PersistentCandidateShuffleReceiver.open(f.options); await started.promise;
    await f.durable.receive(f.sign(1, "ACTION", "unrelated", {})); gate.resolve();
    await expect(opening).rejects.toThrow(/changed/);
  });
  it("authors only a validated local contribution extending the durable head", async () => {
    const f = await fixture();
    // Seed a separate author store with the exact already-admitted setup prefix.
    const authored = new MemoryStore();
    for (const artifact of f.setupEnvelopes.filter(a => a.envelope.from.every((b, i) => b === f.roster[0]![i]))) {
      await authored.appendNext(f.gameId, f.roster[0]!, () => decodeAndVerifyEnvelope(artifact.canonicalBytes));
    }
    const author = new PersistentEnvelopeAuthor(f.gameId, f.identities[0]!.secretKey, authored);
    const append = vi.spyOn(authored, "appendNext"), expected = f.receiver.snapshot, body = f.prepare();
    f.verifier.verify.mockResolvedValueOnce(false);
    await expect(f.receiver.author(author, body, expected)).rejects.toThrow(/Invalid prepared/); expect(append).not.toHaveBeenCalled();
    const result = await f.receiver.author(author, body, expected);
    expect(result.status).toBe("accepted"); expect(result.received.envelope.seq).toBe(3);
    expect(append).toHaveBeenCalledOnce();
    await expect(f.receiver.author(author, body, expected)).rejects.toThrow(/Stale/);
    expect((await f.reopen()).snapshot.nextSeat).toBe(1);
  });
  it("never signs a replacement after an ambiguous append and recovers the committed original", async () => {
    const f = await fixture(), authored = new MemoryStore();
    for (const artifact of f.setupEnvelopes.filter(a => a.envelope.from.every((b, i) => b === f.roster[0]![i]))) {
      await authored.appendNext(f.gameId, f.roster[0]!, () => decodeAndVerifyEnvelope(artifact.canonicalBytes));
    }
    const author = new PersistentEnvelopeAuthor(f.gameId, f.identities[0]!.secretKey, authored);
    const append = authored.appendNext.bind(authored);
    const write = vi.spyOn(authored, "appendNext").mockImplementationOnce(async (...args) => {
      await append(...args); throw new Error("Lost commit acknowledgement");
    });
    const prepared = f.prepare(), expected = f.receiver.snapshot;
    await expect(f.receiver.author(author, prepared, expected)).rejects.toThrow(/recovery required/);
    await expect(f.receiver.author(author, prepared, expected)).rejects.toThrow(/recovery required/);
    expect(write).toHaveBeenCalledOnce(); expect(f.receiver.snapshot.nextSeat).toBe(0);
    const original = await author.readHead(); expect(original!.envelope.seq).toBe(3);
    await f.durable.receive(original!);
    expect((await f.reopen()).snapshot.nextSeat).toBe(1);
  });
  it("rechecks the author head inside the signing transaction", async () => {
    const f = await fixture(), authored = new MemoryStore();
    for (const artifact of f.setupEnvelopes.filter(a => a.envelope.from.every((b, i) => b === f.roster[0]![i]))) {
      await authored.appendNext(f.gameId, f.roster[0]!, () => decodeAndVerifyEnvelope(artifact.canonicalBytes));
    }
    const author = new PersistentEnvelopeAuthor(f.gameId, f.identities[0]!.secretKey, authored);
    f.verifier.verify.mockImplementationOnce(async () => {
      await author.author({ type: "ACTION", round: f.round, phase: "other", body: {} }); return true;
    });
    await expect(f.receiver.author(author, f.prepare(), f.receiver.snapshot)).rejects.toThrow(/recovery required/);
    expect((await author.readHead())!.envelope.type).toBe("ACTION");
    expect(authored.artifacts().filter(a => a.artifact.envelope.type === "SHUFFLE")).toHaveLength(0);
  });
  it("refuses authoring with a missing authored predecessor before signing", async () => {
    const f = await fixture(), authored = new MemoryStore(), author = new PersistentEnvelopeAuthor(f.gameId, f.identities[0]!.secretKey, authored);
    const append = vi.spyOn(authored, "appendNext");
    await expect(f.receiver.author(author, f.prepare(), f.receiver.snapshot)).rejects.toThrow(/recovery required/);
    expect(append).not.toHaveBeenCalled();
  });
});
