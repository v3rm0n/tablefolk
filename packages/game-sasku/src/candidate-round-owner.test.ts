import { expect, it, vi } from "vitest";
import { deferred } from "../../engine/src/persistent-setup.test-fixture";
import { CandidateSaskuRoundOwner } from "./candidate-round-owner";
import { fixture } from "./candidate-round-owner.test-fixture";

it("schedules reverse-order shuffle and deal traffic through an exclusive handoff", async () => {
  const c = await fixture(true);
  const promises = [...c.deals].reverse().map(a => c.owner.receiveHistory(a));
  await c.owner.whenIdle(); expect(c.owner.pendingEnvelopes).toBe(12); expect(c.verifier.verify).not.toHaveBeenCalled();
  for (const artifact of [...c.shuffles].reverse()) promises.push(c.owner.receiveHistory(artifact));
  expect((await Promise.all(promises)).every(r => r.status === "accepted")).toBe(true);
  await c.owner.whenIdle(); expect(c.owner.pendingEnvelopes).toBe(0); expect(c.owner.pendingBytes).toBe(0);
  const snapshot = c.owner.snapshot; expect(snapshot.phase).toBe("round");
  if (snapshot.phase !== "round") throw new Error("No round");
  expect(snapshot.state.ledger.deal).toBeNull();
  expect(Object.keys(c.owner.readPrivateHand(c.f.secrets[0]!)!.dealt)).toHaveLength(9);
  expect((await c.owner.receiveHistory(c.shuffles[0]!)).status).toBe("duplicate"); c.owner.close();
}, 30_000);
it("serializes incoming traffic behind in-flight proof verification", async () => {
  const c = await fixture(), gate = deferred(), started = deferred();
  c.verifier.verify.mockImplementationOnce(async () => { started.resolve(); await gate.promise; return true; });
  const pending = c.owner.receiveHistory(c.shuffles[0]!); await started.promise;
  const future = c.owner.receive(c.f.roster[1]!, c.shuffles[1]!.canonicalBytes);
  expect(c.session.heads().map(h => h.seq)).toEqual([2, 2, 2, 2]);
  expect(() => c.owner.nextShuffleStatement()).toThrow(/unavailable/);
  gate.resolve(); expect((await pending).status).toBe("accepted"); expect((await future).status).toBe("accepted");
  expect(c.owner.failure).toBeNull(); c.owner.close();
}, 30_000);
it("keeps future traffic queued while a local author fills its prerequisite", async () => {
  const c = await fixture();
  const future = c.owner.receive(c.f.roster[1]!, c.shuffles[1]!.canonicalBytes);
  await c.owner.whenIdle(); const before = c.owner.snapshot;
  if (before.phase !== "shuffle") throw new Error("Wrong phase");
  const body = c.shuffles[0]!.envelope.body as { statement: Uint8Array; proof: Uint8Array };
  expect((await c.owner.authorShuffle(c.local, body, before.state)).status).toBe("accepted");
  expect((await future).status).toBe("accepted"); expect(c.owner.pendingBytes).toBe(0); c.owner.close();
}, 30_000);
it("enforces peer binding, budgets, unsupported controls, and cancellation", async () => {
  const c = await fixture(false, 1);
  await expect(c.owner.receive(c.f.roster[2]!, c.shuffles[1]!.canonicalBytes)).rejects.toThrow(/sender/);
  await expect(c.owner.receive(c.f.roster[0]!, c.shuffles[0]!.canonicalBytes)).rejects.toThrow(/peer/);
  const control = c.f.sign(1, "SYNC_REQ", "control.sync", { from: c.f.roster[0]!, from_seq: 0, to_seq: 0 });
  await expect(c.owner.receive(c.f.roster[1]!, control.canonicalBytes)).rejects.toThrow(/Unsupported/);
  const pending = c.owner.receive(c.f.roster[3]!, c.shuffles[3]!.canonicalBytes);
  const rejected = expect(pending).rejects.toThrow(/closed/);
  await c.owner.whenIdle();
  await expect(c.owner.receiveHistory(c.shuffles[1]!)).rejects.toThrow(/queue limit/);
  expect(c.verifier.verify).not.toHaveBeenCalled(); c.owner.close(); await rejected;
  expect(c.owner.pendingBytes).toBe(0); expect(c.owner.pendingEnvelopes).toBe(0);
}, 30_000);
it("finishes active persistence on close but cancels deferred operations", async () => {
  const c = await fixture(), gate = deferred(), started = deferred(), persist = c.store.persistAcceptedEnvelope.bind(c.store);
  vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async a => { started.resolve(); await gate.promise; return persist(a); });
  const active = c.owner.receiveHistory(c.shuffles[0]!); await started.promise;
  const future = c.owner.receiveHistory(c.shuffles[1]!); const rejected = expect(future).rejects.toThrow(/closed/);
  c.owner.close(); await rejected; gate.resolve(); expect((await active).status).toBe("accepted");
  await c.owner.whenIdle(); expect(c.owner.pendingBytes).toBe(0); expect(c.session.heads()[0]!.seq).toBe(3);
  const reopened = await CandidateSaskuRoundOwner.open(c.options);
  expect(reopened.snapshot).toMatchObject({ phase: "shuffle", state: { nextSeat: 1 } }); reopened.close();
}, 30_000);
it("rejects deferred work and requires recovery when the durable phase handoff fails", async () => {
  const c = await fixture(true);
  c.verifier.verify.mockResolvedValueOnce(true).mockResolvedValueOnce(true).mockResolvedValueOnce(true).mockResolvedValueOnce(true).mockResolvedValueOnce(false);
  const deferredDeal = expect(c.owner.receiveHistory(c.deals[0]!)).rejects.toThrow(/handoff/);
  for (const artifact of c.shuffles.slice(0, 3)) expect((await c.owner.receiveHistory(artifact)).status).toBe("accepted");
  await expect(c.owner.receiveHistory(c.shuffles[3]!)).rejects.toThrow(/handoff/);
  await deferredDeal; await c.owner.whenIdle();
  expect(c.owner.failure).not.toBeNull(); expect(c.owner.pendingBytes).toBe(0);
  await expect(c.owner.receiveHistory(c.deals[0]!)).rejects.toThrow(/handoff/);
  const recovered = await CandidateSaskuRoundOwner.open(c.options);
  expect(recovered.snapshot.phase).toBe("round"); recovered.close(); c.owner.close();
}, 30_000);
