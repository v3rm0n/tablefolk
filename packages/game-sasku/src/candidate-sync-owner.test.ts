import { expect, it, vi } from "vitest";
import { decodeSyncResponseBody, encodeSyncRequestBody, encodeSyncResponseBody } from "@p2pcards/protocol";
import { fixture } from "./candidate-round-owner.test-fixture";
import { deferred } from "../../engine/src/persistent-setup.test-fixture";

it("serializes sync control receipt after proof work and refreshes the shuffle checkpoint", async () => {
  const c = await fixture(), gate = deferred(), started = deferred();
  c.verifier.verify.mockImplementationOnce(async () => { started.resolve(); await gate.promise; return true; });
  const pending = c.owner.receiveHistory(c.shuffles[0]!); await started.promise;
  const request = c.f.sign(3, "SYNC_REQ", "control.sync", encodeSyncRequestBody({ from: c.f.roster[0]!, fromSeq: 3, toSeq: 3 }));
  const control = c.owner.receiveSyncRequest(c.f.roster[3]!, request.canonicalBytes);
  await expect(c.owner.receive(c.f.roster[3]!, c.shuffles[3]!.canonicalBytes)).rejects.toThrow(/Conflicting queued/);
  expect(c.session.heads().map(h => h.seq)).toEqual([2, 2, 2, 2]);
  gate.resolve(); expect((await pending).status).toBe("accepted"); expect((await control).status).toBe("accepted");
  expect((await c.owner.receiveHistory(c.shuffles[1]!)).status).toBe("accepted");
  expect(c.owner.failure).toBeNull(); c.owner.close();
}, 30_000);
it("preflights a relayed range and applies originals inside the owner without self-deadlock", async () => {
  const c = await fixture();
  const request = { from: c.f.roster[0]!, fromSeq: 3, toSeq: 3 };
  const outer = c.f.sign(3, "SYNC_RESP", "control.sync", encodeSyncResponseBody({ envelopes: [c.shuffles[0]!] }));
  expect(await c.owner.receiveSyncResponse(c.f.roster[3]!, outer.canonicalBytes, request)).toMatchObject({ status: "range_received", outerStatus: "accepted", receipts: ["accepted"] });
  expect(await c.owner.receiveSyncResponse(c.f.roster[3]!, outer.canonicalBytes, request)).toMatchObject({ status: "range_received", outerStatus: "duplicate", receipts: ["duplicate"] });
  expect(c.owner.snapshot).toMatchObject({ phase: "shuffle", state: { nextSeat: 1 } });
  expect(c.owner.pendingBytes).toBe(0); c.owner.close();
}, 30_000);
it("rejects a mismatched range before storage and stops future semantics without blocking later prerequisites", async () => {
  const c = await fixture(), write = vi.spyOn(c.store, "persistAcceptedEnvelope");
  const outer = c.f.sign(3, "SYNC_RESP", "control.sync", encodeSyncResponseBody({ envelopes: [c.shuffles[1]!] }));
  expect(await c.owner.receiveSyncResponse(c.f.roster[3]!, outer.canonicalBytes, { from: c.f.roster[0]!, fromSeq: 3, toSeq: 3 })).toMatchObject({ status: "stopped", stage: "preflight" });
  expect(write).not.toHaveBeenCalled();
  const request = { from: c.f.roster[1]!, fromSeq: 3, toSeq: 3 };
  expect(await c.owner.receiveSyncResponse(c.f.roster[3]!, outer.canonicalBytes, request)).toMatchObject({ status: "stopped", reason: "missing_prerequisite", outerStatus: "accepted", receipts: [] });
  expect((await c.owner.receiveHistory(c.shuffles[0]!)).status).toBe("accepted");
  expect(await c.owner.receiveSyncResponse(c.f.roster[3]!, outer.canonicalBytes, request)).toMatchObject({ status: "range_received", outerStatus: "duplicate", receipts: ["accepted"] });
  c.owner.close();
}, 30_000);
it("does not use nested originals to repair the outer sender's missing predecessor", async () => {
  const c = await fixture(), write = vi.spyOn(c.store, "persistAcceptedEnvelope");
  const inner = c.shuffles[1]!;
  const outer = c.f.sign(1, "SYNC_RESP", "control.sync", encodeSyncResponseBody({ envelopes: [inner] }), { seq: 4, prev: inner.hash });
  expect(await c.owner.receiveSyncResponse(c.f.roster[1]!, outer.canonicalBytes, { from: c.f.roster[1]!, fromSeq: 3, toSeq: 3 })).toMatchObject({ status: "stopped", stage: "outer", reason: "gap", outerStatus: null });
  expect(write).not.toHaveBeenCalled(); c.owner.close();
}, 30_000);
it("cancels a queued response and releases its whole reservation before writes", async () => {
  const c = await fixture(), gate = deferred(), started = deferred();
  c.verifier.verify.mockImplementationOnce(async () => { started.resolve(); await gate.promise; return true; });
  const pending = c.owner.receiveHistory(c.shuffles[0]!); await started.promise;
  const outer = c.f.sign(3, "SYNC_RESP", "control.sync", encodeSyncResponseBody({ envelopes: [c.shuffles[1]!] }));
  // Use a small platform-neutral signal rather than DOM types in this package.
  const listeners = new Set<() => void>();
  const signal = { aborted: false, addEventListener(_type: "abort", listener: () => void) { listeners.add(listener); }, removeEventListener(_type: "abort", listener: () => void) { listeners.delete(listener); } };
  const sync = c.owner.receiveSyncResponse(c.f.roster[3]!, outer.canonicalBytes, { from: c.f.roster[1]!, fromSeq: 3, toSeq: 3 }, signal);
  signal.aborted = true; for (const listener of listeners) listener();
  expect(await sync).toMatchObject({ status: "cancelled", outerStatus: null, receipts: [] });
  expect(c.owner.pendingEnvelopes).toBe(1); expect(c.owner.pendingBytes).toBe(c.shuffles[0]!.canonicalBytes.length);
  expect(listeners.size).toBe(0); gate.resolve(); await pending; c.owner.close();
}, 30_000);
it("authors controls in queue order and keeps subsequent shuffle preparation usable", async () => {
  const c = await fixture(), gate = deferred(), started = deferred();
  c.verifier.verify.mockImplementationOnce(async () => { started.resolve(); await gate.promise; return true; });
  const snapshot = c.owner.snapshot;
  if (snapshot.phase !== "shuffle") throw new Error("Expected shuffle");
  const body = c.shuffles[0]!.envelope.body as { statement: Uint8Array; proof: Uint8Array };
  const shuffle = c.owner.authorShuffle(c.local, body, snapshot.state); await started.promise;
  const request = c.owner.authorSyncRequest(c.local, { from: c.f.roster[1]!, fromSeq: 3, toSeq: 3 });
  expect((await c.local.readHead())!.envelope.seq).toBe(2);
  gate.resolve(); expect((await shuffle).status).toBe("accepted");
  const control = await request;
  expect(control.status).toBe("accepted"); expect(control.received.envelope.seq).toBe(4);
  expect(control.received.envelope.prev).toEqual((await shuffle).received.hash);
  expect((await c.owner.receiveHistory(c.shuffles[1]!)).status).toBe("accepted");
  expect(c.owner.failure).toBeNull(); expect(c.owner.pendingBytes).toBe(0); c.owner.close();
}, 30_000);
it("serves admitted requests under ownership and rejects missing or unadmitted history before signing", async () => {
  const c = await fixture();
  const request = c.f.sign(3, "SYNC_REQ", "control.sync", encodeSyncRequestBody({ from: c.f.roster[0]!, fromSeq: 3, toSeq: 3 }));
  await expect(c.owner.authorSyncResponse(c.local, c.f.roster[3]!, request)).rejects.toThrow(/not been admitted/);
  await c.owner.receiveSyncRequest(c.f.roster[3]!, request.canonicalBytes);
  await expect(c.owner.authorSyncResponse(c.local, c.f.roster[3]!, request)).rejects.toThrow(/unavailable/);
  expect((await c.local.readHead())!.envelope.seq).toBe(2);
  const local = await c.owner.authorSyncRequest(c.local, { from: c.f.roster[1]!, fromSeq: 3, toSeq: 3 });
  const response = await c.owner.authorSyncResponse(c.local, c.f.roster[3]!, request);
  expect(response.status).toBe("accepted"); expect(response.received.envelope.type).toBe("SYNC_RESP");
  expect(decodeSyncResponseBody(response.received.envelope.body).envelopes[0]!.canonicalBytes).toEqual(local.received.canonicalBytes);
  expect(c.owner.failure).toBeNull(); c.owner.close();
}, 30_000);
it("requires recovery after an ambiguous control append and never signs a replacement", async () => {
  const c = await fixture(), append = c.store.appendNext.bind(c.store);
  vi.spyOn(c.store, "appendNext").mockImplementationOnce(async (...args) => { await append(...args); throw new Error("lost receipt"); });
  const request = { from: c.f.roster[1]!, fromSeq: 3, toSeq: 3 };
  await expect(c.owner.authorSyncRequest(c.local, request)).rejects.toThrow(/requires recovery/);
  expect((await c.local.readHead())!.envelope.seq).toBe(3);
  await expect(c.owner.authorSyncRequest(c.local, request)).rejects.toThrow(/requires recovery/);
  expect(c.store.appendNext).toHaveBeenCalledTimes(1); c.owner.close();
}, 30_000);
it("bounds outgoing ranges and rejects mismatched authored prefixes", async () => {
  const c = await fixture();
  await expect(c.owner.authorSyncRequest(c.local, { from: c.f.roster[1]!, fromSeq: 0, toSeq: 32 })).rejects.toThrow(/range/);
  expect(c.owner.failure).toBeNull();
  await c.local.author({ round: c.f.round, phase: "control.sync", type: "SYNC_REQ", body: encodeSyncRequestBody({ from: c.f.roster[1]!, fromSeq: 3, toSeq: 3 }) });
  await expect(c.owner.authorSyncRequest(c.local, { from: c.f.roster[1]!, fromSeq: 3, toSeq: 3 })).rejects.toThrow(/head requires recovery/);
  expect((await c.local.readHead())!.envelope.seq).toBe(3); c.owner.close();
}, 30_000);
