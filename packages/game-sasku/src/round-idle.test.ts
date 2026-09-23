import { MAX_ROUND_REVEAL_ENVELOPE_BYTES } from "@p2pcards/engine";
import { type EnvelopeArtifact } from "@p2pcards/protocol";
import { SaskuPublicHandController } from "@p2pcards/rules-sasku";
import { SessionChainRegistry } from "@p2pcards/session";
import { afterEach, describe, expect, it, vi } from "vitest";

import { context, deferred } from "./local-authoring.test-fixture";

describe("Sasku round binding and idle barrier", () => {
  afterEach(() => vi.restoreAllMocks());

  it("exposes immutable round metadata and exact registry binding, not an idle lease", async () => {
    const c = await context({}, undefined, false);
    expect(c.game.round).toBe(c.f.round);
    expect(c.game.dealCount).toBe(c.f.plans.length);
    expect(c.game.isBoundTo(c.session)).toBe(true);
    expect(c.game.isBoundTo(new SessionChainRegistry(c.f.gameId, c.f.roster))).toBe(false);
    const idle = c.game.whenIdle();
    await expect(idle).resolves.toBeUndefined();
    const receiving = c.game.receive(c.f.deal(0, 1));
    expect(c.game.whenIdle()).not.toBe(idle);
    await receiving;
    await expect(c.game.whenIdle()).resolves.toBeUndefined();
    expect(c.game.pendingEnvelopes).toBe(0);
  });

  it("waits for the whole admitted queue, not only the active receipt", async () => {
    const c = await context({}, undefined, false);
    const firstEntered = deferred();
    const secondEntered = deferred();
    const firstGate = deferred();
    const secondGate = deferred();
    const persist = c.store.persistAcceptedEnvelope.bind(c.store);
    vi.spyOn(c.store, "persistAcceptedEnvelope")
      .mockImplementationOnce(async (artifact) => { firstEntered.resolve(); await firstGate.promise; return persist(artifact); })
      .mockImplementationOnce(async (artifact) => { secondEntered.resolve(); await secondGate.promise; return persist(artifact); });
    const first = c.game.receive(c.f.deal(0, 1));
    const idle = c.game.whenIdle();
    const settled = vi.fn();
    void idle.then(settled);
    const second = c.game.receive(c.f.deal(0, 2));
    expect(c.game.whenIdle()).toBe(idle);
    await firstEntered.promise;
    expect(c.game.pendingEnvelopes).toBe(2);
    expect(settled).not.toHaveBeenCalled();
    firstGate.resolve();
    await first;
    await secondEntered.promise;
    expect(c.game.pendingEnvelopes).toBe(1);
    expect(settled).not.toHaveBeenCalled();
    secondGate.resolve();
    await Promise.all([second, idle]);
    expect(settled).toHaveBeenCalledOnce();
    expect(c.game.pendingBytes).toBe(0);
  });

  it.each(["before signing", "during receipt"] as const)("does not settle active authoring early when closed %s", async (boundary) => {
    const c = await context({}, undefined, false);
    const gate = deferred();
    const entered = deferred();
    if (boundary === "before signing") {
      const append = c.store.appendNext.bind(c.store);
      vi.spyOn(c.store, "appendNext").mockImplementationOnce(async (...args) => {
        entered.resolve(); await gate.promise; return append(...args);
      });
    } else {
      const persist = c.store.persistAcceptedEnvelope.bind(c.store);
      vi.spyOn(c.store, "persistAcceptedEnvelope").mockImplementationOnce(async (artifact) => {
        entered.resolve(); await gate.promise; return persist(artifact);
      });
    }
    const active = c.game.authorDealShares(c.authors[1]!, c.f.secrets[1]!, c.game.snapshot, c.f.source);
    const outcome = boundary === "before signing"
      ? expect(active).rejects.toMatchObject({ code: "closed" })
      : expect(active).resolves.toMatchObject({ status: "accepted" });
    const queued = expect(c.game.receive(c.f.deal(0, 2))).rejects.toMatchObject({ code: "closed" });
    const idle = c.game.whenIdle();
    const settled = vi.fn();
    void idle.then(settled);
    await entered.promise;
    c.game.close();
    await queued;
    expect(c.game.pendingEnvelopes).toBe(1);
    expect(c.game.pendingBytes).toBe(MAX_ROUND_REVEAL_ENVELOPE_BYTES);
    expect(settled).not.toHaveBeenCalled();
    gate.resolve();
    await Promise.all([outcome, idle]);
    expect(settled).toHaveBeenCalledOnce();
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
    expect(c.game.failure).toBeNull();
  });

  it.each(["invalid bytes", "invalid semantics", "storage failure"] as const)("releases the barrier after %s without claiming success", async (mode) => {
    const c = await context({}, undefined, false);
    const candidate = c.f.deal(0, mode === "invalid semantics" ? 0 : 1);
    if (mode === "storage failure") vi.spyOn(c.store, "persistAcceptedEnvelope").mockRejectedValueOnce(new Error("disk failed"));
    const receiving = c.game.receive(mode === "invalid bytes"
      ? { ...candidate, canonicalBytes: new Uint8Array([0xff]) } as EnvelopeArtifact : candidate);
    const rejected = expect(receiving).rejects.toBeInstanceOf(Error);
    await Promise.all([rejected, c.game.whenIdle()]);
    expect(c.game.pendingEnvelopes).toBe(0);
    expect(c.game.pendingBytes).toBe(0);
    expect(c.game.failure).toBeNull();
    expect(c.game.snapshot.ledger.deal?.pendingSenders).toEqual([1, 2, 3]);
  });

  it("settles after terminal failure cancels queued work, while failure remains separately observable", async () => {
    const c = await context();
    const before = c.game.snapshot;
    vi.spyOn(SaskuPublicHandController.prototype, "apply").mockImplementationOnce(() => { throw new Error("commit failed"); });
    const first = expect(c.game.receive(c.f.action(0, [], 0, "diamonds"))).rejects.toMatchObject({ code: "commit_failed" });
    const second = expect(c.game.receive(c.f.action(0, [0], 1))).rejects.toMatchObject({ code: "commit_failed" });
    await Promise.all([first, second, c.game.whenIdle()]);
    expect(c.game.failure?.code).toBe("commit_failed");
    expect(c.game.snapshot).toBe(before);
    expect(c.game.pendingBytes).toBe(0);
    expect(c.game.pendingEnvelopes).toBe(0);
    await expect(c.game.whenIdle()).resolves.toBeUndefined();
  });
});
