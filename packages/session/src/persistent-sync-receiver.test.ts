import { bytesEqual, bytesToHex, deriveEd25519PublicKey, importEd25519SecretKey } from "@p2pcards/crypto";
import { decodeCanonical, type CborMap, type CborValue } from "@p2pcards/encoding";
import {
  decodeAndVerifyEnvelope,
  encodeSyncResponseBody,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  signEnvelope,
  type EnvelopeArtifact,
  type EnvelopeMessageType,
  type Hash256,
  type SyncRequestBody,
} from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";

import { SessionChainRegistry } from "./chain-registry";
import { PersistentSessionReceiver, type AcceptedEnvelopeStore } from "./persistent-receiver";
import {
  PersistentSyncReceiver,
  type PersistentSyncReceiverOptions,
  type SyncCancellationSignal,
  type SyncHistoryReceiveResult,
  type SyncHistoryReceiver,
} from "./persistent-sync-receiver";

const ALICE = identity(71);
const BOB = identity(72);
const CAROL = identity(73);
const OUTSIDER = identity(74);
const GAME = parseGameId(new Uint8Array(16).fill(0x41));
const ROSTER = [ALICE.publicKey, BOB.publicKey, CAROL.publicKey];
const ZERO = parseHash256(new Uint8Array(32));

describe("durable requested-range receipt", () => {
  it("commits the outer before invoking history and reports only confirmed receipts", async () => {
    const test = fixture();
    const records = history();
    const outer = response(records);
    const started = deferred();
    const commit = deferred();
    test.store.beforeCommit = async (artifact) => {
      if (artifact.envelope.type === "SYNC_RESP") {
        started.resolve();
        await commit.promise;
      }
    };
    const receiving = test.receiver.receiveResponse(outer, request());
    await started.promise;
    expect(test.registry.heads()).toEqual([]);
    expect(test.historyCalls).toEqual([]);
    expect(test.store.records.size).toBe(0);
    commit.resolve();
    await expect(receiving).resolves.toEqual({
      status: "range_received", outerStatus: "accepted", receipts: ["accepted", "accepted"],
    });
    expect(test.store.calls.map(({ envelope }) => [envelope.type, envelope.seq])).toEqual([
      ["SYNC_RESP", 0], ["ACTION", 0], ["ACTION", 1],
    ]);
    expect(test.registry.heads()).toMatchObject([{ from: ALICE.publicKey, seq: 0 }, { from: BOB.publicKey, seq: 1 }]);
  });

  it("never repairs an outer response's own gap using its nested predecessors", async () => {
    const test = fixture();
    const predecessors = history(ALICE);
    const outer = response(predecessors, ALICE, 2, predecessors[1]!.hash);
    await expect(test.receiver.receiveResponse(outer, request(ALICE))).resolves.toEqual({
      status: "stopped", stage: "outer", index: null, reason: "gap", outerStatus: null, receipts: [],
    });
    expect(test.store.calls).toEqual([]);
    expect(test.historyCalls).toEqual([]);
    expect(test.registry.heads()).toEqual([]);
  });

  it.each([
    { author: ALICE, seq: 0, prev: parseHash256(new Uint8Array(32).fill(1)), reason: "broken_prev" },
    { author: OUTSIDER, seq: 0, prev: ZERO, reason: "unknown_sender" },
    { author: ALICE, seq: 4, prev: ZERO, reason: "gap" },
  ])("rejects outer $reason before examining a malformed control body", async ({ author, seq, prev, reason }) => {
    const test = fixture();
    const outer = signed(author, seq, prev, "SYNC_RESP", { envelopes: "not an array" });
    await expect(test.receiver.receiveResponse(outer, request())).resolves.toMatchObject({
      status: "stopped", stage: "outer", reason, outerStatus: null, receipts: [],
    });
    expect(test.store.calls).toEqual([]);
  });

  it("rejects wrong outer type, game, and invalid canonical bytes without writes", async () => {
    const test = fixture();
    await expect(test.receiver.receiveResponse(history()[0]!, request())).resolves.toMatchObject({
      status: "stopped", stage: "outer", reason: "wrong_type",
    });
    const valid = response(history());
    const wrongGame = signEnvelope({ ...valid.envelope, game: parseGameId(new Uint8Array(16).fill(2)) }, ALICE.secretKey);
    await expect(test.receiver.receiveResponse(wrongGame, request())).resolves.toMatchObject({
      status: "stopped", stage: "outer", reason: "wrong_game",
    });
    valid.canonicalBytes.fill(0xff);
    await expect(test.receiver.receiveResponse(valid, request())).resolves.toMatchObject({
      status: "failed", stage: "outer", outerStatus: null, receipts: [],
    });
    expect(test.store.calls).toEqual([]);
  });

  it.each([
    { reason: "wrong_sender", tail: () => signed(CAROL, 1, history()[0]!.hash) },
    { reason: "wrong_sequence", tail: () => signed(BOB, 2, history()[0]!.hash) },
    { reason: "broken_prev", tail: () => signed(BOB, 1, ZERO) },
  ])("preflights the entire range before any writes: $reason", async ({ reason, tail }) => {
    const test = fixture();
    await expect(test.receiver.receiveResponse(response([history()[0]!, tail()]), request())).resolves.toMatchObject({
      status: "stopped", stage: "preflight", index: 1, reason, outerStatus: null, receipts: [],
    });
    expect(test.store.calls).toEqual([]);
    expect(test.historyCalls).toEqual([]);
  });

  it("rejects invalid nested signatures before the outer is committed", async () => {
    const test = fixture();
    const records = history();
    const tampered = decodeCanonical(records[1]!.canonicalBytes) as CborMap;
    (tampered["sig"] as Uint8Array).fill(0);
    const outer = signed(ALICE, 0, ZERO, "SYNC_RESP", {
      envelopes: [decodeCanonical(records[0]!.canonicalBytes), tampered],
    });
    await expect(test.receiver.receiveResponse(outer, request())).resolves.toMatchObject({
      status: "failed", stage: "preflight", outerStatus: null, receipts: [],
    });
    expect(test.store.calls).toEqual([]);
  });

  it.each([{ envelopes: [] }, { envelopes: [], extra: true }, { envelopes: "bad" }])(
    "rejects malformed response bodies: %j", async (body) => {
      const test = fixture();
      await expect(test.receiver.receiveResponse(signed(ALICE, 0, ZERO, "SYNC_RESP", body), request())).resolves.toMatchObject({
        status: "failed", stage: "preflight", outerStatus: null,
      });
      expect(test.store.calls).toEqual([]);
    },
  );

  it("retries a received outer and history idempotently", async () => {
    const test = fixture({ maxPendingResponses: 1 });
    const outer = response(history());
    await test.receiver.receiveResponse(outer, request());
    await expect(test.receiver.receiveResponse(outer, request())).resolves.toEqual({
      status: "range_received", outerStatus: "duplicate", receipts: ["duplicate", "duplicate"],
    });
    expect(test.store.records.size).toBe(3);
  });

  it("stops at a semantic rejection and preserves an idempotent durable prefix", async () => {
    const test = fixture();
    const first = history()[0]!;
    const invalid = signed(BOB, 1, first.hash, "ACTION", { ok: false });
    const outer = response([first, invalid]);
    await expect(test.receiver.receiveResponse(outer, request())).resolves.toMatchObject({
      status: "stopped", stage: "history", index: 1, reason: "invalid_history", outerStatus: "accepted", receipts: ["accepted"],
    });
    await expect(test.receiver.receiveResponse(outer, request())).resolves.toMatchObject({
      status: "stopped", index: 1, receipts: ["duplicate"], outerStatus: "duplicate",
    });
    expect(test.store.records.size).toBe(2);
    expect(test.registry.heads().find(({ from }) => bytesEqual(from, BOB.publicKey))?.seq).toBe(0);
  });

  it("does not execute historical controls through a chain-only fallback", async () => {
    const test = fixture();
    const historical = signed(BOB, 0, ZERO, "SYNC_REQ", { from: CAROL.publicKey, from_seq: 0, to_seq: 1 });
    await expect(test.receiver.receiveResponse(response([historical]), request(BOB, 0, 0))).resolves.toMatchObject({
      status: "stopped", stage: "history", reason: "unsupported_history", receipts: [], outerStatus: "accepted",
    });
    expect(test.store.calls).toHaveLength(1);
    expect(() => new PersistentSyncReceiver(test.registry, test.controls, test.controls)).toThrow(/semantic-capable/);
  });

  it("stops on the first local-chain gap or equivocation without dispatching it", async () => {
    const gap = fixture();
    await expect(gap.receiver.receiveResponse(response([signed(BOB, 4, ZERO)]), request(BOB, 4, 4))).resolves.toMatchObject({
      status: "stopped", stage: "history", index: 0, reason: "gap", outerStatus: "accepted", receipts: [],
    });
    expect(gap.historyCalls).toEqual([]);

    const conflict = fixture();
    await conflict.controls.receive(signed(BOB, 0, ZERO, "ACTION", { ok: true, variant: "existing" }));
    await expect(conflict.receiver.receiveResponse(response([history()[0]!]), request(BOB, 0, 0))).resolves.toMatchObject({
      status: "stopped", stage: "history", reason: "equivocation", receipts: [],
    });
    expect(conflict.historyCalls).toEqual([]);
  });

  it("surfaces durable outer conflicts without applying nested records", async () => {
    const test = fixture();
    const conflicting = signed(ALICE, 0, ZERO, "ACTION", { ok: true });
    test.store.records.set(key(conflicting), conflicting);
    await expect(test.receiver.receiveResponse(response(history()), request())).resolves.toMatchObject({
      status: "stopped", stage: "outer", reason: "durable_conflict", receipts: [], outerStatus: null,
    });
    expect(test.historyCalls).toEqual([]);
  });

  it.each(["outer", "history"] as const)("reports %s persistence failure and supports retry", async (stage) => {
    const test = fixture({ maxPendingResponses: 1 });
    test.store.beforeCommit = async (artifact) => {
      if ((stage === "outer" && artifact.envelope.type === "SYNC_RESP") ||
          (stage === "history" && bytesEqual(artifact.envelope.from, BOB.publicKey) && artifact.envelope.seq === 1)) {
        test.store.beforeCommit = null;
        throw new Error("storage failure");
      }
    };
    const outer = response(history());
    await expect(test.receiver.receiveResponse(outer, request())).resolves.toMatchObject({
      status: "failed", stage, index: stage === "outer" ? null : 1,
      receipts: stage === "outer" ? [] : ["accepted"],
      error: expect.objectContaining({ message: "storage failure" }),
    });
    await expect(test.receiver.receiveResponse(outer, request())).resolves.toMatchObject({
      status: "range_received",
      receipts: stage === "outer" ? ["accepted", "accepted"] : ["duplicate", "accepted"],
    });
  });

  it("records a durably accepted terminal failure but never reports range success", async () => {
    const test = fixture();
    test.history.receive = async (artifact) => {
      const receipt = await test.controls.receive(artifact);
      return { status: "failed", received: receipt.received };
    };
    await expect(test.receiver.receiveResponse(response(history()), request())).resolves.toEqual({
      status: "stopped", stage: "history", index: 0, reason: "terminal_history_failure",
      outerStatus: "accepted", receipts: ["failed"],
    });
    expect(test.store.records.size).toBe(2);
  });

  it.each(["uncommitted", "wrong_artifact", "bad_status"] as const)("rejects a misleading history receipt: %s", async (mode) => {
    const test = fixture();
    test.history.receive = async (received) => ({
      status: mode === "bad_status" ? "complete" : "accepted",
      received: mode === "wrong_artifact" ? signed(CAROL, 0, ZERO) : received,
    } as SyncHistoryReceiveResult);
    await expect(test.receiver.receiveResponse(response(history()), request())).resolves.toMatchObject({
      status: "failed", stage: "history", index: 0, receipts: [], outerStatus: "accepted",
    });
    expect(test.store.records.size).toBe(1);
  });

  it("snapshots queued caller data and isolates history-dispatch arguments", async () => {
    const test = fixture();
    test.history.receive = async (artifact) => {
      const receiving = test.controls.receive(artifact);
      artifact.canonicalBytes.fill(0xff);
      return receiving;
    };
    const records = history();
    const outer = response(records);
    const expected = outer.hash.slice();
    const requested = request();
    const receiving = test.receiver.receiveResponse(outer, requested);
    outer.canonicalBytes.fill(0xff);
    outer.hash.fill(0xff);
    requested.from.fill(0xff);
    await expect(receiving).resolves.toMatchObject({ status: "range_received", receipts: ["accepted", "accepted"] });
    expect(test.registry.heads().find(({ from }) => bytesEqual(from, ALICE.publicKey))?.hash).toEqual(expected);
  });

  it("removes aborted queued responses immediately while preserving the active commit lock", async () => {
    const test = fixture({ maxPendingResponses: 2 });
    const commit = deferred();
    const started = deferred();
    test.store.beforeCommit = async () => { started.resolve(); await commit.promise; };
    const outer = response(history());
    const active = test.receiver.receiveResponse(outer, request());
    await started.promise;
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const signal = new Cancellation();
      const queued = test.receiver.receiveResponse(outer, request(), { signal });
      signal.abort();
      await expect(queued).resolves.toEqual({ status: "cancelled", outerStatus: null, receipts: [] });
      expect(signal.listeners.size).toBe(0);
    }
    const queued = test.receiver.receiveResponse(outer, request());
    await expect(test.receiver.receiveResponse(outer, request())).rejects.toThrow(/Pending synchronization response limit/);
    expect(test.store.calls).toHaveLength(1);
    commit.resolve();
    await expect(active).resolves.toMatchObject({ status: "range_received" });
    await expect(queued).resolves.toMatchObject({ status: "range_received", outerStatus: "duplicate" });
  });

  it.each(["outer", "history"] as const)("waits for an already-submitted %s commit after cancellation", async (stage) => {
    const test = fixture();
    const signal = new Cancellation();
    const started = deferred();
    const commit = deferred();
    test.store.beforeCommit = async (artifact) => {
      if ((stage === "outer" && artifact.envelope.type === "SYNC_RESP") ||
          (stage === "history" && bytesEqual(artifact.envelope.from, BOB.publicKey))) {
        started.resolve();
        await commit.promise;
      }
    };
    let settled = false;
    const pending = test.receiver.receiveResponse(response(history()), request(), { signal }).then((result) => {
      settled = true;
      return result;
    });
    await started.promise;
    signal.abort();
    await Promise.resolve();
    expect(settled).toBe(false);
    commit.resolve();
    await expect(pending).resolves.toEqual({
      status: "cancelled", outerStatus: "accepted", receipts: stage === "outer" ? [] : ["accepted"],
    });
    expect(test.store.records.size).toBe(stage === "outer" ? 1 : 2);
    expect(signal.listeners.size).toBe(0);
  });

  it("cancels before admission without reading the response", async () => {
    const test = fixture();
    const signal = new Cancellation();
    signal.abort();
    const candidate = { get canonicalBytes(): never { throw new Error("must not inspect"); } } as unknown as EnvelopeArtifact;
    await expect(test.receiver.receiveResponse(candidate, request(), { signal })).resolves.toEqual({
      status: "cancelled", outerStatus: null, receipts: [],
    });
    expect(test.store.calls).toEqual([]);
  });

  it("enforces range, response, queue byte, and nested-count bounds", async () => {
    const outer = response(history());
    await expect(fixture({ maxEnvelopes: 1 }).receiver.receiveResponse(outer, request())).rejects.toThrow(/envelope limit/);
    await expect(fixture({ maxResponseBytes: outer.canonicalBytes.length - 1 }).receiver.receiveResponse(outer, request())).rejects.toThrow(/byte limit/);
    await expect(fixture({ maxEnvelopes: 1 }).receiver.receiveResponse(outer, request(BOB, 0, 0))).resolves.toMatchObject({
      status: "stopped", stage: "preflight", reason: "limit_exceeded", outerStatus: null,
    });
    const test = fixture({ maxPendingBytes: outer.canonicalBytes.length });
    const commit = deferred();
    test.store.beforeCommit = () => commit.promise;
    const first = test.receiver.receiveResponse(outer, request());
    await expect(test.receiver.receiveResponse(outer, request())).rejects.toThrow(/byte limit/);
    commit.resolve();
    await first;
    await expect(test.receiver.receiveResponse(outer, request())).resolves.toMatchObject({ status: "range_received" });
  });

  it("rejects incompatible construction and invalid limits", () => {
    const test = fixture();
    expect(test.controls.isBoundTo(test.registry)).toBe(true);
    expect(() => new PersistentSyncReceiver(new SessionChainRegistry(GAME, ROSTER), test.controls, test.history)).toThrow(/bound to its registry/);
    expect(() => new PersistentSyncReceiver(test.registry, test.controls, {} as SyncHistoryReceiver)).toThrow(/semantic-capable/);
    for (const key of ["maxEnvelopes", "maxResponseBytes", "maxPendingResponses", "maxPendingBytes"] as const) {
      expect(() => fixture({ [key]: 0 })).toThrow(/positive safe integers/);
    }
  });

  it("rolls back failed cancellation-listener registration without submitting work", async () => {
    const test = fixture({ maxPendingResponses: 1 });
    const broken: SyncCancellationSignal = {
      aborted: false,
      addEventListener() { throw new Error("registration failed"); },
      removeEventListener() { throw new Error("cleanup failed"); },
    };
    const outer = response(history());
    await expect(test.receiver.receiveResponse(outer, request(), { signal: broken })).rejects.toThrow(/registration failed/);
    expect(test.store.calls).toEqual([]);
    await expect(test.receiver.receiveResponse(outer, request())).resolves.toMatchObject({ status: "range_received" });
  });
});

function fixture(options: PersistentSyncReceiverOptions = {}) {
  const registry = new SessionChainRegistry(GAME, ROSTER);
  const store = new MemoryStore();
  const controls = new PersistentSessionReceiver(registry, store);
  const historyCalls: EnvelopeArtifact[] = [];
  const history: SyncHistoryReceiver = {
    async receive(received) {
      historyCalls.push(decodeAndVerifyEnvelope(received.canonicalBytes));
      if (received.envelope.type !== "ACTION") {
        return { status: "rejected", reason: "unsupported_history", received };
      }
      if ((received.envelope.body as CborMap)["ok"] !== true) {
        return { status: "rejected", reason: "invalid_history", received };
      }
      return controls.receive(received);
    },
  };
  return { registry, store, controls, history, historyCalls, receiver: new PersistentSyncReceiver(registry, controls, history, options) };
}

class MemoryStore implements AcceptedEnvelopeStore {
  readonly records = new Map<string, EnvelopeArtifact>();
  readonly calls: EnvelopeArtifact[] = [];
  beforeCommit: ((artifact: EnvelopeArtifact) => Promise<void>) | null = null;

  async persistAcceptedEnvelope(candidate: EnvelopeArtifact) {
    const artifact = decodeAndVerifyEnvelope(candidate.canonicalBytes);
    this.calls.push(artifact);
    await this.beforeCommit?.(artifact);
    const existing = this.records.get(key(artifact));
    if (existing !== undefined) {
      return bytesEqual(existing.canonicalBytes, artifact.canonicalBytes)
        ? { status: "duplicate" as const, record: { artifact: existing } }
        : { status: "conflict" as const, existing: { artifact: existing }, received: artifact };
    }
    this.records.set(key(artifact), artifact);
    return { status: "stored" as const, record: { artifact } };
  }
}

class Cancellation implements SyncCancellationSignal {
  aborted = false;
  readonly listeners = new Set<() => void>();
  addEventListener(_type: "abort", listener: () => void): void { this.listeners.add(listener); }
  removeEventListener(_type: "abort", listener: () => void): void { this.listeners.delete(listener); }
  abort(): void {
    this.aborted = true;
    for (const listener of [...this.listeners]) { listener(); }
  }
}

function identity(fill: number) {
  const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(fill));
  return { secretKey, publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)) };
}

function signed(author: ReturnType<typeof identity>, seq: number, prev: Hash256, type: EnvelopeMessageType = "ACTION", body: CborValue = { ok: true }): EnvelopeArtifact {
  return signEnvelope({ v: 1, game: GAME, from: author.publicKey, seq, prev, round: 1, phase: "play", type, body }, author.secretKey);
}

function history(author = BOB): EnvelopeArtifact[] {
  const first = signed(author, 0, ZERO);
  return [first, signed(author, 1, first.hash)];
}

function response(envelopes: readonly EnvelopeArtifact[], author = ALICE, seq = 0, prev = ZERO): EnvelopeArtifact {
  return signed(author, seq, prev, "SYNC_RESP", encodeSyncResponseBody({ envelopes }));
}

function request(author = BOB, fromSeq = 0, toSeq = 1): SyncRequestBody {
  return { from: parseIdentityPublicKey(author.publicKey), fromSeq, toSeq };
}

function key(artifact: EnvelopeArtifact): string {
  return `${bytesToHex(artifact.envelope.from)}:${artifact.envelope.seq}`;
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((complete) => { resolve = complete; });
  return { promise, resolve };
}
