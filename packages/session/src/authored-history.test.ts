import { deriveEd25519PublicKey, importEd25519SecretKey } from "@p2pcards/crypto";
import {
  decodeAndVerifyEnvelope, parseGameId, parseHash256, parseIdentityPublicKey, signEnvelope,
  type EnvelopeArtifact,
} from "@p2pcards/protocol";
import { describe, expect, it, vi } from "vitest";

import { replayAuthoredHistory, DEFAULT_MAX_AUTHORED_REPLAY_ENVELOPES, type AuthoredHistoryStore } from "./authored-history";

const SECRET = importEd25519SecretKey(new Uint8Array(32).fill(111));
const SELF = parseIdentityPublicKey(deriveEd25519PublicKey(SECRET));
const GAME = parseGameId(new Uint8Array(16).fill(0x71));
const ZERO = parseHash256(new Uint8Array(32));

describe("authored history replay", () => {
  it("verifies the whole prefix before sending byte-identical original envelopes", async () => {
    const records = chain(3);
    const source = historyStore(records, 1);
    const send = vi.fn(async (payload: Uint8Array) => {
      expect(source.readAuthoredPage.mock.calls.length).toBeGreaterThanOrEqual(4);
      expect(payload).toEqual(records[send.mock.calls.length - 1]!.canonicalBytes);
      payload.fill(0xff);
    });
    const result = await replayAuthoredHistory(source, GAME, SELF, send);
    expect(result).toEqual({
      status: "replayed", checkpoint: { from: SELF, seq: 2, hash: records[2]!.hash },
      submittedCount: 3, submittedBytes: records.reduce((sum, value) => sum + value.canonicalBytes.length, 0),
    });
    expect(source.readAuthoredHead).toHaveBeenCalledTimes(1);
    expect(source.readAuthoredPage).toHaveBeenCalledTimes(6);
    expect(records.map((value) => decodeAndVerifyEnvelope(value.canonicalBytes).envelope.seq)).toEqual([0, 1, 2]);
  });

  it("ignores misleading artifact views and snapshots scope before asynchronous reads", async () => {
    const records = chain(2);
    const source = historyStore(records);
    source.readAuthoredHead.mockResolvedValue({ ...records[1]!, hash: ZERO, envelope: { ...records[1]!.envelope, seq: 0 } });
    const game = parseGameId(GAME);
    const self = parseIdentityPublicKey(SELF);
    const send = vi.fn(async () => undefined);
    const replaying = replayAuthoredHistory(source, game, self, send);
    game.fill(0xff);
    self.fill(0xff);
    await expect(replaying).resolves.toMatchObject({ status: "replayed", checkpoint: { seq: 1, hash: records[1]!.hash }, submittedCount: 2 });
    expect(source.readAuthoredPage.mock.calls.every(([game, sender]) =>
      game.every((value, index) => value === GAME[index]) && sender.every((value, index) => value === SELF[index]),
    )).toBe(true);
  });

  it("does not chase appends beyond the captured checkpoint", async () => {
    const records = chain(3);
    const source = historyStore(records);
    source.readAuthoredHead.mockResolvedValue(records[1]!);
    const sent: Uint8Array[] = [];
    await expect(replayAuthoredHistory(source, GAME, SELF, async (bytes) => { sent.push(bytes); })).resolves.toMatchObject({
      status: "replayed", checkpoint: { seq: 1 }, submittedCount: 2,
    });
    expect(sent).toEqual(records.slice(0, 2).map(({ canonicalBytes }) => canonicalBytes));
  });

  it("sends nothing when a late verification page is corrupt", async () => {
    const records = chain(3);
    const source = historyStore(records, 1);
    source.readAuthoredPage.mockImplementation(async (_game, _sender, from) => {
      if (from === 2) {
        return [{ ...records[2]!, canonicalBytes: new Uint8Array([0xff]) as EnvelopeArtifact["canonicalBytes"] }];
      }
      return [records[from]!];
    });
    const send = vi.fn(async () => undefined);
    await expect(replayAuthoredHistory(source, GAME, SELF, send)).resolves.toMatchObject({ status: "failed", stage: "verify", submittedCount: 0 });
    expect(send).not.toHaveBeenCalled();
  });

  it.each(["genesis", "cross_page_link", "checkpoint"] as const)("rejects an invalid %s before any transmission", async (mode) => {
    const records = chain(2);
    if (mode === "genesis") {
      records[0] = signEnvelope({ ...records[0]!.envelope, prev: parseHash256(new Uint8Array(32).fill(9)) }, SECRET);
    } else if (mode === "cross_page_link") {
      records[1] = signEnvelope({ ...records[1]!.envelope, prev: ZERO }, SECRET);
    }
    const source = historyStore(records, 1);
    if (mode === "checkpoint") {
      source.readAuthoredHead.mockResolvedValue(signEnvelope({ ...records[1]!.envelope, body: { heads: [], marker: "another checkpoint" } }, SECRET));
    }
    const send = vi.fn(async () => undefined);
    await expect(replayAuthoredHistory(source, GAME, SELF, send)).resolves.toMatchObject({ status: "failed", stage: "verify", submittedCount: 0 });
    expect(send).not.toHaveBeenCalled();
  });

  it("revalidates the sending pass against captured page hashes", async () => {
    const records = chain(2);
    const source = historyStore(records);
    const changed = signEnvelope({ ...records[1]!.envelope, body: { heads: [], marker: "changed" } }, SECRET);
    source.readAuthoredPage.mockResolvedValueOnce(records).mockResolvedValue([records[0]!, changed]);
    const send = vi.fn(async () => undefined);
    await expect(replayAuthoredHistory(source, GAME, SELF, send)).resolves.toMatchObject({ status: "failed", stage: "send", submittedCount: 0 });
    expect(send).not.toHaveBeenCalled();
  });

  it("accepts shorter second-pass prefixes but verifies their captured endpoint before sending", async () => {
    const records = chain(2);
    const source = historyStore(records);
    source.readAuthoredPage.mockResolvedValueOnce(records)
      .mockImplementation(async (_game, _sender, from) => [records[from]!]);
    const send = vi.fn(async () => {
      expect(source.readAuthoredPage).toHaveBeenCalledTimes(3);
    });
    await expect(replayAuthoredHistory(source, GAME, SELF, send)).resolves.toMatchObject({ status: "replayed", submittedCount: 2 });
    expect(send).toHaveBeenCalledTimes(2);
  });

  it.each(["empty", "extra", "wrong_game", "wrong_sender"] as const)("rejects a %s page", async (mode) => {
    const records = chain(2);
    const source = historyStore(records);
    let page = records;
    if (mode === "empty") { page = []; }
    if (mode === "extra") { page = [...records, records[1]!]; }
    if (mode === "wrong_game") {
      page = [signEnvelope({ ...records[0]!.envelope, game: parseGameId(new Uint8Array(16).fill(7)) }, SECRET)];
    }
    if (mode === "wrong_sender") {
      const secret = importEd25519SecretKey(new Uint8Array(32).fill(3));
      page = [signEnvelope({ ...records[0]!.envelope, from: parseIdentityPublicKey(deriveEd25519PublicKey(secret)) }, secret)];
    }
    source.readAuthoredPage.mockResolvedValue(page);
    await expect(replayAuthoredHistory(source, GAME, SELF, async () => undefined)).resolves.toMatchObject({ status: "failed", stage: "verify", submittedCount: 0 });
  });

  it("bounds total envelopes and bytes without requesting an unbounded range", async () => {
    const records = chain(2);
    const source = historyStore(records);
    source.readAuthoredHead.mockResolvedValue(signEnvelope({ ...records[1]!.envelope, seq: DEFAULT_MAX_AUTHORED_REPLAY_ENVELOPES }, SECRET));
    await expect(replayAuthoredHistory(source, GAME, SELF, async () => undefined)).resolves.toMatchObject({ status: "failed", stage: "head" });
    expect(source.readAuthoredPage).not.toHaveBeenCalled();
    const bytes = records.reduce((sum, value) => sum + value.canonicalBytes.length, 0);
    await expect(replayAuthoredHistory(historyStore(records), GAME, SELF, async () => undefined, { maxBytes: bytes - 1 })).resolves.toMatchObject({
      status: "failed", stage: "verify", submittedCount: 0,
    });
  });

  it("reports only confirmed submissions when a send fails or cancellation arrives", async () => {
    const records = chain(3);
    let calls = 0;
    const failed = await replayAuthoredHistory(historyStore(records), GAME, SELF, async () => {
      if (++calls === 2) { throw new Error("channel unavailable"); }
    });
    expect(failed).toMatchObject({ status: "failed", stage: "send", submittedCount: 1, submittedBytes: records[0]!.canonicalBytes.length });
    const signal = { aborted: false, addEventListener() {}, removeEventListener() {} };
    const cancelled = await replayAuthoredHistory(historyStore(records), GAME, SELF, async () => { signal.aborted = true; }, { signal });
    expect(cancelled).toMatchObject({ status: "cancelled", submittedCount: 1 });
  });

  it("handles empty history and cancellation without inventing readiness", async () => {
    const source = historyStore([]);
    const send = vi.fn(async () => undefined);
    await expect(replayAuthoredHistory(source, GAME, SELF, send)).resolves.toEqual({
      status: "replayed", checkpoint: null, submittedCount: 0, submittedBytes: 0,
    });
    source.readAuthoredHead.mockClear();
    await expect(replayAuthoredHistory(source, GAME, SELF, send, {
      signal: { aborted: true, addEventListener() {}, removeEventListener() {} },
    })).resolves.toMatchObject({ status: "cancelled", checkpoint: null });
    expect(source.readAuthoredHead).not.toHaveBeenCalled();
    expect(send).not.toHaveBeenCalled();
  });

  it("replays only a suffix anchored to a previously verified live prefix", async () => {
    const records = chain(4), source = historyStore(records, 1), sent: Uint8Array[] = [];
    const after = { from: SELF, seq: 1, hash: records[1]!.hash };
    const result = await replayAuthoredHistory(source, GAME, SELF, async bytes => { sent.push(bytes); }, { after });
    expect(result).toMatchObject({ status: "replayed", checkpoint: { seq: 3 }, submittedCount: 2 });
    expect(sent).toEqual(records.slice(2).map(record => record.canonicalBytes));
    expect(source.readAuthoredPage.mock.calls.every(([, , from]) => from >= 1)).toBe(true);
    source.readAuthoredPage.mockClear();
    await expect(replayAuthoredHistory(source, GAME, SELF, async () => undefined,
      { after: { from: SELF, seq: 3, hash: records[3]!.hash } })).resolves.toMatchObject({ status: "replayed", submittedCount: 0 });
    expect(source.readAuthoredPage).toHaveBeenCalledTimes(1);
  });

  it("rejects a changed or missing live prefix before sending the suffix", async () => {
    const records = chain(3), source = historyStore(records), send = vi.fn(async () => undefined);
    const after = { from: SELF, seq: 1, hash: records[1]!.hash };
    const changed = signEnvelope({ ...records[1]!.envelope, body: { heads: [], changed: true } }, SECRET);
    source.readAuthoredPage.mockImplementation(async (_game, _sender, from, to) =>
      from === 1 && to === 1 ? [changed] : records.slice(from, to + 1));
    await expect(replayAuthoredHistory(source, GAME, SELF, send, { after })).resolves.toMatchObject({ status: "failed", stage: "verify", submittedCount: 0 });
    expect(send).not.toHaveBeenCalled();
    await expect(replayAuthoredHistory(historyStore([]), GAME, SELF, send, { after })).resolves.toMatchObject({ status: "failed", stage: "head" });
  });

  it("rejects invalid limits and a send callback without an awaited result", async () => {
    const source = historyStore(chain(1));
    await expect(replayAuthoredHistory(source, GAME, SELF, async () => undefined, { maxBytes: 0 })).rejects.toThrow(/positive safe integers/);
    await expect(replayAuthoredHistory(source, GAME, SELF, () => undefined as unknown as Promise<void>)).resolves.toMatchObject({
      status: "failed", stage: "send", submittedCount: 0,
    });
  });
});

function chain(count: number): EnvelopeArtifact[] {
  const records: EnvelopeArtifact[] = [];
  for (let seq = 0; seq < count; seq += 1) {
    records.push(signEnvelope({
      v: 1, game: GAME, from: SELF, seq, prev: records.at(-1)?.hash ?? ZERO,
      round: 1, phase: "setup.keys", type: "WITNESS", body: { heads: [] },
    }, SECRET));
  }
  return records;
}

function historyStore(records: readonly EnvelopeArtifact[], pageSize = 128) {
  return {
    readAuthoredHead: vi.fn<AuthoredHistoryStore["readAuthoredHead"]>(async () => records.at(-1) ?? null),
    readAuthoredPage: vi.fn<AuthoredHistoryStore["readAuthoredPage"]>(async (_game, _sender, from, to) =>
      records.slice(from, Math.min(to + 1, from + pageSize))),
  };
}
