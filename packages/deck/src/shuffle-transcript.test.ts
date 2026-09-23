/// <reference types="node" />
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { asciiToBytes, bytesToHex, encodeRistrettoScalar, hexToBytes } from "@p2pcards/crypto";
import { CandidateShuffleTranscript } from "./shuffle-transcript";
import { parseGameId, proofChallengeInput } from "@p2pcards/protocol";
import { decodeCanonical } from "@p2pcards/encoding";

const fixture = JSON.parse(readFileSync(new URL("../test-vectors/shuffle-transcript.json", import.meta.url), "utf8")) as {
  root: string;
  operations: { kind: string; bytes: string; count?: number }[];
  challenges: { input: string; digest: string; scalar: string }[];
};
class Transcript extends CandidateShuffleTranscript {
  constructor(root: Uint8Array) { super(root, { gameId: hexToBytes("42".repeat(16)) as import("@p2pcards/protocol").GameId, round: 7, phase: "shuffle-2" }); }
}
const label = asciiToBytes("x");

describe("candidate SHA-512/CBOR shuffle transcript", () => {
  it("uses the existing game/round/phase framing at integer boundaries", () => {
    for (const round of [0, 23, 24, 255, 256, 65535, 65536, 4294967295, 4294967296, Number.MAX_SAFE_INTEGER]) {
      const context = { gameId: parseGameId(new Uint8Array(16)), round, phase: "shuffle-0" };
      const result = new CandidateShuffleTranscript(new Uint8Array([1]), context).challenge(label).read();
      const prefix = proofChallengeInput("shuffle", context, null).slice(0, -1);
      const statement = decodeCanonical(result.input.slice(prefix.length));
      expect(result.input).toEqual(proofChallengeInput("shuffle", context, statement));
    }
  });

  it("binds, captures, and strictly validates context", () => {
    const context = { gameId: parseGameId(new Uint8Array(16)), round: 0, phase: "shuffle-0" };
    const root = new Uint8Array([1]);
    const baseline = new CandidateShuffleTranscript(root, context).challenge(label).read();
    for (const changed of [{ ...context, round: 1 }, { ...context, phase: "shuffle-1" },
      { ...context, gameId: parseGameId(new Uint8Array(16).fill(1)) }]) {
      expect(new CandidateShuffleTranscript(root, changed).challenge(label).read().scalar).not.toBe(baseline.scalar);
    }
    const captured = new CandidateShuffleTranscript(root, context);
    context.gameId.fill(1); context.round = 1; context.phase = "changed";
    expect(captured.challenge(label).read()).toEqual(baseline);
    for (const round of [-0, -1, 0.5, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => new CandidateShuffleTranscript(root, { ...context, round })).toThrow();
    }
    for (const phase of ["", "a".repeat(65), "é"]) {
      expect(() => new CandidateShuffleTranscript(root, { ...context, phase })).toThrow();
    }
  });
  it("matches independently encoded Python/hashlib/big-integer vectors", () => {
    const transcript = new Transcript(hexToBytes(fixture.root));
    const results = [];
    for (const op of fixture.operations) {
      const bytes = hexToBytes(op.bytes);
      if (op.kind === "label") transcript.label(bytes);
      else if (op.kind === "append") transcript.appendPublicBytes(bytes);
      else {
        const reader = transcript.challenge(bytes);
        for (let i = 0; i < op.count!; i++) {
          const result = reader.read();
          results.push({ input: bytesToHex(result.input), digest: bytesToHex(result.digest), scalar: bytesToHex(encodeRistrettoScalar(result.scalar)) });
        }
      }
    }
    expect(results).toEqual(fixture.challenges);
  });

  it("binds context, labels, append values, ordering, and earlier challenges", () => {
    function result(root: number, first: number, second: number, name: string, prior: boolean) {
      const t = new Transcript(new Uint8Array([root]));
      t.label(asciiToBytes(name));
      t.appendPublicBytes(new Uint8Array([first]));
      t.appendPublicBytes(new Uint8Array([second]));
      const c = t.challenge(label);
      if (prior) c.read();
      return bytesToHex(c.read().digest);
    }
    const original = result(0, 1, 2, "a", false);
    for (const variant of [result(1, 1, 2, "a", false), result(0, 3, 2, "a", false),
      result(0, 2, 1, "a", false), result(0, 1, 2, "b", false), result(0, 1, 2, "a", true)]) {
      expect(variant).not.toBe(original);
    }
  });

  it("detaches roots, labels, appends, and exposed challenge buffers", () => {
    const root = new Uint8Array([1]), value = new Uint8Array([2]), name = label.slice();
    const t = new Transcript(root); root.fill(9);
    t.appendPublicBytes(value); value.fill(9);
    const reader = t.challenge(name); name.fill(9);
    const control = new Transcript(new Uint8Array([1])); control.appendPublicBytes(new Uint8Array([2]));
    const reference = control.challenge(label);
    const first = reader.read(); expect(first).toEqual(reference.read());
    first.input.fill(0); first.digest.fill(0);
    expect(reader.read()).toEqual(reference.read());
  });

  it("invalidates a reader after unrelated transcript advancement", () => {
    const t = new Transcript(new Uint8Array([1]));
    const reader = t.challenge(label); t.label(label);
    expect(() => reader.read()).toThrow(/Stale/);
    const a = t.challenge(label), b = t.challenge(label);
    a.read(); expect(() => b.read()).toThrow(/Stale/);
  });

  it("enforces read, byte, and event budgets without a partial append", () => {
    const t = new Transcript(new Uint8Array([1])), control = new Transcript(new Uint8Array([1]));
    for (let i = 0; i < 3; i++) { t.appendPublicBytes(new Uint8Array(8192)); control.appendPublicBytes(new Uint8Array(8192)); }
    expect(() => t.appendPublicBytes(new Uint8Array(8192))).toThrow(/event bound/);
    expect(t.challenge(label).read()).toEqual(control.challenge(label).read());
    const bounded = new Transcript(new Uint8Array([1]));
    const reader = bounded.challenge(label);
    for (let i = 0; i < 16; i++) reader.read();
    expect(() => reader.read()).toThrow(/count bound/);
    const events = new Transcript(new Uint8Array([1]));
    for (let i = 0; i < 128; i++) events.label(label);
    expect(() => events.label(label)).toThrow(/event bound/);
    expect(() => events.challenge(label).read()).toThrow(/event bound/);
  });

  it("rejects oversized, empty, and non-byte inputs at admission", () => {
    expect(() => new Transcript(new Uint8Array())).toThrow();
    expect(() => new Transcript(new Uint8Array(1025))).toThrow();
    const t = new Transcript(new Uint8Array([1]));
    for (const invalid of [new Uint8Array(), new Uint8Array(65)]) {
      expect(() => t.label(invalid)).toThrow(); expect(() => t.challenge(invalid)).toThrow();
    }
    expect(() => t.appendPublicBytes(new Uint8Array(8193))).toThrow();
    expect(() => t.appendPublicBytes(null as unknown as Uint8Array)).toThrow();
    class Subclass extends Uint8Array {}
    expect(() => new Transcript(new Subclass([1]))).toThrow();
  });
});
