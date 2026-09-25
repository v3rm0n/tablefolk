import { describe, expect, it } from "vitest";
import type { SaskuHandScore } from "@p2pcards/rules-sasku";
import { parseRoundCompletionMarker, roundCompletionMarker, sameRoundCompletion } from "./round-completion-marker";

const score: SaskuHandScore = { kind: "simple_win", winner: 0, gamePoints: [2, 0], basePoints: 2, bonusPoints: 0 };

describe("round completion marker", () => {
  it("binds the exact audited score and round to a bounded transport marker", () => {
    const first = roundCompletionMarker(1, score);
    expect(first).toHaveLength(34);
    expect(parseRoundCompletionMarker(first)).toEqual(first);
    expect(sameRoundCompletion(first, roundCompletionMarker(1, { ...score }))).toBe(true);
    expect(sameRoundCompletion(first, roundCompletionMarker(2, score))).toBe(false);
    expect(sameRoundCompletion(first, roundCompletionMarker(1, { ...score, gamePoints: [0, 2] }))).toBe(false);
    expect(() => parseRoundCompletionMarker(first.subarray(0, 33))).toThrow();
    expect(() => roundCompletionMarker(33, score)).toThrow();
  });
});
