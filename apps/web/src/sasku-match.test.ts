import { describe, expect, it } from "vitest";
import type { SaskuHandScore } from "@p2pcards/rules-sasku";
import { dealerForSaskuRound, INITIAL_SASKU_MATCH, recordSaskuRound } from "./sasku-match";

const award = (side: 0 | 1 | null, points: number): SaskuHandScore => ({
  kind: side === null ? "pass_round_tie" : "simple_win", winner: side,
  gamePoints: side === 0 ? [points, 0] : side === 1 ? [0, points] : [0, 0],
  basePoints: points, bonusPoints: 0,
});

describe("Sasku match", () => {
  it("rotates the dealer after zero-point hands and ends at twelve audited game points", () => {
    let match = recordSaskuRound(INITIAL_SASKU_MATCH, 3, award(null, 0));
    expect(match).toMatchObject({ round: 2, totals: [0, 0], winner: null });
    match = recordSaskuRound(match, 0, award(0, 4));
    match = recordSaskuRound(match, 1, award(1, 6));
    match = recordSaskuRound(match, 2, award(0, 8));
    expect(match).toMatchObject({ round: 4, totals: [12, 6], winner: 0 });
    expect(match.completed.map(item => item.dealer)).toEqual([3, 0, 1, 2]);
    expect(() => recordSaskuRound(match, 3, award(1, 2))).toThrow(/cannot accept/);
  });

  it("rejects a dealer that disagrees with the signed seat rotation", () => {
    expect(dealerForSaskuRound(1)).toBe(3);
    expect(dealerForSaskuRound(2)).toBe(0);
    expect(() => recordSaskuRound(INITIAL_SASKU_MATCH, 0, award(0, 2))).toThrow(/dealer rotation/);
  });
});
