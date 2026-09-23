import { describe, expect, it } from "vitest";
import {
  SASKU_CARD_POINTS, SASKU_COURT_ORDER, SASKU_SUITS, SaskuScoringError,
  partnershipForSeat, scoreSaskuHand,
  type SaskuContract, type SaskuHandTotals, type SaskuSeat,
} from "./scoring";

describe("Sasku completed-hand scoring", () => {
  it("keeps opposite seats in fixed partnerships and profiles the stated court order", () => {
    expect([0, 1, 2, 3].map(partnershipForSeat)).toEqual([0, 1, 0, 1]);
    expect(SASKU_COURT_ORDER.map(({ rank, suit }) => `${rank}:${suit}`)).toEqual([
      "king:clubs", "queen:clubs", "jack:clubs", "king:spades", "queen:spades", "jack:spades",
      "king:hearts", "queen:hearts", "jack:hearts", "king:diamonds", "queen:diamonds", "jack:diamonds",
    ]);
    expect(SASKU_CARD_POINTS).toEqual({ ace: 11, ten: 10, king: 4, queen: 3, jack: 2, other: 0 });
    expect(Object.values(SASKU_CARD_POINTS).reduce<number>((sum, value) => sum + value * 4, 0)).toBe(120);
  });

  for (const suit of SASKU_SUITS) {
    for (const seat of [0, 1, 2, 3] as const) {
      it.each([61, 89, 90, 91, 118, 120])(`scores ${suit}, declarer seat ${seat}, winner card points %i`, (cardPoints) => {
        const base = (seat % 2 === 0 ? 2 : 4) + (suit === "diamonds" ? 2 : 0);
        const bonus = cardPoints === 90 ? 1 : cardPoints >= 91 ? 2 : 0;
        const score = scoreSaskuHand(totals(cardPoints, 5, { kind: "named", suit, declarerSeat: seat }));
        expect(score).toEqual({
          kind: bonus === 0 ? "simple_win" : bonus === 1 ? "seajann" : "jann",
          winner: 0, gamePoints: [base + bonus, 0], basePoints: base, bonusPoints: bonus,
        });
      });
    }
  }

  it.each([0, 1, 2, 3] as const)("awards pokk to the non-declaring partnership, declarer %i", (seat) => {
    for (const suit of SASKU_SUITS) {
      expect(scoreSaskuHand(totals(60, 4, { kind: "named", suit, declarerSeat: seat }))).toEqual({
        kind: "pokk", winner: seat % 2 === 0 ? 1 : 0,
        gamePoints: seat % 2 === 0 ? [0, 2] : [2, 0], basePoints: 2, bonusPoints: 0,
      });
    }
  });

  it("uses tricks, not a zero card-point total, to identify karvane", () => {
    for (const suit of SASKU_SUITS) {
      for (const declarerSeat of [0, 1, 2, 3] as const) {
        const contract: SaskuContract = { kind: "named", suit, declarerSeat };
        expect(scoreSaskuHand(totals(120, 9, contract))).toEqual({
          kind: "karvane", winner: 0, gamePoints: [12, 0], basePoints: 12, bonusPoints: 0,
        });
        expect(scoreSaskuHand(totals(120, 5, contract)).kind).toBe("jann");
      }
    }
  });

  it("makes pass-round scoring override named-diamonds, bonuses, karvane, and pokk", () => {
    for (const cardPoints of [61, 89, 90, 91, 118, 120]) {
      expect(scoreSaskuHand(totals(cardPoints, 5, { kind: "pass_round" }))).toEqual({
        kind: "pass_round_win", winner: 0, gamePoints: [2, 0], basePoints: 2, bonusPoints: 0,
      });
    }
    expect(scoreSaskuHand(totals(120, 9, { kind: "pass_round" })).gamePoints).toEqual([2, 0]);
    expect(scoreSaskuHand(totals(60, 4, { kind: "pass_round" }))).toEqual({
      kind: "pass_round_tie", winner: null, gamePoints: [0, 0], basePoints: 0, bonusPoints: 0,
    });
    expect(scoreSaskuHand(totals(90, 5, { kind: "named", suit: "diamonds", declarerSeat: 1 })).gamePoints).toEqual([7, 0]);
  });

  it("is symmetric under partnership exchange across every feasible total/count pair", () => {
    let checked = 0;
    for (let points = 0; points <= 120; points += 1) {
      for (let tricks = 0; tricks <= 9; tricks += 1) {
        let original;
        try { original = scoreSaskuHand(totals(points, tricks)); }
        catch (error) { expect(error).toBeInstanceOf(SaskuScoringError); continue; }
        const swapped = scoreSaskuHand(totals(120 - points, 9 - tricks, { kind: "named", suit: "clubs", declarerSeat: 1 }));
        expect(swapped.gamePoints).toEqual([...original.gamePoints].reverse());
        expect(swapped.kind).toBe(original.kind);
        expect(swapped.basePoints).toBe(original.basePoints);
        expect(swapped.bonusPoints).toBe(original.bonusPoints);
        expect(original.gamePoints.filter((value) => value > 0)).toHaveLength(1);
        checked += 1;
      }
    }
    expect(checked).toBeGreaterThan(500);
  });

  it.each([
    { cardPoints: [60, 59] },
    { tricks: [4, 4] },
    { cardPoints: [121, -1] },
    { cardPoints: [NaN, 60] },
    { cardPoints: [60.5, 59.5] },
    { cardPoints: [-0, 120] },
    { tricks: [1.5, 7.5] },
    { cardPoints: [1, 119], tricks: [1, 8] },
    { cardPoints: [119, 1], tricks: [8, 1] },
    { cardPoints: [120, 0], tricks: [4, 5] },
    { cardPoints: [61, 59], tricks: [1, 8] },
    { cardPoints: [90, 30], tricks: [2, 7] },
    { cardPoints: [0, 120], tricks: [0, 8] },
  ])("rejects inconsistent or impossible completed-hand totals: %j", (invalid) => {
    expect(() => scoreSaskuHand({ ...totals(75, 5), ...invalid } as unknown as SaskuHandTotals)).toThrow(SaskuScoringError);
  });

  it.each([
    null,
    { kind: "named", suit: "stars", declarerSeat: 0 },
    { kind: "named", suit: "clubs", declarerSeat: 4 },
    { kind: "named", suit: "clubs", declarerSeat: -1 },
    { kind: "named", suit: "clubs", declarerSeat: 0.5 },
    { kind: "named", suit: "clubs" },
    { kind: "pass_round", suit: "clubs" },
    { kind: "pass_round", declarerSeat: 0 },
    { kind: "unknown" },
  ])("rejects ambiguous or malformed contracts: %j", (contract) => {
    expect(() => scoreSaskuHand(totals(75, 5, contract as SaskuContract))).toThrow(SaskuScoringError);
  });

  it("does not mutate inputs or expose mutable output totals", () => {
    const points: [number, number] = [90, 30];
    const tricks: [number, number] = [5, 4];
    const input = { cardPoints: points, tricks, contract: { kind: "named", suit: "clubs", declarerSeat: 0 } as const };
    const score = scoreSaskuHand(input);
    expect(points).toEqual([90, 30]);
    points[0] = 0;
    tricks[0] = 0;
    expect(score.gamePoints).toEqual([3, 0]);
    expect(Object.isFrozen(score)).toBe(true);
    expect(Object.isFrozen(score.gamePoints)).toBe(true);
    expect(() => scoreSaskuHand({ ...input, tricks: [9] } as unknown as SaskuHandTotals)).toThrow();
    expect(() => partnershipForSeat(10 as SaskuSeat)).toThrow();
  });
});

function totals(points: number, tricks: number, contract: SaskuContract = { kind: "named", suit: "clubs", declarerSeat: 0 }): SaskuHandTotals {
  return { cardPoints: [points, 120 - points], tricks: [tricks, 9 - tricks], contract };
}
