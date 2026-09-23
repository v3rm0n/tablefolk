export const SASKU_TOTAL_CARD_POINTS = 120;
export const SASKU_TRICKS_PER_HAND = 9;
export const SASKU_SUITS = Object.freeze(["clubs", "spades", "hearts", "diamonds"] as const);
export const SASKU_CARD_POINTS = Object.freeze({ ace: 11, ten: 10, king: 4, queen: 3, jack: 2, other: 0 });
export const SASKU_COURT_ORDER = Object.freeze(SASKU_SUITS.flatMap((suit) =>
  (["king", "queen", "jack"] as const).map((rank) => Object.freeze({ suit, rank })),
));

export type SaskuSuit = (typeof SASKU_SUITS)[number];
export type SaskuSeat = 0 | 1 | 2 | 3;
export type SaskuPartnership = 0 | 1;
export type SaskuContract =
  | { readonly kind: "named"; readonly suit: SaskuSuit; readonly declarerSeat: SaskuSeat }
  | { readonly kind: "pass_round" };

export interface SaskuHandTotals {
  readonly cardPoints: readonly [number, number];
  readonly tricks: readonly [number, number];
  readonly contract: SaskuContract;
}

export type SaskuScoreKind = "simple_win" | "seajann" | "jann" | "karvane" | "pokk" | "pass_round_win" | "pass_round_tie";

export interface SaskuHandScore {
  readonly kind: SaskuScoreKind;
  readonly winner: SaskuPartnership | null;
  readonly gamePoints: readonly [number, number];
  readonly basePoints: number;
  readonly bonusPoints: number;
}

export class SaskuScoringError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SaskuScoringError";
  }
}

// Four copies of each scoring rank plus 16 zero-value cards in the 36 played cards.
// This validates point/count feasibility only, not ownership or legality of play.
const feasiblePoints = (() => {
  const table = Array.from({ length: 37 }, () => new Uint8Array(121));
  table[0]![0] = 1;
  const inventory = [...Object.values(SASKU_CARD_POINTS).filter((points) => points > 0).flatMap((points) => [points, points, points, points]), ...new Array<number>(16).fill(0)];
  for (const points of inventory) {
    for (let count = 35; count >= 0; count -= 1) {
      for (let sum = 120 - points; sum >= 0; sum -= 1) {
        if (table[count]![sum] === 1) { table[count + 1]![sum + points] = 1; }
      }
    }
  }
  return table;
})();

export function partnershipForSeat(seat: number): SaskuPartnership {
  integer(seat, 3, "Seat");
  return seat % 2 as SaskuPartnership;
}

/** Score an already completed hand. This does not validate bids, trick winners, or hidden-hand legality. */
export function scoreSaskuHand(input: SaskuHandTotals): SaskuHandScore {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new SaskuScoringError("Completed hand totals are required");
  }
  const points = pair(input.cardPoints, SASKU_TOTAL_CARD_POINTS, "Card points");
  const tricks = pair(input.tricks, SASKU_TRICKS_PER_HAND, "Tricks");
  if (points[0] + points[1] !== SASKU_TOTAL_CARD_POINTS) {
    throw new SaskuScoringError("Both partnerships' card points must add up to 120");
  }
  if (tricks[0] + tricks[1] !== SASKU_TRICKS_PER_HAND) {
    throw new SaskuScoringError("Both partnerships' tricks must add up to nine");
  }
  if (feasiblePoints[tricks[0] * 4]![points[0]] !== 1) {
    throw new SaskuScoringError("Those card points and trick counts are not possible with the scoring-card inventory");
  }
  const contract = input.contract;
  if (typeof contract !== "object" || contract === null || Array.isArray(contract)) {
    throw new SaskuScoringError("A named trump contract or an explicit pass-round is required");
  }
  const keys = Object.keys(contract).sort().join(",");
  if (contract.kind === "pass_round") {
    if (keys !== "kind") { throw new SaskuScoringError("A pass-round has default diamonds and no declarer"); }
    return points[0] === points[1]
      ? result("pass_round_tie", null, 0, 0)
      : result("pass_round_win", points[0] > points[1] ? 0 : 1, 2, 0);
  }
  if (contract.kind !== "named" || keys !== "declarerSeat,kind,suit" || !SASKU_SUITS.includes(contract.suit)) {
    throw new SaskuScoringError("Named trump requires a supported suit and the declaring seat");
  }
  const declaringSide = partnershipForSeat(contract.declarerSeat);
  if (points[0] === points[1]) {
    return result("pokk", declaringSide === 0 ? 1 : 0, 2, 0);
  }
  const winner = points[0] > points[1] ? 0 : 1;
  if (tricks[winner === 0 ? 1 : 0] === 0) {
    return result("karvane", winner, 12, 0);
  }
  const base = (winner === declaringSide ? 2 : 4) + (contract.suit === "diamonds" ? 2 : 0);
  const winningPoints = points[winner];
  const bonus = winningPoints === 90 ? 1 : winningPoints >= 91 ? 2 : 0;
  return result(bonus === 1 ? "seajann" : bonus === 2 ? "jann" : "simple_win", winner, base, bonus);
}

function result(kind: SaskuScoreKind, winner: SaskuPartnership | null, basePoints: number, bonusPoints: number): SaskuHandScore {
  const total = basePoints + bonusPoints;
  const gamePoints: [number, number] = winner === null ? [0, 0] : winner === 0 ? [total, 0] : [0, total];
  return Object.freeze({ kind, winner, gamePoints: Object.freeze(gamePoints), basePoints, bonusPoints });
}

function pair(value: readonly [number, number], maximum: number, name: string): readonly [number, number] {
  if (!Array.isArray(value) || value.length !== 2) { throw new SaskuScoringError(`${name} must contain two partnership totals`); }
  return [integer(value[0], maximum, name), integer(value[1], maximum, name)];
}

function integer(value: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum || Object.is(value, -0)) {
    throw new SaskuScoringError(`${name} must be whole numbers from zero to ${maximum}`);
  }
  return value;
}
