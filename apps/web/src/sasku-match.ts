import type { SaskuHandScore, SaskuPartnership, SaskuSeat } from "@p2pcards/rules-sasku";

export const SASKU_MATCH_TARGET = 12;
export const MAX_SASKU_MATCH_ROUNDS = 32;

export interface CompletedSaskuRound {
  readonly round: number;
  readonly dealer: SaskuSeat;
  readonly score: SaskuHandScore;
}

export interface SaskuMatchState {
  readonly round: number;
  readonly totals: readonly [number, number];
  readonly completed: readonly CompletedSaskuRound[];
  readonly winner: SaskuPartnership | null;
}

export const INITIAL_SASKU_MATCH: SaskuMatchState = Object.freeze({
  round: 1, totals: Object.freeze([0, 0] as const), completed: Object.freeze([]), winner: null,
});

/** Call only with a completed, valid hand audit from the verified round receiver. */
export function recordSaskuRound(match: SaskuMatchState, dealer: SaskuSeat, score: SaskuHandScore): SaskuMatchState {
  if (match.winner !== null || match.round !== match.completed.length + 1 || match.round > MAX_SASKU_MATCH_ROUNDS) {
    throw new Error("Sasku match cannot accept another round");
  }
  const expectedDealer = ((3 + match.round - 1) % 4) as SaskuSeat;
  if (dealer !== expectedDealer) throw new Error("Sasku dealer rotation does not match the game profile");
  const totals = Object.freeze([match.totals[0] + score.gamePoints[0], match.totals[1] + score.gamePoints[1]] as const);
  const winner = totals[0] >= SASKU_MATCH_TARGET ? 0 : totals[1] >= SASKU_MATCH_TARGET ? 1 : null;
  if (winner === null && match.round === MAX_SASKU_MATCH_ROUNDS) {
    throw new Error("Sasku match history limit reached before a winner");
  }
  return Object.freeze({ round: winner === null ? match.round + 1 : match.round, totals,
    completed: Object.freeze([...match.completed, Object.freeze({ round: match.round, dealer, score })]),
    winner });
}

export function dealerForSaskuRound(round: number): SaskuSeat {
  if (!Number.isSafeInteger(round) || round < 1 || round > MAX_SASKU_MATCH_ROUNDS) throw new Error("Invalid Sasku match round");
  return ((3 + round - 1) % 4) as SaskuSeat;
}
