import { SASKU_SUITS, parseSaskuCard, type SaskuCardId, type SaskuRank } from "@p2pcards/rules-sasku";

const rankStrength: Readonly<Record<SaskuRank, number>> = {
  "6": 0, "7": 1, "8": 2, "9": 3, "10": 4, A: 5, J: 6, Q: 7, K: 8,
};

/** Group plain cards by suit and rank, then place courts in strength order on the right. */
export function compareSaskuHandCards(leftId: SaskuCardId, rightId: SaskuCardId): number {
  const left = parseSaskuCard(leftId), right = parseSaskuCard(rightId);
  if (left.isCourt !== right.isCourt) return Number(left.isCourt) - Number(right.isCourt);
  const suitOrder = SASKU_SUITS.indexOf(right.suit) - SASKU_SUITS.indexOf(left.suit);
  const rankOrder = rankStrength[left.rank] - rankStrength[right.rank];
  return suitOrder || rankOrder;
}
