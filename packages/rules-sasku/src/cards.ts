import {
  SASKU_CARD_POINTS, SASKU_COURT_ORDER, SASKU_SUITS, partnershipForSeat,
  type SaskuPartnership, type SaskuSeat, type SaskuSuit,
} from "./scoring";

export const SASKU_RANKS = Object.freeze(["6", "7", "8", "9", "10", "J", "Q", "K", "A"] as const);
export type SaskuRank = (typeof SASKU_RANKS)[number];
export type SaskuSuitCode = "C" | "S" | "H" | "D";
export type SaskuCardId = `${SaskuRank}${SaskuSuitCode}`;
export type SaskuEffectiveSuit = SaskuSuit | "trump";

export interface SaskuCard {
  readonly id: SaskuCardId;
  readonly rank: SaskuRank;
  readonly suit: SaskuSuit;
  readonly points: number;
  readonly isCourt: boolean;
}

const suitCodes = { clubs: "C", spades: "S", hearts: "H", diamonds: "D" } as const;
const rankPoints: Readonly<Record<SaskuRank, number>> = Object.freeze({
  "6": 0, "7": 0, "8": 0, "9": 0,
  "10": SASKU_CARD_POINTS.ten, J: SASKU_CARD_POINTS.jack,
  Q: SASKU_CARD_POINTS.queen, K: SASKU_CARD_POINTS.king, A: SASKU_CARD_POINTS.ace,
});

export const SASKU_CARDS: readonly SaskuCard[] = Object.freeze(SASKU_SUITS.flatMap((suit) =>
  SASKU_RANKS.map((rank) => Object.freeze({
    id: `${rank}${suitCodes[suit]}` as SaskuCardId, rank, suit, points: rankPoints[rank],
    isCourt: rank === "K" || rank === "Q" || rank === "J",
  })),
));

export const SASKU_DECK_SPEC = Object.freeze({
  id: "sasku-36/v1",
  cards: Object.freeze(SASKU_CARDS.map((card) => card.id)),
});

const cardsById: ReadonlyMap<string, SaskuCard> = new Map(SASKU_CARDS.map((card) => [card.id, card]));
const plainRanks = ["6", "7", "8", "9", "10", "A"] as const;
const courtRanks = { king: "K", queen: "Q", jack: "J" } as const;
const courtStrength: ReadonlyMap<string, number> = new Map(SASKU_COURT_ORDER.map((card, index) =>
  [`${courtRanks[card.rank]}${suitCodes[card.suit]}`, 18 - index],
));

export class SaskuPlayError extends Error {
  constructor(message: string) { super(message); this.name = "SaskuPlayError"; }
}

export interface SaskuPlay {
  readonly seat: SaskuSeat;
  readonly card: SaskuCardId;
}

export interface SaskuTrickResult {
  readonly winner: SaskuPlay;
  readonly partnership: SaskuPartnership;
  readonly cardPoints: number;
}

export function parseSaskuCard(value: unknown): SaskuCard {
  const card = typeof value === "string" && value.length >= 2 && value.length <= 3 ? cardsById.get(value) : undefined;
  if (card === undefined) { throw new SaskuPlayError("Unknown Sasku card identifier"); }
  return card;
}

export function saskuEffectiveSuit(cardId: SaskuCardId, trump: SaskuSuit): SaskuEffectiveSuit {
  requireTrump(trump);
  const card = parseSaskuCard(cardId);
  return card.isCourt || card.suit === trump ? "trump" : card.suit;
}

/** The caller owns turn order and validates the hand's origin; this filters the acting player's cards. */
export function legalSaskuCards(
  hand: readonly SaskuCardId[],
  trick: readonly SaskuPlay[],
  trump: SaskuSuit,
): readonly SaskuCardId[] {
  requireTrump(trump);
  const plays = normalizeTrick(trick);
  if (plays.length === 4) { throw new SaskuPlayError("The trick is already complete"); }
  if (!Array.isArray(hand) || hand.length > 9) { throw new SaskuPlayError("A Sasku hand contains at most nine cards"); }
  const seen = new Set(plays.map(({ card }) => card));
  const cards = Array.from(hand, (id) => {
    const card = parseSaskuCard(id);
    if (seen.has(card.id)) { throw new SaskuPlayError("A hand contains duplicate or already-played cards"); }
    seen.add(card.id);
    return card.id;
  });
  if (plays.length === 0) { return Object.freeze(cards); }
  const led = saskuEffectiveSuit(plays[0]!.card, trump);
  const following = cards.filter((card) => saskuEffectiveSuit(card, trump) === led);
  return Object.freeze(following.length === 0 ? cards : following);
}

/** Adjudicates an ordered public trick, not ownership, turn order, or hidden-hand following legality. */
export function winningSaskuPlay(trick: readonly SaskuPlay[], trump: SaskuSuit): SaskuPlay | null {
  requireTrump(trump);
  return winnerOf(normalizeTrick(trick), trump);
}

export function resolveSaskuTrick(trick: readonly SaskuPlay[], trump: SaskuSuit): SaskuTrickResult {
  requireTrump(trump);
  const plays = normalizeTrick(trick);
  if (plays.length !== 4) { throw new SaskuPlayError("A completed trick requires four distinct seats and cards"); }
  const winner = winnerOf(plays, trump)!;
  return Object.freeze({
    winner, partnership: partnershipForSeat(winner.seat),
    cardPoints: plays.reduce((total, play) => total + parseSaskuCard(play.card).points, 0),
  });
}

function winnerOf(plays: readonly SaskuPlay[], trump: SaskuSuit): SaskuPlay | null {
  if (plays.length === 0) { return null; }
  const led = saskuEffectiveSuit(plays[0]!.card, trump);
  let winner = plays[0]!;
  let best = priority(winner.card, led, trump);
  for (const play of plays.slice(1)) {
    const strength = priority(play.card, led, trump);
    if (strength > best) { winner = play; best = strength; }
  }
  return winner;
}

function priority(id: SaskuCardId, led: SaskuEffectiveSuit, trump: SaskuSuit): number {
  const card = parseSaskuCard(id);
  const suit = saskuEffectiveSuit(id, trump);
  const strength = courtStrength.get(id) ?? (plainRanks as readonly string[]).indexOf(card.rank) + 1;
  return suit === "trump" ? 100 + strength : suit === led ? strength : 0;
}

function normalizeTrick(value: readonly SaskuPlay[]): readonly SaskuPlay[] {
  if (!Array.isArray(value) || value.length > 4) { throw new SaskuPlayError("A trick contains at most four plays"); }
  const seats = new Set<number>();
  const cards = new Set<SaskuCardId>();
  return Object.freeze(Array.from(value, (play) => {
    if (typeof play !== "object" || play === null || Array.isArray(play) || !Number.isSafeInteger(play.seat) ||
        play.seat < 0 || play.seat > 3 || Object.is(play.seat, -0)) {
      throw new SaskuPlayError("A play requires a seat from zero through three");
    }
    const card = parseSaskuCard(play.card);
    if (seats.has(play.seat) || cards.has(card.id)) { throw new SaskuPlayError("A trick cannot repeat a seat or card"); }
    seats.add(play.seat); cards.add(card.id);
    return Object.freeze({ seat: play.seat, card: card.id });
  }));
}

function requireTrump(value: SaskuSuit): void {
  if (!SASKU_SUITS.includes(value)) { throw new SaskuPlayError("A supported chosen trump suit is required"); }
}
