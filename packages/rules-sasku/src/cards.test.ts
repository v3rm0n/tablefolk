import { bytesToHex } from "@p2pcards/crypto";
import { CardPointTable } from "@p2pcards/deck";
import { cardDerivationHash } from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";

import {
  SASKU_CARDS, SASKU_DECK_SPEC, SASKU_RANKS, SaskuPlayError,
  legalSaskuCards, parseSaskuCard, resolveSaskuTrick, saskuEffectiveSuit, winningSaskuPlay,
  type SaskuCardId, type SaskuPlay,
} from "./cards";
import { SASKU_SUITS, type SaskuSeat, type SaskuSuit } from "./scoring";

const COURTS: readonly SaskuCardId[] = ["KC", "QC", "JC", "KS", "QS", "JS", "KH", "QH", "JH", "KD", "QD", "JD"];
const PLAIN_RANKS = ["A", "10", "9", "8", "7", "6"] as const;
const CODES = { clubs: "C", spades: "S", hearts: "H", diamonds: "D" } as const;

describe("confirmed Sasku deck and following rules", () => {
  it("freezes 36 unique, suit-major card IDs with exactly 120 card points", () => {
    expect(SASKU_RANKS).toEqual(["6", "7", "8", "9", "10", "J", "Q", "K", "A"]);
    expect(SASKU_CARDS).toHaveLength(36);
    expect(new Set(SASKU_DECK_SPEC.cards).size).toBe(36);
    expect(SASKU_DECK_SPEC.id).toBe("sasku-36/v1");
    expect(SASKU_DECK_SPEC.cards.slice(0, 9)).toEqual(["6C", "7C", "8C", "9C", "10C", "JC", "QC", "KC", "AC"]);
    expect(SASKU_DECK_SPEC.cards.at(-1)).toBe("AD");
    expect(SASKU_CARDS.reduce((points, card) => points + card.points, 0)).toBe(120);
    expect(SASKU_CARDS.filter((card) => card.isCourt)).toHaveLength(12);
    expect(SASKU_CARDS.filter((card) => card.points === 0)).toHaveLength(16);
    expect(Object.isFrozen(SASKU_DECK_SPEC.cards)).toBe(true);
    expect(SASKU_CARDS.every(Object.isFrozen)).toBe(true);
  });

  it.each(["TC", "6c", "11H", "5D", "joker", "Q\u2665", "__proto__", "", undefined, 10])("rejects non-profile card ID %s", (value) => {
    expect(() => parseSaskuCard(value)).toThrow(SaskuPlayError);
  });

  it.each(SASKU_SUITS)("classifies exactly 18 trumps when %s is chosen", (trump) => {
    expect(SASKU_CARDS.filter((card) => saskuEffectiveSuit(card.id, trump) === "trump")).toHaveLength(18);
    for (const card of SASKU_CARDS) {
      expect(saskuEffectiveSuit(card.id, trump)).toBe(card.isCourt || card.suit === trump ? "trump" : card.suit);
    }
  });

  it("treats a matching printed-suit court as trump, with free discard when void", () => {
    const hand: SaskuCardId[] = ["QH", "8C", "AD"];
    expect(legalSaskuCards(hand, plays("6H"), "diamonds")).toEqual(hand);
    expect(legalSaskuCards([...hand, "AH"], plays("6H"), "diamonds")).toEqual(["AH"]);
    expect(legalSaskuCards(hand, plays("JH"), "diamonds")).toEqual(["QH", "AD"]);
    expect(legalSaskuCards(["AH", "8C"], plays("JH"), "diamonds")).toEqual(["AH", "8C"]);
  });

  it("requires following even after somebody trumps, without forcing an overtake", () => {
    expect(legalSaskuCards(["AH", "AD", "QH"], plays("6H", "KC"), "diamonds")).toEqual(["AH"]);
    expect(legalSaskuCards(["JD", "6D", "AH"], plays("KC"), "diamonds")).toEqual(["JD", "6D"]);
    expect(legalSaskuCards(["6H", "7H"], plays("AH"), "diamonds")).toEqual(["6H", "7H"]);
    expect(legalSaskuCards([], [], "clubs")).toEqual([]);
  });

  it("matches the following rule for every lead, trump, and disjoint two-card hand", () => {
    let checked = 0;
    for (const trump of SASKU_SUITS) {
      const effective = (id: SaskuCardId): string => /^[KQJ]/.test(id) || id.endsWith(CODES[trump]) ? "trump" : id.slice(-1);
      for (const lead of SASKU_DECK_SPEC.cards) {
        const available = SASKU_DECK_SPEC.cards.filter((card) => card !== lead);
        for (let a = 0; a < available.length; a += 1) {
          for (let b = a + 1; b < available.length; b += 1) {
            const hand = [available[a]!, available[b]!];
            const matching = hand.filter((card) => effective(card) === effective(lead));
            const expected = matching.length === 0 ? hand : matching;
            const actual = legalSaskuCards(hand, plays(lead), trump);
            if (actual.length !== expected.length || actual.some((card, index) => card !== expected[index])) {
              throw new Error(`Following mismatch for ${trump}, ${lead}, ${hand.join(",")}`);
            }
            checked += 1;
          }
        }
      }
    }
    expect(checked).toBe(85_680);
  });

  it("rejects duplicate, overlapping, oversized, and malformed hands or tricks", () => {
    expect(() => legalSaskuCards(["6H", "6H"], [], "diamonds")).toThrow(/duplicate/);
    expect(() => legalSaskuCards(["6H"], plays("6H"), "diamonds")).toThrow(/already-played/);
    expect(() => legalSaskuCards(SASKU_DECK_SPEC.cards.slice(0, 10), [], "diamonds")).toThrow(/nine/);
    expect(() => legalSaskuCards(new Array<SaskuCardId>(2), [], "diamonds")).toThrow();
    expect(() => legalSaskuCards(["AD"], plays("6H", "7H", "8H", "9H"), "diamonds")).toThrow(/complete/);
    expect(() => winningSaskuPlay([{ seat: 0, card: "6H" }, { seat: 0, card: "7H" }], "diamonds")).toThrow(/repeat/);
    expect(() => winningSaskuPlay(plays("6H", "6H"), "diamonds")).toThrow(/repeat/);
    expect(() => winningSaskuPlay([{ seat: -0, card: "6H" }], "diamonds")).toThrow(/seat/);
    expect(() => winningSaskuPlay([{ seat: 4 as SaskuSeat, card: "6H" }], "diamonds")).toThrow(/seat/);
    expect(() => winningSaskuPlay([], "stars" as SaskuSuit)).toThrow(/trump/);
    expect(() => winningSaskuPlay(new Array<SaskuPlay>(2), "clubs")).toThrow();
  });
});

describe("Sasku trick resolution", () => {
  it.each(SASKU_SUITS)("preserves every court comparison above every non-court trump for %s", (trump) => {
    for (const [index, court] of COURTS.entries()) {
      for (const weaker of COURTS.slice(index + 1)) {
        expect(winningSaskuPlay(plays(weaker, court), trump)?.card).toBe(court);
        expect(winningSaskuPlay(plays(court, weaker), trump)?.card).toBe(court);
      }
      for (const rank of PLAIN_RANKS) {
        const low = `${rank}${CODES[trump]}` as SaskuCardId;
        expect(winningSaskuPlay(plays(low, court), trump)?.card).toBe(court);
      }
    }
  });

  it("ranks A > 10 > 9 > 8 > 7 > 6 within plain and chosen-trump suits", () => {
    for (const suit of SASKU_SUITS) {
      for (const trump of SASKU_SUITS) {
        for (let high = 0; high < PLAIN_RANKS.length; high += 1) {
          for (let low = high + 1; low < PLAIN_RANKS.length; low += 1) {
            const strongest = `${PLAIN_RANKS[high]}${CODES[suit]}` as SaskuCardId;
            const weakest = `${PLAIN_RANKS[low]}${CODES[suit]}` as SaskuCardId;
            expect(winningSaskuPlay(plays(weakest, strongest), trump)?.card).toBe(strongest);
          }
        }
      }
    }
  });

  it("ignores off-suit aces and picks the highest trump rather than the highest point value", () => {
    expect(winningSaskuPlay(plays("6H", "AC", "AS", "7H"), "diamonds")).toEqual({ seat: 3, card: "7H" });
    expect(winningSaskuPlay(plays("AH", "6D", "AS", "AC"), "diamonds")).toEqual({ seat: 1, card: "6D" });
    expect(resolveSaskuTrick(plays("10H", "AH", "6H", "QH"), "diamonds")).toEqual({
      winner: { seat: 3, card: "QH" }, partnership: 1, cardPoints: 24,
    });
    expect(resolveSaskuTrick(plays("AC", "AS", "AH", "AD"), "diamonds").cardPoints).toBe(44);
  });

  it("uses the first play as lead, without inventing a turn-order or first-leader policy", () => {
    expect(winningSaskuPlay([], "clubs")).toBeNull();
    expect(winningSaskuPlay([{ seat: 2, card: "6H" }, { seat: 0, card: "AC" }], "diamonds")).toEqual({ seat: 2, card: "6H" });
    expect(() => resolveSaskuTrick(plays("6H", "AH", "7H"), "diamonds")).toThrow(/four/);
  });

  it("returns immutable results independent of input arrays and play objects", () => {
    const trick = [{ seat: 0 as const, card: "6H" as SaskuCardId }, { seat: 1 as const, card: "AH" as SaskuCardId }];
    const winner = winningSaskuPlay(trick, "diamonds")!;
    trick[1]!.card = "6C";
    expect(winner).toEqual({ seat: 1, card: "AH" });
    expect(Object.isFrozen(winner)).toBe(true);
    const hand: SaskuCardId[] = ["QH", "8C"];
    const legal = legalSaskuCards(hand, plays("6H"), "diamonds");
    hand[0] = "AH";
    expect(legal).toEqual(["QH", "8C"]);
    expect(Object.isFrozen(legal)).toBe(true);
  });
});

describe("Sasku cryptographic deck binding", () => {
  it("matches independent SHA512 inputs for the fixed deck spec and edge card IDs", () => {
    // Node createHash over literal ASCII domain + manually encoded CBOR text strings.
    expect(bytesToHex(cardDerivationHash(SASKU_DECK_SPEC.id, "6C"))).toBe(
      "1e664f1821fca54ae038139908326813b036878e137d8fbb8a19eb09ed7e3b54b26bdbcd20c9962a57eb799f4c40fd02f5f319ffdbb5cb1de473ffb603e8445b",
    );
    expect(bytesToHex(cardDerivationHash(SASKU_DECK_SPEC.id, "AD"))).toBe(
      "3b719be423fbf75ed163844dfad40d43078beeb82564d12bd069855b1b4a848ab9b8175ade71fc7583aa916d302f98af6b565a056c726b4e20ba866432923e34",
    );
  });

  it("derives 36 distinct identifiable Ristretto card points through the existing deck API", () => {
    const table = new CardPointTable(SASKU_DECK_SPEC);
    expect(table.size).toBe(36);
    const encodings = new Set<string>();
    for (let index = 0; index < table.size; index += 1) {
      const point = table.pointAt(index);
      expect(table.identify(point)).toBe(SASKU_DECK_SPEC.cards[index]);
      encodings.add(bytesToHex(point.toBytes()));
    }
    expect(encodings.size).toBe(36);
  });
});

function plays(...cards: SaskuCardId[]): SaskuPlay[] {
  return cards.map((card, seat) => ({ card, seat: seat as SaskuSeat }));
}
