import { describe, expect, it } from "vitest";
import type { SaskuCardId } from "@p2pcards/rules-sasku";
import { compareSaskuHandCards } from "./sasku-hand-order";

describe("displayed Sasku hand", () => {
  it("places stronger cards to the right and orders equal plain ranks and courts diamonds through clubs", () => {
    const hand: SaskuCardId[] = ["KC", "6C", "AD", "JS", "6D", "10H", "JD", "6H", "6S", "AC", "KD", "QH", "AH", "AS"];
    expect(hand.sort(compareSaskuHandCards)).toEqual([
      "6D", "6H", "6S", "6C", "10H", "AD", "AH", "AS", "AC", "JD", "KD", "QH", "JS", "KC",
    ]);
  });
});
