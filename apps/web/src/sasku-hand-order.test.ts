import { describe, expect, it } from "vitest";
import type { SaskuCardId } from "@p2pcards/rules-sasku";
import { compareSaskuHandCards } from "./sasku-hand-order";

describe("displayed Sasku hand", () => {
  it("groups plain cards by suit then ascending rank, followed by courts in strength order", () => {
    const hand: SaskuCardId[] = ["KC", "6C", "AD", "JS", "6D", "10H", "JD", "6H", "6S", "AC", "KD", "QH", "AH", "AS"];
    expect(hand.sort(compareSaskuHandCards)).toEqual([
      "6D", "AD", "6H", "10H", "AH", "6S", "AS", "6C", "AC", "JD", "JS", "QH", "KD", "KC",
    ]);
  });
});
