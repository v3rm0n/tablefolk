import { bytesToHex, RistrettoPoint } from "@p2pcards/crypto";
import { describe, expect, it } from "vitest";

import { CardPointTable, DeckSpecError, deriveCardPoint } from "./card-points";

describe("card point derivation", () => {
  it("matches the framed Sasku fixture", () => {
    expect(bytesToHex(deriveCardPoint("sasku/36@1", "C:K").toBytes())).toBe(
      "c0ffd2ae357d7e606d6d3e037a23583b33506700020b92ebca0520e86516a04d",
    );
  });

  it("builds a deterministic bidirectional point table", () => {
    const first = new CardPointTable({ id: "test/2@1", cards: ["C:A", "D:10"] });
    const second = new CardPointTable({ id: "test/2@1", cards: ["C:A", "D:10"] });

    expect(first.size).toBe(2);
    expect(first.deckSpecId).toBe("test/2@1");
    expect(first.pointAt(0).equals(second.pointAt(0))).toBe(true);
    expect(first.pointAt(0).equals(first.pointAt(1))).toBe(false);
    expect(first.cardIdAt(1)).toBe("D:10");
    expect(first.identify(first.pointAt(0))).toBe("C:A");
    expect(first.identify(RistrettoPoint.base())).toBeNull();
  });

  it("rejects invalid and duplicate deck specifications", () => {
    expect(() => new CardPointTable({ id: "", cards: ["a", "b"] })).toThrow(DeckSpecError);
    expect(() => new CardPointTable({ id: "x", cards: ["a"] })).toThrow(DeckSpecError);
    expect(() => new CardPointTable({ id: "x", cards: ["a", "a"] })).toThrow(
      /Duplicate card/,
    );
    expect(() => new CardPointTable({ id: "x", cards: ["", "b"] })).toThrow(DeckSpecError);
  });

  it("rejects positions outside the deck", () => {
    const table = new CardPointTable({ id: "test/2@1", cards: ["a", "b"] });
    expect(() => table.cardIdAt(-1)).toThrow(RangeError);
    expect(() => table.pointAt(2)).toThrow(RangeError);
  });
});
