import { describe, expect, it } from "vitest";
import { decodeSaskuAction, SaskuHandError, SaskuPublicHandController, type SaskuActionInput, type SaskuCardId } from "./index";

describe("Sasku public action adapter", () => {
  it.each([0, 1, 2, 3])("derives seat %i only from the caller's verified authority", (seat) => {
    for (const kind of ["pass", "diamonds"] as const) {
      expect(decodeSaskuAction(seat, { kind, data: {}, reveal: [] }, {})).toEqual({ type: kind, seat });
    }
    expect(decodeSaskuAction(seat, { kind: "bid", data: { value: 3 }, reveal: [] }, {})).toEqual({ type: "bid", seat, value: 3 });
    expect(decodeSaskuAction(seat, { kind: "choose_trump", data: { suit: "hearts" }, reveal: [] }, {})).toEqual({ type: "choose_trump", seat, suit: "hearts" });
    expect(decodeSaskuAction(seat, { kind: "play", data: {}, reveal: [35] }, { 35: "6C" })).toEqual({ type: "play", seat, card: "6C" });
  });

  it("uses the opened card, not the plaintext-deck card at that position", () => {
    const result = decodeSaskuAction(0, { kind: "play", data: {}, reveal: [0] }, { 0: "AD" });
    expect(result).toEqual({ type: "play", seat: 0, card: "AD" });
    expect(Object.isFrozen(result)).toBe(true);
  });

  it("feeds the public hand controller while keeping expected turn and phase checks in the controller", () => {
    const hand = new SaskuPublicHandController({ dealer: 3 });
    hand.apply(decodeSaskuAction(0, { kind: "diamonds", data: {}, reveal: [] }, {}));
    const play = decodeSaskuAction(0, { kind: "play", data: {}, reveal: [17] }, { 17: "6C" });
    expect(hand.preview(play).handSizes).toEqual([8, 9, 9, 9]);
    expect(hand.snapshot.handSizes).toEqual([9, 9, 9, 9]);
    hand.apply(play);
    expect(hand.snapshot.trick).toEqual([{ seat: 0, card: "6C" }]);
    expect(() => hand.apply(decodeSaskuAction(0, { kind: "pass", data: {}, reveal: [] }, {}))).toThrow(/expected seat/);
    expect(() => hand.apply(decodeSaskuAction(1, { kind: "pass", data: {}, reveal: [] }, {}))).toThrow(/Only card plays/);
  });

  it.each([-0, -1, 4, 0.5, NaN, Infinity])("rejects invalid actor %s", (actor) => {
    expect(() => decodeSaskuAction(actor, { kind: "pass", data: {}, reveal: [] }, {})).toThrow(SaskuHandError);
  });

  it.each([
    null, [], {}, { kind: "pass", data: {}, reveal: [], seat: 0 },
    { kind: "pass", data: {}, reveal: [], shares: [] },
    { kind: "pass", data: { seat: 0 }, reveal: [] },
    { kind: "pass", data: { card: "AD" }, reveal: [] },
    { kind: "play", data: { card: "AD" }, reveal: [1] },
    { kind: "play", data: { pos: 1 }, reveal: [1] },
    { kind: "pass", data: null, reveal: [] },
    { kind: "pass", data: [], reveal: [] },
    { kind: "pass", data: new Uint8Array(), reveal: [] },
    { kind: "pass", data: new Map(), reveal: [] },
    { kind: "pass", data: new Date(0), reveal: [] },
    { kind: "pass", data: {}, reveal: [1] },
    { kind: "pass", data: {}, reveal: {} },
    { kind: "unknown", data: {}, reveal: [] },
    { kind: "Pass", data: {}, reveal: [] },
    { kind: "bid", data: { value: 2 }, reveal: [] },
    { kind: "bid", data: { value: 10 }, reveal: [] },
    { kind: "bid", data: { value: 3.5 }, reveal: [] },
    { kind: "bid", data: { value: "6" }, reveal: [] },
    { kind: "bid", data: { value: -0 }, reveal: [] },
    { kind: "bid", data: { value: NaN }, reveal: [] },
    { kind: "bid", data: { value: 6, seat: 3 }, reveal: [] },
    { kind: "choose_trump", data: { suit: "stars" }, reveal: [] },
    { kind: "choose_trump", data: { suit: "clubs", value: 1 }, reveal: [] },
  ])("rejects ambiguous, forged, or unsupported action data: %j", (input) => {
    expect(() => decodeSaskuAction(0, input as SaskuActionInput, {})).toThrow(SaskuHandError);
  });

  it.each([
    { reveal: [], cards: {} }, { reveal: [1], cards: {} },
    { reveal: [1], cards: { 0: "6C" } }, { reveal: [1], cards: { 1: "6C", 2: "7C" } },
    { reveal: [1, 2], cards: { 1: "6C", 2: "7C" } }, { reveal: [1, 1], cards: { 1: "6C" } },
    { reveal: [1], cards: { "01": "6C" } }, { reveal: [-0], cards: { 0: "6C" } },
    { reveal: [-1], cards: {} }, { reveal: [36], cards: { 36: "6C" } },
    { reveal: [0.5], cards: {} }, { reveal: [NaN], cards: {} },
    { reveal: new Array<number>(1), cards: {} },
  ])("requires exactly one matching valid opened position: %j", ({ reveal, cards }) => {
    expect(() => decodeSaskuAction(0, { kind: "play", data: {}, reveal }, cards as Record<number, SaskuCardId>)).toThrow(SaskuHandError);
  });

  it("rejects unknown opened card IDs, inherited cards, and extra cards on an auction action", () => {
    expect(() => decodeSaskuAction(0, { kind: "play", data: {}, reveal: [1] }, { 1: "joker" as SaskuCardId })).toThrow(/card/);
    expect(() => decodeSaskuAction(0, { kind: "play", data: {}, reveal: [1] }, Object.create({ 1: "6C" }))).toThrow(SaskuHandError);
    expect(() => decodeSaskuAction(0, { kind: "pass", data: {}, reveal: [] }, { 1: "6C" })).toThrow(/cannot reveal/);
    for (const cards of [null, [], new Map(), new Uint8Array()]) {
      expect(() => decodeSaskuAction(0, { kind: "pass", data: {}, reveal: [] }, cards as unknown as Record<number, SaskuCardId>)).toThrow(SaskuHandError);
    }
  });

  it("accepts decoded null-prototype maps and snapshots all returned action fields", () => {
    const data = Object.assign(Object.create(null), { value: 6 });
    const input = Object.assign(Object.create(null), { kind: "bid", data, reveal: [] });
    const bid = decodeSaskuAction(2, input, Object.create(null));
    data.value = 9;
    input.kind = "diamonds";
    expect(bid).toEqual({ type: "bid", seat: 2, value: 6 });
    const cards = { 0: "AD" as SaskuCardId };
    const reveal = [0];
    const play = decodeSaskuAction(1, { kind: "play", data: {}, reveal }, cards);
    cards[0] = "6C";
    reveal[0] = 2;
    expect(play).toEqual({ type: "play", seat: 1, card: "AD" });
  });

  it("does not invoke action/data/card getters or ignore hidden extension fields", () => {
    const fail = () => { throw new Error("Getter must not run"); };
    const input = { kind: "bid", data: { get value() { return fail(); } }, reveal: [] };
    expect(() => decodeSaskuAction(0, input, {})).toThrow(SaskuHandError);
    expect(() => decodeSaskuAction(0, { get kind() { return fail(); }, data: {}, reveal: [] }, {})).toThrow(SaskuHandError);
    expect(() => decodeSaskuAction(0, { kind: "play", data: {}, reveal: [0] }, { get 0() { return fail(); } })).toThrow(SaskuHandError);
    const data = Object.defineProperty({}, "seat", { value: 3 });
    expect(() => decodeSaskuAction(0, { kind: "pass", data, reveal: [] }, {})).toThrow(SaskuHandError);
    expect(() => decodeSaskuAction(0, { kind: "pass", data: { [Symbol("extra")]: true }, reveal: [] }, {})).toThrow(SaskuHandError);
  });
});
