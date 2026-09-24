import { describe, expect, it } from "vitest";
import { SASKU_DECK_SPEC, parseSaskuCard, type SaskuCardId } from "./cards";
import {
  MAX_SASKU_HAND_ACTIONS, SaskuHandController, SaskuHandError, replaySaskuHand, saskuBidStrength,
  type SaskuDeal, type SaskuHandAction, type SaskuHandSetup,
} from "./hand";
import { SASKU_SUITS, scoreSaskuHand, type SaskuSeat } from "./scoring";

describe("Sasku bidding", () => {
  it("counts courts once and adds the longest non-court suit", () => {
    expect(saskuBidStrength(["KH", "QH", "JH", "KD", "6H", "7H", "8H", "6C", "6S"])).toBe(7);
    expect(saskuBidStrength(["KC", "QC", "JC", "KS", "QS", "JS", "KH", "QH", "JH"])).toBe(9);
    expect(saskuBidStrength(["6C", "7C", "8C", "6S", "7S", "6H", "7H", "6D", "7D"])).toBe(3);
    expect(() => saskuBidStrength(["6C"])).toThrow(/nine-card/);
    expect(() => saskuBidStrength(new Array<SaskuCardId>(9).fill("6C"))).toThrow(/repeat/);
  });

  it.each([0, 1, 2, 3] as const)("starts after dealer %i and defaults to diamonds after four passes", (dealer) => {
    const hand = new SaskuHandController(setup(dealer));
    expect(hand.snapshot.turn).toBe((dealer + 1) % 4);
    expect(hand.legalCardsForTurn()).toEqual([]);
    for (let pass = 0; pass < 4; pass += 1) {
      const turn = hand.snapshot.turn!;
      hand.apply({ type: "pass", seat: turn });
      if (pass < 3) { expect(hand.snapshot.phase).toBe("bidding"); }
    }
    expect(hand.snapshot).toMatchObject({ phase: "playing", turn: (dealer + 1) % 4, contract: { kind: "pass_round" }, highestBid: null });
  });

  it("lets an earlier passer re-enter, resets passes on a raise, and gives the winner trump choice", () => {
    const hands = variedDeal();
    expect(hands.map(saskuBidStrength)).toEqual([8, 5, 4, 7]);
    const game = new SaskuHandController({ dealer: 3, hands });
    game.apply({ type: "pass", seat: 0 });
    game.apply({ type: "bid", seat: 1, value: 5 });
    game.apply({ type: "pass", seat: 2 });
    game.apply({ type: "pass", seat: 3 });
    expect(game.snapshot.consecutivePasses).toBe(2);
    game.apply({ type: "bid", seat: 0, value: 8 });
    expect(game.snapshot.consecutivePasses).toBe(0);
    for (const seat of [1, 2, 3] as const) { game.apply({ type: "pass", seat }); }
    expect(game.snapshot).toMatchObject({ phase: "choosing_trump", turn: 0, highestBid: { seat: 0, value: 8 } });
    const before = game.snapshot;
    expect(() => game.apply({ type: "choose_trump", seat: 1, suit: "hearts" })).toThrow(/expected seat/);
    expect(() => game.apply({ type: "pass", seat: 0 })).toThrow(/choose the trump/);
    expect(game.snapshot).toEqual(before);
    game.apply({ type: "choose_trump", seat: 0, suit: "clubs" });
    expect(game.snapshot).toMatchObject({ phase: "playing", turn: 0, contract: { kind: "named", declarerSeat: 0, suit: "clubs" } });
  });

  it("accepts bids up to strength and rejects overstated, equal, or lower bids without mutation", () => {
    const game = new SaskuHandController({ dealer: 0, hands: variedDeal() });
    const initial = game.snapshot;
    expect(() => game.apply({ type: "bid", seat: 1, value: 6 })).toThrow(/cannot exceed/);
    expect(game.snapshot).toEqual(initial);
    game.apply({ type: "bid", seat: 1, value: 4 });
    expect(() => game.apply({ type: "bid", seat: 2, value: 4 })).toThrow(/strictly exceed/);
    expect(game.snapshot.turn).toBe(2);
    const equal = new SaskuHandController(setup(3));
    equal.apply({ type: "bid", seat: 0, value: 6 });
    expect(() => equal.apply({ type: "bid", seat: 1, value: 6 })).toThrow(/strictly exceed/);
    expect(equal.history).toHaveLength(1);
  });

  it("allows a lower-strength on-turn diamonds caller to supersede the numeric bidder", () => {
    const game = new SaskuHandController({ dealer: 0, hands: variedDeal() });
    game.apply({ type: "bid", seat: 1, value: 5 });
    const before = game.snapshot;
    expect(() => game.apply({ type: "diamonds", seat: 3 })).toThrow(/expected seat/);
    expect(game.snapshot).toEqual(before);
    game.apply({ type: "diamonds", seat: 2 });
    expect(game.snapshot).toMatchObject({ phase: "playing", turn: 2, contract: { kind: "named", suit: "diamonds", declarerSeat: 2 } });
    expect(() => game.apply({ type: "diamonds", seat: 2 })).toThrow(/Only card plays/);
  });

  it("does not turn advice against outbidding a partner into a prohibition", () => {
    const game = new SaskuHandController({ dealer: 1, hands: variedDeal() });
    game.apply({ type: "bid", seat: 2, value: 4 });
    game.apply({ type: "pass", seat: 3 });
    game.apply({ type: "bid", seat: 0, value: 8 });
    expect(game.snapshot.highestBid).toEqual({ seat: 0, value: 8 });
  });
});

describe("Sasku complete-information hand controller", () => {
  it("previews transitions without changing hands, history, or public state", () => {
    const game = new SaskuHandController(setup(3));
    const before = game.snapshot;
    const expected = game.preview({ type: "diamonds", seat: 0 });
    expect(expected.phase).toBe("playing");
    expect(game.snapshot).toEqual(before);
    expect(game.history).toEqual([]);
    expect(game.apply({ type: "diamonds", seat: 0 })).toEqual(expected);
    const card = game.handFor(0)[0]!;
    const playing = game.snapshot;
    const after = game.preview({ type: "play", seat: 0, card });
    expect(after.handSizes).toEqual([8, 9, 9, 9]);
    expect(game.snapshot).toEqual(playing);
    expect(game.handFor(0)).toContain(card);
    expect(game.apply({ type: "play", seat: 0, card })).toEqual(after);
  });

  it("enforces clockwise turns, ownership, and effective-suit following", () => {
    const game = new SaskuHandController(setup(3));
    game.apply({ type: "diamonds", seat: 0 });
    expect(() => game.apply({ type: "play", seat: 1, card: game.handFor(1)[0]! })).toThrow(/expected seat/);
    expect(() => game.apply({ type: "play", seat: 0, card: game.handFor(1)[0]! })).toThrow(/does not hold/);
    game.apply({ type: "play", seat: 0, card: "6C" });
    expect(game.snapshot.turn).toBe(1);
    expect(game.legalCardsForTurn()).toEqual(["7C"]);
    const before = game.snapshot;
    expect(() => game.apply({ type: "play", seat: 1, card: "JC" })).toThrow(/must follow/);
    expect(game.snapshot).toEqual(before);
    game.apply({ type: "play", seat: 1, card: "7C" });
    game.apply({ type: "play", seat: 2, card: "8C" });
    game.apply({ type: "play", seat: 3, card: "9C" });
    expect(game.snapshot).toMatchObject({ turn: 3, trick: [], handSizes: [8, 8, 8, 8], tricksWon: [0, 1], cardPoints: [0, 0] });
    expect(game.snapshot.completedTricks[0]?.winner).toEqual({ seat: 3, card: "9C" });
  });

  for (const dealer of [0, 1, 2, 3] as const) {
    it.each(SASKU_SUITS)(`completes all nine tricks for dealer ${dealer}, named %s, and replays exactly`, (suit) => {
      const initial = setup(dealer);
      const game = new SaskuHandController(initial);
      const declarer = game.snapshot.turn!;
      game.apply({ type: "bid", seat: declarer, value: saskuBidStrength(game.handFor(declarer)) });
      for (let pass = 0; pass < 3; pass += 1) { game.apply({ type: "pass", seat: game.snapshot.turn! }); }
      game.apply({ type: "choose_trump", seat: declarer, suit });
      const selectedCards = new Set<SaskuCardId>();
      for (let play = 0; play < 36; play += 1) {
        const before = game.snapshot;
        expect(before.score).toBeNull();
        const card = game.legalCardsForTurn()[0]!;
        expect(selectedCards.has(card)).toBe(false);
        selectedCards.add(card);
        const actor = before.turn!;
        game.apply({ type: "play", seat: actor, card });
        const after = game.snapshot;
        expect(after.handSizes.reduce((sum, size) => sum + size, 0)).toBe(35 - play);
        if (play % 4 === 3 && play < 35) { expect(after.turn).toBe(after.completedTricks.at(-1)!.winner.seat); }
        if (play % 4 !== 3) { expect(after.turn).toBe((actor + 1) % 4); }
        expect(replaySaskuHand(initial, game.history).snapshot).toEqual(after);
      }
      const completed = game.snapshot;
      expect(completed.phase).toBe("complete");
      expect(completed.turn).toBeNull();
      expect(completed.handSizes).toEqual([0, 0, 0, 0]);
      expect(completed.cardPoints[0] + completed.cardPoints[1]).toBe(120);
      expect(completed.tricksWon[0] + completed.tricksWon[1]).toBe(9);
      expect(completed.completedTricks.flatMap(({ plays }) => plays)).toHaveLength(36);
      expect(completed.score).toEqual(scoreSaskuHand({ cardPoints: completed.cardPoints, tricks: completed.tricksWon, contract: completed.contract! }));
      expect(completed.nextDealer).toBe((dealer + 1) % 4);
      expect(game.legalCardsForTurn()).toEqual([]);
      expect(() => game.apply({ type: "pass", seat: 0 })).toThrow(/complete/);
    });
  }

  it("finishes a pass-round with its special score instead of named diamonds", () => {
    const game = new SaskuHandController(setup(3));
    for (let pass = 0; pass < 4; pass += 1) { game.apply({ type: "pass", seat: game.snapshot.turn! }); }
    finish(game);
    expect(game.snapshot.score?.bonusPoints).toBe(0);
    expect(game.snapshot.score?.gamePoints.reduce((sum, points) => sum + points, 0)).toBe(game.snapshot.cardPoints[0] === 60 ? 0 : 2);
  });

  it("completes and replays the unequal-strength deal after an immediate diamonds call", () => {
    const initial: SaskuHandSetup = { dealer: 3, hands: variedDeal() };
    const game = new SaskuHandController(initial);
    game.apply({ type: "diamonds", seat: 0 });
    finish(game);
    expect(game.snapshot.phase).toBe("complete");
    expect(game.snapshot.cardPoints.reduce((sum, points) => sum + points, 0)).toBe(120);
    expect(replaySaskuHand(initial, game.history).snapshot).toEqual(game.snapshot);
  });

  it("snapshots deal/actions and keeps unplayed card identities out of the public snapshot", () => {
    const initial = setup(3);
    const hands = initial.hands.map((hand) => [...hand]) as unknown as SaskuDeal;
    const game = new SaskuHandController({ hands, dealer: 3 });
    const first = game.handFor(0);
    (hands[0] as SaskuCardId[]).fill("AD");
    expect(game.handFor(0)).toEqual(first);
    const action = { type: "bid", seat: 0, value: 6 } as const;
    game.apply(action);
    expect(Object.isFrozen(game.snapshot)).toBe(true);
    expect(Object.isFrozen(game.snapshot.handSizes)).toBe(true);
    expect(Object.isFrozen(game.history[0])).toBe(true);
    expect(Object.isFrozen(game.handFor(0))).toBe(true);
    expect(game.snapshot).not.toHaveProperty("hands");
    expect(JSON.stringify(game.snapshot)).not.toContain('"6C"');
  });

  it("rejects malformed deals and replay history without changing caller data", () => {
    const initial = setup(3);
    expect(() => new SaskuHandController({ ...initial, dealer: 4 as SaskuSeat })).toThrow(/Seat/);
    expect(() => new SaskuHandController({ ...initial, hands: initial.hands.slice(0, 3) as unknown as SaskuDeal })).toThrow(/four-hand/);
    const repeated = initial.hands.map((hand) => [...hand]);
    repeated[1]![0] = repeated[0]![0]!;
    expect(() => new SaskuHandController({ ...initial, hands: repeated as unknown as SaskuDeal })).toThrow(/exactly once/);
    expect(() => new SaskuHandController({ ...initial, hands: [[], ...initial.hands.slice(1)] as unknown as SaskuDeal })).toThrow(/nine/);
    expect(() => replaySaskuHand(initial, new Array<SaskuHandAction>(MAX_SASKU_HAND_ACTIONS + 1))).toThrow(/oversized/);
    expect(() => replaySaskuHand(initial, [{ type: "pass", seat: 1 }])).toThrow(/expected seat/);
  });

  it.each([
    { type: "bid", seat: 0, value: NaN }, { type: "bid", seat: 0, value: 10 },
    { type: "bid", seat: 0, value: 6.5 }, { type: "pass", seat: -0 },
    { type: "diamonds", seat: 0, value: 1 }, { type: "pass", seat: 0, extra: true },
    { type: "choose_trump", seat: 0, suit: "stars" }, { type: "play", seat: 0, card: "joker" },
    { type: "unknown", seat: 0 }, null,
  ])("rejects malformed actions atomically: %j", (candidate) => {
    const game = new SaskuHandController(setup(3));
    const before = game.snapshot;
    expect(() => game.apply(candidate as SaskuHandAction)).toThrow();
    expect(game.snapshot).toEqual(before);
    expect(game.history).toEqual([]);
  });
});

function setup(dealer: SaskuSeat): SaskuHandSetup {
  const hands = [[], [], [], []] as SaskuCardId[][];
  SASKU_DECK_SPEC.cards.forEach((card, index) => hands[index % 4]!.push(card));
  return { hands: hands as unknown as SaskuDeal, dealer };
}

function variedDeal(): SaskuDeal {
  const high: SaskuCardId[] = ["KC", "QC", "JC", "KS", "QS", "JS", "KH", "6H", "6D"];
  const low: SaskuCardId[] = ["QH", "JH", "6C", "7C", "8C", "6S", "7S", "7H", "7D"];
  const used = new Set([...high, ...low]);
  const remaining = SASKU_DECK_SPEC.cards.filter((card) => !used.has(card));
  return [high, low, remaining.slice(0, 9), remaining.slice(9)];
}

function finish(game: SaskuHandController): void {
  while (game.snapshot.phase === "playing") {
    const card = game.legalCardsForTurn()[0]!;
    expect(parseSaskuCard(card)).toBeDefined();
    game.apply({ type: "play", seat: game.snapshot.turn!, card });
  }
}
