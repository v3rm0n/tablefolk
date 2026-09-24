import { describe, expect, it } from "vitest";
import {
  MAX_SASKU_HAND_ACTIONS, SASKU_DECK_SPEC, SASKU_SUITS,
  SaskuHandController, SaskuHandError, SaskuPublicHandController, auditSaskuHand, saskuBidStrength,
  type SaskuCardId, type SaskuDeal, type SaskuHandAction, type SaskuHandAuditRule,
  type SaskuHandSetup, type SaskuPublicHandSetup, type SaskuSeat,
} from "./index";

describe("Sasku public-only hand progression", () => {
  for (const distribution of ["round-robin", "unequal"] as const) {
    for (const dealer of [0, 1, 2, 3] as const) {
      it.each([...SASKU_SUITS, "diamonds-call", "pass-round"] as const)(
        `matches every reference transition and audits ${distribution}, dealer ${dealer}, %s`,
        (contract) => {
          const initial = setup(dealer, distribution);
          const reference = new SaskuHandController(initial);
          const publicHand = new SaskuPublicHandController({ dealer });
          const step = (action: SaskuHandAction): void => {
            const before = publicHand.snapshot;
            const history = publicHand.history;
            const { score, ...expected } = reference.preview(action);
            const preview = publicHand.preview(action);
            expect(preview).toEqual({ ...expected, provisionalScore: score });
            expect(publicHand.snapshot).toEqual(before);
            expect(publicHand.history).toEqual(history);
            reference.apply(action);
            expect(publicHand.apply(action)).toEqual(preview);
            expect(publicHand.history).toEqual(reference.history);
            expect(publicHand.snapshot).not.toHaveProperty("score");
          };
          const declarer = reference.snapshot.turn!;
          if (contract === "pass-round") {
            for (let pass = 0; pass < 4; pass += 1) step({ type: "pass", seat: reference.snapshot.turn! });
          } else if (contract === "diamonds-call") {
            step({ type: "diamonds", seat: declarer });
          } else {
            step({ type: "bid", seat: declarer, value: saskuBidStrength(reference.handFor(declarer)) });
            for (let pass = 0; pass < 3; pass += 1) step({ type: "pass", seat: reference.snapshot.turn! });
            step({ type: "choose_trump", seat: declarer, suit: contract });
          }
          expect(auditSaskuHand(initial, publicHand.history)).toEqual({ status: "incomplete", snapshot: reference.snapshot });
          for (let play = 0; play < 36; play += 1) {
            const legal = reference.legalCardsForTurn();
            step({ type: "play", seat: reference.snapshot.turn!, card: legal[play % legal.length]! });
          }
          expect(publicHand.snapshot.handSizes).toEqual([0, 0, 0, 0]);
          expect(publicHand.snapshot.provisionalScore).toEqual(reference.snapshot.score);
          expect(auditSaskuHand(initial, publicHand.history)).toEqual({ status: "valid", snapshot: reference.snapshot });
          expect(auditSaskuHand(initial, publicHand.history.slice(0, -1))).toMatchObject({ status: "incomplete", snapshot: { score: null } });
          const replay = new SaskuPublicHandController({ dealer });
          for (const action of publicHand.history) replay.apply(action);
          expect(replay.snapshot).toEqual(publicHand.snapshot);
          expect(() => publicHand.apply({ type: "pass", seat: 0 })).toThrow(/complete/);
        },
      );
    }
  }

  it("allows passer re-entry, rejects ties and phase errors, and retains auction state on failure", () => {
    const game = new SaskuPublicHandController({ dealer: 3 });
    game.apply({ type: "pass", seat: 0 });
    game.apply({ type: "bid", seat: 1, value: 5 });
    const before = game.snapshot;
    expect(() => game.apply({ type: "bid", seat: 2, value: 5 })).toThrow(/strictly exceed/);
    expect(() => game.apply({ type: "choose_trump", seat: 2, suit: "clubs" })).toThrow(/during bidding/);
    expect(game.snapshot).toEqual(before);
    game.apply({ type: "pass", seat: 2 });
    game.apply({ type: "pass", seat: 3 });
    game.apply({ type: "bid", seat: 0, value: 8 });
    expect(game.snapshot.consecutivePasses).toBe(0);
    for (const seat of [1, 2, 3] as const) game.apply({ type: "pass", seat });
    expect(game.snapshot).toMatchObject({ phase: "choosing_trump", turn: 0 });
    expect(() => game.apply({ type: "choose_trump", seat: 1, suit: "clubs" })).toThrow(/expected seat/);
    expect(() => game.apply({ type: "pass", seat: 0 })).toThrow(/choose the trump/);
    game.apply({ type: "choose_trump", seat: 0, suit: "hearts" });
    expect(game.snapshot.contract).toEqual({ kind: "named", suit: "hearts", declarerSeat: 0 });
    expect(() => game.apply({ type: "diamonds", seat: 0 })).toThrow(/Only card plays/);
  });

  it("rejects a previously declared bidder changing their bid without knowing the deal", () => {
    const game = new SaskuPublicHandController({ dealer: 3 });
    game.apply({ type: "bid", seat: 0, value: 3 });
    game.apply({ type: "bid", seat: 1, value: 4 });
    game.apply({ type: "pass", seat: 2 });
    game.apply({ type: "pass", seat: 3 });
    const before = game.snapshot;
    expect(() => game.apply({ type: "bid", seat: 0, value: 7 })).toThrow(/bid cannot change/);
    expect(game.snapshot).toEqual(before);
    game.apply({ type: "diamonds", seat: 0 });
    expect(game.snapshot.contract).toEqual({ kind: "named", suit: "diamonds", declarerSeat: 0 });
  });

  it("rejects repeated card identities within and across tricks without consuming a turn", () => {
    const game = new SaskuPublicHandController({ dealer: 3 });
    game.apply({ type: "diamonds", seat: 0 });
    game.apply({ type: "play", seat: 0, card: "6C" });
    const before = game.snapshot;
    expect(() => game.preview({ type: "play", seat: 1, card: "6C" })).toThrow(/more than once/);
    expect(() => game.apply({ type: "play", seat: 1, card: "6C" })).toThrow(/more than once/);
    expect(game.snapshot).toEqual(before);
    for (const [seat, card] of [[1, "7C"], [2, "8C"], [3, "9C"]] as const) game.apply({ type: "play", seat, card });
    const completedTrick = game.snapshot;
    expect(() => game.apply({ type: "play", seat: 3, card: "6C" })).toThrow(/more than once/);
    expect(game.snapshot).toEqual(completedTrick);
    expect(game.history).toHaveLength(5);
  });

  it("does not accept hidden-hand setup or expose hand readers, and snapshots public inputs/results", () => {
    let readHands = false;
    const hiddenSetup = { dealer: 3, get hands() { readHands = true; throw new Error("Hidden hands were read"); } };
    expect(() => new SaskuPublicHandController(hiddenSetup as SaskuPublicHandSetup)).toThrow(/only an explicit dealer/);
    expect(readHands).toBe(false);
    const initial = { dealer: 3 as SaskuSeat };
    const game = new SaskuPublicHandController(initial);
    initial.dealer = 0;
    expect(game.snapshot.dealer).toBe(3);
    expect(game).not.toHaveProperty("handFor");
    expect(game).not.toHaveProperty("legalCardsForTurn");
    expect(JSON.stringify(game.snapshot)).not.toContain('"6C"');
    const action: SaskuHandAction = { type: "bid", seat: 0, value: 6 };
    game.apply(action);
    (action as { value: number }).value = 9;
    expect(game.snapshot.highestBid).toEqual({ seat: 0, value: 6 });
    expect(Object.isFrozen(game.snapshot)).toBe(true);
    expect(Object.isFrozen(game.snapshot.highestBid)).toBe(true);
    expect(Object.isFrozen(game.snapshot.handSizes)).toBe(true);
    expect(Object.isFrozen(game.history)).toBe(true);
    expect(Object.isFrozen(game.history[0])).toBe(true);
    expect(() => (game.snapshot.handSizes as number[]).pop()).toThrow();
    expect(game.snapshot.handSizes).toEqual([9, 9, 9, 9]);
  });

  it.each([null, [], {}, { dealer: -0 }, { dealer: -1 }, { dealer: 4 }, { dealer: 0.5 }, { dealer: NaN }, { dealer: 0, extra: 1 }])(
    "rejects invalid public setup: %j", (initial) => {
      expect(() => new SaskuPublicHandController(initial as SaskuPublicHandSetup)).toThrow(SaskuHandError);
    },
  );

  it.each([
    null, [], { type: "unknown", seat: 0 }, { type: "pass", seat: -0 }, { type: "pass", seat: 4 },
    { type: "pass", seat: 0, extra: true }, { type: "bid", seat: 0, value: -0 },
    { type: "bid", seat: 0, value: 1 }, { type: "bid", seat: 0, value: 2 },
    { type: "bid", seat: 0, value: 10 }, { type: "bid", seat: 0, value: NaN },
    { type: "bid", seat: 0, value: 4.5 }, { type: "choose_trump", seat: 0, suit: "stars" },
    { type: "play", seat: 0, card: "joker" }, { type: "pass", seat: 1 },
  ])("rejects invalid public actions atomically: %j", (action) => {
    const game = new SaskuPublicHandController({ dealer: 3 });
    const before = game.snapshot;
    expect(() => game.preview(action as SaskuHandAction)).toThrow(SaskuHandError);
    expect(() => game.apply(action as SaskuHandAction)).toThrow(SaskuHandError);
    expect(game.snapshot).toEqual(before);
    expect(game.history).toEqual([]);
  });
});

describe("Sasku disclosed-hand audit", () => {
  it("does not turn a completed public hand's provisional score into a valid result when its bid was false", () => {
    const initial = setup(3);
    const reference = new SaskuHandController(initial);
    reference.apply({ type: "bid", seat: 0, value: 6 });
    for (const seat of [1, 2, 3] as const) reference.apply({ type: "pass", seat });
    reference.apply({ type: "choose_trump", seat: 0, suit: "hearts" });
    while (reference.snapshot.phase === "playing") {
      reference.apply({ type: "play", seat: reference.snapshot.turn!, card: reference.legalCardsForTurn()[0]! });
    }
    const publicHand = new SaskuPublicHandController({ dealer: 3 });
    publicHand.apply({ type: "bid", seat: 0, value: 9 });
    for (const action of reference.history.slice(1)) publicHand.apply(action);
    expect(publicHand.snapshot.phase).toBe("complete");
    expect(publicHand.snapshot.provisionalScore).toEqual(reference.snapshot.score);
    expect(Object.isFrozen(publicHand.snapshot.provisionalScore)).toBe(true);
    expect(auditSaskuHand(initial, publicHand.history)).toEqual({ status: "violation", seat: 0, at: 0, rule: "bid_strength" });
    expect(() => auditSaskuHand(initial, [...reference.history, { type: "pass", seat: 0 }])).toThrow(/complete/);
  });

  it("accepts a bid below the hand maximum but detects an overbid at audit", () => {
    const initial = setup(3);
    const maximum = saskuBidStrength(initial.hands[0]);
    const publicHand = new SaskuPublicHandController({ dealer: 3 });
    publicHand.apply({ type: "bid", seat: 0, value: 3 });
    expect(auditSaskuHand(initial, publicHand.history)).toMatchObject({ status: "incomplete" });
    const overbid = new SaskuPublicHandController({ dealer: 3 });
    overbid.apply({ type: "bid", seat: 0, value: maximum + 1 });
    expect(overbid.snapshot.highestBid?.value).toBe(maximum + 1);
    expect(auditSaskuHand(initial, overbid.history)).toEqual({ status: "violation", seat: 0, at: 0, rule: "bid_strength" });
  });

  it.each([
    { dealer: 3, leader: 0, lead: "6C", actor: 1, discard: "JC" },
    { dealer: 2, leader: 3, lead: "KC", actor: 0, discard: "6C" },
  ] as const)("detects effective-suit violations after public acceptance: %j", ({ dealer, leader, lead, actor, discard }) => {
    const initial = setup(dealer);
    const publicHand = new SaskuPublicHandController({ dealer });
    publicHand.apply({ type: "diamonds", seat: leader });
    publicHand.apply({ type: "play", seat: leader, card: lead });
    publicHand.apply({ type: "play", seat: actor, card: discard });
    expect(auditSaskuHand(initial, publicHand.history)).toEqual({ status: "violation", seat: actor, at: 2, rule: "follow_suit" });
    expect(publicHand.history).toHaveLength(3);
  });

  it("detects a play that does not belong to the disclosed hand without returning hidden card data", () => {
    const game = new SaskuPublicHandController({ dealer: 3 });
    game.apply({ type: "diamonds", seat: 0 });
    game.apply({ type: "play", seat: 0, card: "7C" });
    const result = auditSaskuHand(setup(3), game.history);
    expect(result).toEqual({ status: "violation", seat: 0, at: 1, rule: "card_ownership" });
    expect(Object.isFrozen(result)).toBe(true);
    expect(result).not.toHaveProperty("snapshot");
    expect(JSON.stringify(result)).not.toContain("7C");
  });

  it("reports the first hidden violation deterministically without mutating the deal or history", () => {
    const initial = setup(3);
    const actions: readonly SaskuHandAction[] = Object.freeze([
      Object.freeze({ type: "bid", seat: 0, value: 9 } as const),
      Object.freeze({ type: "diamonds", seat: 1 } as const),
      Object.freeze({ type: "play", seat: 1, card: "6C" } as const),
    ]);
    initial.hands.forEach(Object.freeze);
    Object.freeze(initial.hands);
    const before = JSON.stringify({ initial, actions });
    for (let attempt = 0; attempt < 3; attempt += 1) {
      expect(auditSaskuHand(initial, actions)).toEqual({ status: "violation", seat: 0, at: 0, rule: "bid_strength" });
    }
    expect(JSON.stringify({ initial, actions })).toBe(before);
  });

  it("never treats empty or partial valid history as a completed audit", () => {
    const initial = setup(3);
    const actions: readonly SaskuHandAction[] = [
      { type: "diamonds", seat: 0 }, { type: "play", seat: 0, card: "6C" },
    ];
    for (let length = 0; length <= actions.length; length += 1) {
      const result = auditSaskuHand(initial, actions.slice(0, length));
      expect(result).toMatchObject({ status: "incomplete", snapshot: { score: null } });
      expect(Object.isFrozen(result)).toBe(true);
    }
  });

  it("rejects invalid deal/history inputs before attributing a hidden-hand violation", () => {
    const initial = setup(3);
    expect(() => auditSaskuHand({ ...initial, hands: [] as unknown as SaskuDeal }, [])).toThrow(/four-hand/);
    expect(() => auditSaskuHand(initial, null as unknown as SaskuHandAction[])).toThrow(/history/);
    expect(() => auditSaskuHand(initial, new Array<SaskuHandAction>(MAX_SASKU_HAND_ACTIONS + 1))).toThrow(/oversized/);
    expect(() => auditSaskuHand(initial, new Array<SaskuHandAction>(1))).toThrow(/action/);
    expect(() => auditSaskuHand(initial, [{ type: "pass", seat: 1 }])).toThrow(/expected seat/);
    const invalidTail = [{ type: "bid", seat: 0, value: 9 }, { type: "pass", seat: 3 }] as const;
    expect(() => auditSaskuHand(initial, invalidTail)).toThrow(/expected seat/);
    expect(() => auditSaskuHand(initial, [
      { type: "diamonds", seat: 0 }, { type: "play", seat: 0, card: "6C" }, { type: "play", seat: 1, card: "6C" },
    ])).toThrow(/more than once/);
  });

  it("preserves structured private-rule errors in the complete-information controller", () => {
    const cases: readonly { prefix: readonly SaskuHandAction[]; action: SaskuHandAction; rule: SaskuHandAuditRule }[] = [
      { prefix: [], action: { type: "bid", seat: 0, value: 9 }, rule: "bid_strength" },
      { prefix: [{ type: "diamonds", seat: 0 }], action: { type: "play", seat: 0, card: "7C" }, rule: "card_ownership" },
      { prefix: [{ type: "diamonds", seat: 0 }, { type: "play", seat: 0, card: "6C" }], action: { type: "play", seat: 1, card: "JC" }, rule: "follow_suit" },
    ];
    for (const { prefix, action, rule } of cases) {
      const game = new SaskuHandController(setup(3));
      for (const preceding of prefix) game.apply(preceding);
      const before = game.snapshot;
      expect(() => game.apply(action)).toThrow(expect.objectContaining({ rule }));
      expect(game.snapshot).toEqual(before);
      expect(game.history).toEqual(prefix);
    }
  });
});

function setup(dealer: SaskuSeat, distribution: "round-robin" | "unequal" = "round-robin"): SaskuHandSetup {
  if (distribution === "unequal") {
    const high: SaskuCardId[] = ["KC", "QC", "JC", "KS", "QS", "JS", "KH", "6H", "6D"];
    const low: SaskuCardId[] = ["QH", "JH", "6C", "7C", "8C", "6S", "7S", "7H", "7D"];
    const remaining = SASKU_DECK_SPEC.cards.filter((card) => !high.includes(card) && !low.includes(card));
    return { dealer, hands: [high, low, remaining.slice(0, 9), remaining.slice(9)] };
  }
  const hands = [[], [], [], []] as SaskuCardId[][];
  SASKU_DECK_SPEC.cards.forEach((card, index) => hands[index % 4]!.push(card));
  return { dealer, hands: hands as unknown as SaskuDeal };
}
