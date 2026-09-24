import { legalSaskuCards, parseSaskuCard, resolveSaskuTrick, SaskuPlayError, type SaskuCardId, type SaskuPlay, type SaskuTrickResult } from "./cards";
import { SASKU_SUITS, scoreSaskuHand, type SaskuContract, type SaskuHandScore, type SaskuSeat, type SaskuSuit } from "./scoring";

export const MAX_SASKU_HAND_ACTIONS = 64;
export type SaskuDeal = readonly [readonly SaskuCardId[], readonly SaskuCardId[], readonly SaskuCardId[], readonly SaskuCardId[]];
export interface SaskuPublicHandSetup { readonly dealer: SaskuSeat }
export interface SaskuHandSetup extends SaskuPublicHandSetup { readonly hands: SaskuDeal }
export type SaskuHandAction =
  | { readonly type: "pass" | "diamonds"; readonly seat: SaskuSeat }
  | { readonly type: "bid"; readonly seat: SaskuSeat; readonly value: number }
  | { readonly type: "choose_trump"; readonly seat: SaskuSeat; readonly suit: SaskuSuit }
  | { readonly type: "play"; readonly seat: SaskuSeat; readonly card: SaskuCardId };
export type SaskuHandPhase = "bidding" | "choosing_trump" | "playing" | "complete";
export interface SaskuCompletedTrick extends SaskuTrickResult { readonly plays: readonly SaskuPlay[] }
export interface SaskuHandSnapshot {
  readonly phase: SaskuHandPhase;
  readonly dealer: SaskuSeat;
  readonly turn: SaskuSeat | null;
  readonly highestBid: { readonly seat: SaskuSeat; readonly value: number } | null;
  readonly consecutivePasses: number;
  readonly contract: SaskuContract | null;
  readonly trick: readonly SaskuPlay[];
  readonly completedTricks: readonly SaskuCompletedTrick[];
  readonly cardPoints: readonly [number, number];
  readonly tricksWon: readonly [number, number];
  readonly handSizes: readonly number[];
  readonly score: SaskuHandScore | null;
  readonly nextDealer: SaskuSeat | null;
}
export interface SaskuPublicHandSnapshot extends Omit<SaskuHandSnapshot, "score"> {
  readonly provisionalScore: SaskuHandScore | null;
}
export type SaskuHandAuditRule = "bid_strength" | "card_ownership" | "follow_suit";
export type SaskuHandAuditResult =
  | { readonly status: "valid" | "incomplete"; readonly snapshot: SaskuHandSnapshot }
  | { readonly status: "violation"; readonly seat: SaskuSeat; readonly at: number; readonly rule: SaskuHandAuditRule };

interface HandState {
  phase: SaskuHandPhase;
  readonly dealer: SaskuSeat;
  turn: SaskuSeat | null;
  highestBid: { readonly seat: SaskuSeat; readonly value: number } | null;
  consecutivePasses: number;
  contract: SaskuContract | null;
  readonly hands: SaskuCardId[][] | null;
  readonly handSizes: number[];
  trick: readonly SaskuPlay[];
  readonly completedTricks: SaskuCompletedTrick[];
  readonly cardPoints: [number, number];
  readonly tricksWon: [number, number];
  score: SaskuHandScore | null;
  readonly history: SaskuHandAction[];
}

export class SaskuHandError extends Error {
  readonly rule: SaskuHandAuditRule | null;
  constructor(message: string, rule: SaskuHandAuditRule | null = null) {
    super(message); this.name = "SaskuHandError"; this.rule = rule;
  }
}

export function saskuBidStrength(hand: readonly SaskuCardId[]): number {
  if (!Array.isArray(hand) || hand.length !== 9) { throw new SaskuHandError("Bid strength requires a complete nine-card hand"); }
  const seen = new Set<SaskuCardId>();
  const suits: Record<SaskuSuit, number> = { clubs: 0, spades: 0, hearts: 0, diamonds: 0 };
  let courts = 0;
  for (let index = 0; index < 9; index += 1) {
    const card = parseSaskuCard(hand[index]);
    if (seen.has(card.id)) { throw new SaskuHandError("A bidding hand cannot repeat cards"); }
    seen.add(card.id);
    if (card.isCourt) { courts += 1; } else { suits[card.suit] += 1; }
  }
  return courts + Math.max(...Object.values(suits));
}

/** Complete-information reference/replay controller. Not a live peer's hidden-hand state or a deal verifier. */
export class SaskuHandController {
  #state: HandState;

  constructor(setup: SaskuHandSetup) {
    if (typeof setup !== "object" || setup === null || !Array.isArray(setup.hands) || setup.hands.length !== 4) {
      throw new SaskuHandError("A complete four-hand deal and dealer are required");
    }
    const dealer = seat(setup.dealer);
    const seen = new Set<SaskuCardId>();
    const hands = Array.from({ length: 4 }, (_, player) => {
      const hand = setup.hands[player];
      if (!Array.isArray(hand) || hand.length !== 9) { throw new SaskuHandError("Every player must start with nine cards"); }
      return Array.from({ length: 9 }, (_, index) => {
        const card = parseSaskuCard(hand[index]);
        if (seen.has(card.id)) { throw new SaskuHandError("The deal must contain each of the 36 cards exactly once"); }
        seen.add(card.id);
        return card.id;
      });
    });
    this.#state = initialState(dealer, hands);
  }

  get snapshot(): SaskuHandSnapshot { return snapshot(this.#state); }
  get history(): readonly SaskuHandAction[] { return Object.freeze([...this.#state.history]); }
  handFor(player: SaskuSeat): readonly SaskuCardId[] { return Object.freeze([...this.#state.hands![seat(player)]!]); }
  legalCardsForTurn(): readonly SaskuCardId[] {
    const state = this.#state;
    return state.phase === "playing" && state.turn !== null
      ? legalSaskuCards(state.hands![state.turn]!, state.trick, trumpSuit(state.contract!))
      : Object.freeze([]);
  }

  /** Non-mutating validation/preview, available to a future durable action coordinator. */
  preview(action: SaskuHandAction): SaskuHandSnapshot { return snapshot(nextState(this.#state, action)); }
  apply(action: SaskuHandAction): SaskuHandSnapshot {
    this.#state = nextState(this.#state, action);
    return this.snapshot;
  }
}

/** Public constraints only. Revealed cards need engine authentication/ownership checks; scores need a hand audit. */
export class SaskuPublicHandController {
  #state: HandState;

  constructor(setup: SaskuPublicHandSetup) {
    if (typeof setup !== "object" || setup === null || Array.isArray(setup) ||
        Object.keys(setup).length !== 1 || !Object.hasOwn(setup, "dealer")) {
      throw new SaskuHandError("Public hand setup must contain only an explicit dealer");
    }
    this.#state = initialState(seat(setup.dealer), null);
  }

  get snapshot(): SaskuPublicHandSnapshot { return publicSnapshot(this.#state); }
  get history(): readonly SaskuHandAction[] { return Object.freeze([...this.#state.history]); }
  preview(action: SaskuHandAction): SaskuPublicHandSnapshot { return publicSnapshot(nextState(this.#state, action)); }
  apply(action: SaskuHandAction): SaskuPublicHandSnapshot {
    this.#state = nextState(this.#state, action);
    return this.snapshot;
  }
}

function initialState(dealer: SaskuSeat, hands: SaskuCardId[][] | null): HandState {
  return { phase: "bidding", dealer, turn: nextSeat(dealer), highestBid: null, consecutivePasses: 0,
    contract: null, hands, handSizes: [9, 9, 9, 9], trick: [], completedTricks: [], cardPoints: [0, 0],
    tricksWon: [0, 0], score: null, history: [] };
}

function nextState(current: HandState, candidate: SaskuHandAction): HandState {
  const action = normalizeAction(candidate);
  if (current.phase === "complete") { throw new SaskuHandError("The hand is complete"); }
  if (action.seat !== current.turn) { throw new SaskuHandError("Action is not from the expected seat"); }
  if (current.history.length >= MAX_SASKU_HAND_ACTIONS) { throw new SaskuHandError("Hand action limit exceeded"); }
  const state: HandState = {
    ...current, hands: current.hands?.map((hand) => [...hand]) ?? null,
    handSizes: [...current.handSizes], completedTricks: [...current.completedTricks],
    cardPoints: [...current.cardPoints], tricksWon: [...current.tricksWon], history: [...current.history, action],
  };
  if (state.phase === "bidding") {
    if (action.type === "bid") {
      if (state.hands !== null && action.value > saskuBidStrength(state.hands[action.seat]!)) {
        throw new SaskuHandError("A bid cannot exceed the player's calculated hand strength", "bid_strength");
      }
      if (state.highestBid !== null && action.value <= state.highestBid.value) { throw new SaskuHandError("A bid must strictly exceed the current highest bid"); }
      if (current.history.some((past) => past.type === "bid" && past.seat === action.seat)) {
        throw new SaskuHandError("A player's bid cannot change while bidding");
      }
      state.highestBid = Object.freeze({ seat: action.seat, value: action.value });
      state.consecutivePasses = 0;
      state.turn = nextSeat(action.seat);
    } else if (action.type === "diamonds") {
      state.contract = Object.freeze({ kind: "named", suit: "diamonds", declarerSeat: action.seat });
      state.phase = "playing";
      state.turn = action.seat;
    } else if (action.type === "pass") {
      state.consecutivePasses += 1;
      if (state.highestBid === null && state.consecutivePasses === 4) {
        state.contract = Object.freeze({ kind: "pass_round" });
        state.phase = "playing";
        state.turn = nextSeat(state.dealer);
      } else if (state.highestBid !== null && state.consecutivePasses === 3) {
        state.phase = "choosing_trump";
        state.turn = state.highestBid.seat;
      } else { state.turn = nextSeat(action.seat); }
    } else { throw new SaskuHandError("Only bids, passes, or an on-turn diamonds call are allowed during bidding"); }
  } else if (state.phase === "choosing_trump") {
    if (action.type !== "choose_trump") { throw new SaskuHandError("The auction winner must choose the trump suit"); }
    state.contract = Object.freeze({ kind: "named", suit: action.suit, declarerSeat: action.seat });
    state.phase = "playing";
    state.turn = action.seat;
  } else {
    if (action.type !== "play") { throw new SaskuHandError("Only card plays are allowed during trick play"); }
    const hand = state.hands?.[action.seat];
    if (hand !== undefined) {
      if (!hand.includes(action.card)) { throw new SaskuHandError("The acting player does not hold that card", "card_ownership"); }
      if (!legalSaskuCards(hand, state.trick, trumpSuit(state.contract!)).includes(action.card)) {
        throw new SaskuHandError("The player must follow the effective led suit", "follow_suit");
      }
    }
    if (current.history.some((past) => past.type === "play" && past.card === action.card)) {
      throw new SaskuHandError("A card cannot be played more than once");
    }
    if (state.handSizes[action.seat] === 0) { throw new SaskuHandError("The acting player has no cards left"); }
    hand?.splice(hand.indexOf(action.card), 1);
    state.handSizes[action.seat]! -= 1;
    state.trick = Object.freeze([...state.trick, Object.freeze({ seat: action.seat, card: action.card })]);
    if (state.trick.length === 4) {
      const result = resolveSaskuTrick(state.trick, trumpSuit(state.contract!));
      state.completedTricks.push(Object.freeze({ ...result, plays: state.trick }));
      state.cardPoints[result.partnership] += result.cardPoints;
      state.tricksWon[result.partnership] += 1;
      state.trick = Object.freeze([]);
      if (state.completedTricks.length === 9) {
        state.score = scoreSaskuHand({ cardPoints: state.cardPoints, tricks: state.tricksWon, contract: state.contract! });
        state.phase = "complete";
        state.turn = null;
      } else { state.turn = result.winner.seat; }
    } else { state.turn = nextSeat(action.seat); }
  }
  return state;
}

export function replaySaskuHand(setup: SaskuHandSetup, actions: readonly SaskuHandAction[]): SaskuHandController {
  if (!Array.isArray(actions) || actions.length > MAX_SASKU_HAND_ACTIONS) { throw new SaskuHandError("Invalid or oversized hand action history"); }
  const controller = new SaskuHandController(setup);
  for (let index = 0; index < actions.length; index += 1) { controller.apply(actions[index]!); }
  return controller;
}

/** Checks a public action history against a supplied full deal, not signatures or cryptographic deal provenance. */
export function auditSaskuHand(setup: SaskuHandSetup, actions: readonly SaskuHandAction[]): SaskuHandAuditResult {
  if (!Array.isArray(actions) || actions.length > MAX_SASKU_HAND_ACTIONS) { throw new SaskuHandError("Invalid or oversized hand action history"); }
  const reference = new SaskuHandController(setup);
  const publicHand = new SaskuPublicHandController({ dealer: reference.snapshot.dealer });
  // Reject malformed or publicly impossible histories before attributing a hidden-hand violation.
  for (let index = 0; index < actions.length; index += 1) { publicHand.apply(actions[index]!); }
  const history = publicHand.history;
  for (let at = 0; at < history.length; at += 1) {
    const action = history[at]!;
    try { reference.apply(action); }
    catch (cause) {
      if (!(cause instanceof SaskuHandError) || cause.rule === null) { throw cause; }
      return Object.freeze({ status: "violation", seat: action.seat, at, rule: cause.rule });
    }
  }
  const result = reference.snapshot;
  return Object.freeze({ status: result.phase === "complete" ? "valid" : "incomplete", snapshot: result });
}

function snapshot(state: HandState): SaskuHandSnapshot {
  return Object.freeze({
    phase: state.phase, dealer: state.dealer, turn: state.turn, highestBid: state.highestBid,
    consecutivePasses: state.consecutivePasses, contract: state.contract,
    trick: Object.freeze([...state.trick]), completedTricks: Object.freeze([...state.completedTricks]),
    cardPoints: Object.freeze([...state.cardPoints]) as readonly [number, number],
    tricksWon: Object.freeze([...state.tricksWon]) as readonly [number, number],
    handSizes: Object.freeze([...state.handSizes]), score: state.score,
    nextDealer: state.phase === "complete" ? nextSeat(state.dealer) : null,
  });
}

function publicSnapshot(state: HandState): SaskuPublicHandSnapshot {
  const { score, ...result } = snapshot(state);
  return Object.freeze({ ...result, provisionalScore: score });
}

function normalizeAction(action: SaskuHandAction): SaskuHandAction {
  if (typeof action !== "object" || action === null || Array.isArray(action)) { throw new SaskuHandError("A hand action is required"); }
  const actor = seat(action.seat);
  const keys = Object.keys(action).sort().join(",");
  if ((action.type === "pass" || action.type === "diamonds") && keys === "seat,type") {
    return Object.freeze({ type: action.type, seat: actor });
  }
  if (action.type === "bid" && keys === "seat,type,value" && Number.isSafeInteger(action.value) && action.value >= 3 && action.value <= 9) {
    return Object.freeze({ type: "bid", seat: actor, value: action.value });
  }
  if (action.type === "choose_trump" && keys === "seat,suit,type" && SASKU_SUITS.includes(action.suit)) {
    return Object.freeze({ type: "choose_trump", seat: actor, suit: action.suit });
  }
  if (action.type === "play" && keys === "card,seat,type") {
    try { return Object.freeze({ type: "play", seat: actor, card: parseSaskuCard(action.card).id }); }
    catch (cause) { if (!(cause instanceof SaskuPlayError)) { throw cause; } }
  }
  throw new SaskuHandError("Invalid hand action fields or values");
}

function seat(value: SaskuSeat): SaskuSeat {
  if (!Number.isSafeInteger(value) || value < 0 || value > 3 || Object.is(value, -0)) { throw new SaskuHandError("Seat must be zero through three"); }
  return value;
}
function nextSeat(value: SaskuSeat): SaskuSeat { return ((value + 1) % 4) as SaskuSeat; }
function trumpSuit(contract: SaskuContract): SaskuSuit { return contract.kind === "pass_round" ? "diamonds" : contract.suit; }
