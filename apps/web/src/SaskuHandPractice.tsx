import { useRef, useState } from "react";
import {
  SASKU_DECK_SPEC, SASKU_SUITS, SaskuHandController, parseSaskuCard, saskuBidStrength,
  type SaskuCardId, type SaskuDeal, type SaskuHandAction, type SaskuSeat,
} from "@p2pcards/rules-sasku";
import { SASKU_SUIT_MARKS, SaskuCardFace, saskuCardName } from "./sasku-card-display";

// This distribution is an intentionally public fixture, not a shuffle or production dealing policy.
const PUBLIC_DEAL = Object.freeze([0, 1, 2, 3].map((seat) =>
  Object.freeze(SASKU_DECK_SPEC.cards.filter((_card, index) => index % 4 === seat)),
)) as SaskuDeal;
const HIGH_HAND: readonly SaskuCardId[] = Object.freeze(["KC", "QC", "JC", "KS", "QS", "JS", "KH", "6H", "6D"]);
const LOWER_HAND: readonly SaskuCardId[] = Object.freeze(["QH", "JH", "6C", "7C", "8C", "6S", "7S", "7H", "7D"]);
const remaining = SASKU_DECK_SPEC.cards.filter((card) => !HIGH_HAND.includes(card) && !LOWER_HAND.includes(card));
const PUBLIC_DEALS = Object.freeze([
  { label: "Equal strengths / 6, 6, 6, 6", hands: PUBLIC_DEAL },
  { label: "Raises and re-entry / 8, 5, 4, 7", hands: Object.freeze([HIGH_HAND, LOWER_HAND, Object.freeze(remaining.slice(0, 9)), Object.freeze(remaining.slice(9))]) as SaskuDeal },
]);

export function SaskuHandPractice() {
  const controller = useRef<SaskuHandController | null>(null);
  if (controller.current === null) { controller.current = new SaskuHandController({ dealer: 3, hands: PUBLIC_DEAL }); }
  const [state, setState] = useState(() => controller.current!.snapshot);
  const [dealIndex, setDealIndex] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const turn = state.turn;
  const hand = turn === null ? [] : controller.current.handFor(turn);
  const legal = controller.current.legalCardsForTurn();
  const strength = state.phase === "bidding" ? saskuBidStrength(hand) : null;
  const canBid = strength !== null && (state.highestBid === null || strength > state.highestBid.value);
  const trump = state.contract?.kind === "pass_round" ? "diamonds" : state.contract?.suit;
  const lastTrick = state.completedTricks.at(-1);

  const apply = (action: SaskuHandAction): void => {
    try { setState(controller.current!.apply(action)); setError(null); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Practice action failed"); }
  };
  const restart = (dealer: SaskuSeat, selectedDeal = dealIndex): void => {
    controller.current = new SaskuHandController({ dealer, hands: PUBLIC_DEALS[selectedDeal]!.hands });
    setState(controller.current.snapshot); setError(null);
  };

  return <details className="hand-practice">
    <summary>Full Sasku hand practice <span>Bid, choose trump, play nine tricks</span></summary>
    <div className="practice-heading">
      <div><p className="eyebrow">One hand, start to finish</p><h2>Call your hand.<br /><em>Play your cards.</em></h2></div>
      <p>This local exercise uses the confirmed auction and turn rules. All four hands are public, fixed examples. There is no cryptographic shuffle, network play, or verified game transcript, and your lobby is unchanged.</p>
    </div>
    {error !== null && <p className="notice notice--error" role="alert">{error}</p>}
    <div className="hand-practice-bar">
      <span>Dealer: seat {state.dealer + 1}</span><span>Order: 1 / 2 / 3 / 4</span>
      <button className="button button--quiet" onClick={() => restart(state.dealer)}>Restart example hand</button>
    </div>
    <div className="practice-selector"><label htmlFor="sasku-public-deal">Public practice deal</label>
      <select id="sasku-public-deal" value={dealIndex} onChange={(event) => {
        const selected = Number(event.target.value);
        if (PUBLIC_DEALS[selected] !== undefined) { setDealIndex(selected); restart(state.dealer, selected); }
      }}>{PUBLIC_DEALS.map((deal, index) => <option key={index} value={index}>{deal.label}</option>)}</select>
      <p className="privacy-note">Changing the example restarts this local hand. Neither example is shuffled.</p>
    </div>
    <div className="hand-practice-layout">
      <section className="hand-practice-main" aria-label="Practice hand controls">
        <div className="hand-phase" aria-live="polite">
          <p className="eyebrow">{state.phase === "bidding" ? "Auction" : state.phase === "choosing_trump" ? "Trump choice" : state.phase === "playing" ? `Trick ${state.completedTricks.length + 1} of 9` : "Hand result"}</p>
          <h3>{state.phase === "complete" ? "Practice hand complete" : state.phase === "choosing_trump" ? `Seat ${turn! + 1} chooses trump` : state.phase === "bidding" ? `Seat ${turn! + 1} to bid` : `Seat ${turn! + 1} to play`}</h3>
        </div>
        {state.phase === "bidding" && <>
          <p>Hand strength: <strong>{strength}</strong>. Courts count once, then add the longest non-court suit.</p>
          <p>{state.highestBid === null ? "No numerical bid yet." : `Highest bid: ${state.highestBid.value}, seat ${state.highestBid.seat + 1}.`} {state.consecutivePasses} consecutive {state.consecutivePasses === 1 ? "pass" : "passes"}.</p>
          <div className="hand-action-buttons">
            <button className="button button--primary" disabled={!canBid} onClick={() => apply({ type: "bid", seat: turn!, value: strength! })}>Bid {strength}</button>
            <button className="button button--secondary" onClick={() => apply({ type: "pass", seat: turn! })}>Pass</button>
            <button className="button button--secondary" onClick={() => apply({ type: "diamonds", seat: turn! })}>Name diamonds now</button>
          </div>
          <p className="privacy-note">A bid must be exact and strictly higher. Three passes after a bid end the auction; four initial passes mean default diamonds. A diamonds call ends bidding immediately on your turn.</p>
        </>}
        {state.phase === "choosing_trump" && <div className="hand-action-buttons">{SASKU_SUITS.map((suit) =>
          <button key={suit} className="button button--secondary" onClick={() => apply({ type: "choose_trump", seat: turn!, suit })}>Choose {suit} {SASKU_SUIT_MARKS[suit]}</button>,
        )}</div>}
        {state.phase === "playing" && <>
          <p className="hand-contract">{SASKU_SUIT_MARKS[trump!]} {trump} trump {state.contract?.kind === "pass_round" ? "/ pass-round" : `/ declared by seat ${state.contract!.declarerSeat + 1}`}</p>
          <ol className="hand-trick" aria-label="Current practice trick">{state.trick.map((play) => <li key={play.seat}><span>Seat {play.seat + 1}</span><strong>{parseSaskuCard(play.card).rank}{SASKU_SUIT_MARKS[parseSaskuCard(play.card).suit]}</strong></li>)}</ol>
          {state.trick.length === 0 && <p>Seat {turn! + 1} leads this trick. Any held card may lead.</p>}
          <p className="privacy-note">Follow the effective led suit if possible. Courts are trumps only; when void, any card is allowed.</p>
        </>}
        {state.phase !== "complete" && <div className="full-hand-cards" data-playing={state.phase === "playing"} aria-label={`Public practice hand for seat ${turn! + 1}`}>
          {hand.map((card) => {
            const parsed = parseSaskuCard(card);
            const playable = state.phase === "playing" && legal.includes(card);
            return <button key={card} className={`practice-card ${parsed.suit === "hearts" || parsed.suit === "diamonds" ? "practice-card--red" : ""}`}
              disabled={!playable} aria-label={`${state.phase === "playing" ? "Play" : "Held"} ${saskuCardName(card)}`} onClick={() => apply({ type: "play", seat: turn!, card })}>
              <SaskuCardFace id={card} /><small>{state.phase === "playing" ? playable ? "Legal" : "Must follow" : "Held card"}</small>
            </button>;
          })}
        </div>}
        {state.phase === "complete" && state.score !== null && <div className="hand-final-score" role="status">
          <p>Partnership A: <strong>{state.score.gamePoints[0]} P</strong> / Partnership B: <strong>{state.score.gamePoints[1]} P</strong></p>
          <p>{state.score.kind.replaceAll("_", " ")}. All 36 cards and 120 card points are accounted for.</p>
          <p>Next dealer: seat {state.nextDealer! + 1}. No match target or automatic match winner is assumed.</p>
          <button className="button button--primary" onClick={() => restart(state.nextDealer!)}>Next practice hand</button>
        </div>}
      </section>
      <aside className="hand-ledger" aria-label="Practice hand ledger">
        <p className="eyebrow">The hand ledger</p><h3>{state.completedTricks.length} of 9 tricks</h3>
        <dl><div><dt>A / seats 1 + 3</dt><dd>{state.cardPoints[0]} card points / {state.tricksWon[0]} tricks</dd></div><div><dt>B / seats 2 + 4</dt><dd>{state.cardPoints[1]} card points / {state.tricksWon[1]} tricks</dd></div></dl>
        <p>{state.handSizes.reduce((sum, size) => sum + size, 0)} cards remain in the hands.</p>
        {lastTrick !== undefined && <p className="hand-last-trick">Last trick: seat {lastTrick.winner.seat + 1} won with the {saskuCardName(lastTrick.winner.card)}, taking {lastTrick.cardPoints} card points.</p>}
        <details><summary>Completed tricks</summary><ol className="hand-trick-history">{state.completedTricks.map((trick, index) => <li key={index}>
          <strong>Trick {index + 1}: seat {trick.winner.seat + 1}, {trick.cardPoints} points</strong>
          <span>{trick.plays.map(({ seat, card }) => `${seat + 1}: ${card}`).join(" / ")}</span>
        </li>)}</ol>{state.completedTricks.length === 0 && <p>No tricks completed yet.</p>}</details>
        <details><summary>Inspect the public example deal</summary><p>This fixed distribution is a training fixture, not a production dealing policy.</p><ol className="public-deal">{PUBLIC_DEALS[dealIndex]!.hands.map((cards, seat) => <li key={seat}><strong>Seat {seat + 1}</strong><span>{cards.join(" ")}</span></li>)}</ol></details>
      </aside>
    </div>
  </details>;
}
