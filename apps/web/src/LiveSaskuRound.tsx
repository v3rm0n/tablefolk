import { useState } from "react";
import type { SaskuActionIntent } from "@p2pcards/game-sasku";
import { SASKU_SUITS, parseSaskuCard } from "@p2pcards/rules-sasku";
import type { LiveRoundView } from "./live-round";
import { SaskuCardFace, saskuCardName, SASKU_SUIT_MARKS } from "./sasku-card-display";

export function LiveSaskuRound({ view, act }: { view: LiveRoundView; act: (intent: SaskuActionIntent) => Promise<void> }) {
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const state = view.state?.hand;
  const mine = state?.turn === view.seat;
  const enabled = mine && view.connected && !submitting && !view.error;
  const send = async (intent: SaskuActionIntent) => {
    setError(null); setSubmitting(true);
    try { await act(intent); } catch (e) { setError(e instanceof Error ? e.message : "Action failed"); }
    finally { setSubmitting(false); }
  };
  const trump = state?.contract?.kind === "pass_round" ? "diamonds" : state?.contract?.suit;
  const preparing = ["setup", "shuffle", "dealing"].includes(view.phase);
  const done = view.phase === "complete";
  const team = view.seat % 2;
  const last = state?.completedTricks.at(-1);
  const showingLast = Boolean(last && state?.trick.length === 0);
  const displayedTrick = showingLast ? last!.plays : state?.trick ?? [];
  const turnLabel = view.phase === "bidding" ? "Your turn to bid" : view.phase === "choosing_trump" ? "Choose your trump" : "Your turn to play";
  const title = done ? "First round complete" : view.phase === "audit" ? "Checking the round" : preparing ? "Preparing your hand" : mine ? turnLabel : `Player ${(state?.turn ?? 0) + 1}’s turn`;
  const instruction = preparing ? !view.connected ? "Waiting for everyone to start or reconnect." : view.phase === "setup" ? "Getting the table ready with all four players." : view.phase === "shuffle" ? view.message : "Your nine cards will appear automatically." : done ? "Nine tricks played. Here’s how your table finished." : view.phase === "audit" ? "Checking all cards and plays before confirming the score."
    : !view.connected ? "Syncing the table. Your hand is saved." : submitting ? "Saving your move…" : view.phase === "bidding" ? mine ? "Bid your hand strength, pass, or call diamonds." : "You can review your hand while you wait."
    : view.phase === "choosing_trump" ? mine ? "Choose the trump suit for this round." : "The auction winner is choosing trump."
    : mine ? state?.trick.length ? "Follow the led suit. Highlighted cards are legal." : "You lead. Choose any card from your hand." : "The next play will appear on the table.";
  // Keep the hand in a familiar suit/rank order, without changing signed deck positions.
  const cards = [...view.hand].sort((a, b) => {
    const left = parseSaskuCard(a.card), right = parseSaskuCard(b.card);
    return SASKU_SUITS.indexOf(left.suit) - SASKU_SUITS.indexOf(right.suit) || ["A", "K", "Q", "J", "10", "9", "8", "7", "6"].indexOf(left.rank) - ["A", "K", "Q", "J", "10", "9", "8", "7", "6"].indexOf(right.rank);
  });
  return <section className="live-round" aria-label="Live Sasku round" data-phase={view.phase}>
    <header className="live-heading">
      <div><p className="eyebrow">Sasku · Round 1</p><h2>{title}</h2><p className="live-instruction" role="status">{instruction}</p></div>
      <span className={`live-turn-badge ${mine && !preparing && !done ? "is-yours" : ""}`}>{preparing ? "Getting ready" : done ? "Round finished" : `You · Player ${view.seat + 1}`}</span>
    </header>
    {(view.error || error) && <p role="alert" className="notice notice--error">{view.error ?? error}</p>}
    <div className="live-scoreboard" aria-label="Round scoreboard">
      <div><span>Your team <small>{team === 0 ? "1 + 3" : "2 + 4"}</small></span><strong>{state?.cardPoints[team] ?? 0}<small> card points</small></strong></div>
      <div className="live-contract"><span>{trump ? "Trump" : "Contract"}</span><strong>{trump ? <>{SASKU_SUIT_MARKS[trump]} {trump}</> : "Not chosen"}</strong></div>
      <div><span>Opponents <small>{team === 0 ? "2 + 4" : "1 + 3"}</small></span><strong>{state?.cardPoints[1 - team] ?? 0}<small> card points</small></strong></div>
    </div>
    {preparing ? <div className="live-preparation">
      <span className="live-preparation-mark" aria-hidden="true">♠</span>
      <h3>{view.phase === "setup" ? "Everyone is getting ready" : view.phase === "shuffle" ? "Shuffling the deck" : "Dealing nine cards to you"}</h3>
      <p>Keep this tab open. Your hand will appear here automatically.</p>
      <ol aria-label="Hand preparation">{["Setup", "Shuffle", "Deal"].map((label, i) => <li key={label} aria-current={i === ["setup", "shuffle", "dealing"].indexOf(view.phase) ? "step" : undefined} className={i < ["setup", "shuffle", "dealing"].indexOf(view.phase) ? "is-complete" : ""}><span>{i + 1}</span>{label}</li>)}</ol>
    </div> : <div className="live-felt" aria-label={showingLast ? "Last completed trick" : "Current live trick"}>
      <div className="live-table-center"><span>{showingLast ? "Last trick" : done ? "Round complete" : view.phase === "bidding" ? "Auction" : view.phase === "choosing_trump" ? "Trump choice" : `Trick ${Math.min((state?.completedTricks.length ?? 0) + 1, 9)} of 9`}</span>
        <strong className={showingLast ? "live-trick-winner" : undefined}>{showingLast ? `${last!.winner.seat === view.seat ? "You" : `Player ${last!.winner.seat + 1}`} won` : view.phase === "bidding" ? state?.highestBid ? `Bid ${state.highestBid.value}` : "Open bidding" : trump ? SASKU_SUIT_MARKS[trump] : "♠"}</strong>
        {showingLast ? <small>{last!.cardPoints} card points</small> : state?.highestBid && view.phase === "bidding" ? <small>Player {state.highestBid.seat + 1}</small> : null}</div>
      {[0, 1, 2, 3].map(relative => {
        const seat = (view.seat + relative) % 4, play = displayedTrick.find(p => p.seat === seat);
        const active = state?.turn === seat && !done && view.phase !== "audit";
        return <div key={seat} className={`live-player live-player--${relative}${active ? " is-active" : ""}`} aria-current={active ? "true" : undefined}>
          <div className="live-player-label"><span>{relative === 0 ? "You" : `Player ${seat + 1}`}</span><small>{relative === 2 ? "Your partner" : relative === 0 ? `Player ${seat + 1}` : "Opponent"}</small></div>
          {play ? <div className={`live-played-card ${["hearts", "diamonds"].includes(parseSaskuCard(play.card).suit) ? "is-red" : ""}`} aria-label={`Player ${seat + 1}: ${saskuCardName(play.card)}`}><SaskuCardFace id={play.card} /></div>
            : <div className="live-card-space" aria-hidden="true">{active ? "•••" : ""}</div>}
        </div>;
      })}
    </div>}
    {!preparing && !done && <div className="live-actions">
      {view.phase === "bidding" ? <><p>Hand strength <strong>{view.strength}</strong>{state?.highestBid ? ` · Highest bid ${state.highestBid.value}` : " · No bid yet"}</p><div className="hand-action-buttons">
        <button className="button button--primary" disabled={!enabled || view.strength === null || view.strength <= (state?.highestBid?.value ?? -1)} onClick={() => void send({ type: "bid", value: view.strength! })}>Bid {view.strength}</button>
        <button className="button button--secondary" disabled={!enabled} onClick={() => void send({ type: "pass" })}>Pass</button>
        <button className="button button--secondary" disabled={!enabled} onClick={() => void send({ type: "diamonds" })}>Name diamonds now</button>
      </div></> : view.phase === "choosing_trump" ? <div className="hand-action-buttons">{SASKU_SUITS.map(suit => <button className="button button--secondary" key={suit} disabled={!enabled} onClick={() => void send({ type: "choose_trump", suit })}>Choose {suit} {SASKU_SUIT_MARKS[suit]}</button>)}</div>
        : <p>{last ? <>Last trick: <strong>{last.winner.seat === view.seat ? "you" : `player ${last.winner.seat + 1}`}</strong> took {last.cardPoints} points.</> : "Courts are trumps. Follow the effective suit when you can."}</p>}
    </div>}
    <div className="live-hand-heading"><span>{done ? "All cards played" : "Your hand"}</span><small>{view.hand.length} cards · Only visible to you</small></div>
    <div className="live-hand" aria-label="Your private hand">{cards.map(({ position, card, playable }) => {
      const suit = parseSaskuCard(card).suit, available = enabled && playable && view.phase === "playing";
      return <button key={position} className={`live-hand-card${suit === "hearts" || suit === "diamonds" ? " is-red" : ""}${available ? " is-playable" : ""}`}
        disabled={!available} aria-label={`Play ${saskuCardName(card)}`} onClick={() => void send({ type: "play", position })}>
        <SaskuCardFace id={card} /><small>{available ? "Play" : "\u00a0"}</small>
      </button>;
    })}</div>
    {done && <div className="live-result" role="status">
      {view.state?.audit?.result?.status === "valid" ? <><p className="eyebrow">Round verified</p><h3>Your team: {view.state.audit.result.score.gamePoints[team]} P <span>· Opponents: {view.state.audit.result.score.gamePoints[1 - team]} P</span></h3><p>Round verified by this browser: all 36 cards and all plays checked.</p></> : <p>Round audit found a violation. The result is not accepted.</p>}
      <p>That’s the first round. You can leave the table when you’re ready.</p>
    </div>}
    {state && state.completedTricks.length > 0 && <details className="live-history"><summary>Completed tricks <span>{state.completedTricks.length} / 9</span></summary><ol>{state.completedTricks.map((trick, index) => <li key={index}><strong>Trick {index + 1}</strong><span>Player {trick.winner.seat + 1} · {trick.cardPoints} points</span><small>{trick.plays.map(p => `P${p.seat + 1}: ${p.card}`).join(" · ")}</small></li>)}</ol></details>}
  </section>;
}
