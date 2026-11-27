import type { TableStatus } from "./lobby-types";
import { useEffect, useState } from "react";
import type { SaskuActionIntent } from "@p2pcards/game-sasku";
import { SASKU_SUITS, parseSaskuCard } from "@p2pcards/rules-sasku";
import type { LiveRoundView } from "./live-round";
import { SaskuCardFace, saskuCardName, SASKU_SUIT_MARKS } from "./sasku-card-display";
import { compareSaskuHandCards } from "./sasku-hand-order";

import { backgroundWarning, observeRoundVisibility } from "./connection-warnings";

const SUIT_LABELS = { clubs: "Clubs", spades: "Spades", hearts: "Hearts", diamonds: "Diamonds" } as const;

export function LiveSaskuRound({ view, act, warnOnBackground, table, vote }: {
  view: LiveRoundView;
  act: (intent: SaskuActionIntent) => Promise<void>;
  warnOnBackground: boolean;
  table: TableStatus | null;
  vote: () => Promise<void> | undefined;
}) {
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const state = view.state?.hand;
  const mine = state?.turn === view.seat;
  const yourTurn = view.connected && mine && ["bidding", "choosing_trump", "playing"].includes(view.phase);
  const enabled = mine && view.connected && !submitting && !view.error;
  const send = async (intent: SaskuActionIntent) => {
    setError(null); setSubmitting(true);
    try { await act(intent); } catch (e) { setError(e instanceof Error ? e.message : "Action failed"); }
    finally { setSubmitting(false); }
  };
  const trump = state?.contract?.kind === "pass_round" ? "diamonds" : state?.contract?.suit;
  const preparing = ["setup", "shuffle", "dealing"].includes(view.phase);
  const done = view.phase === "match_complete";
  const roundDone = view.phase === "complete" || done;
  const [tabVisibility, setTabVisibility] = useState<"visible" | "hidden" | "resumed">("visible");
  const watchVisibility = warnOnBackground && !roundDone;
  useEffect(() => {
    setTabVisibility("visible");
    if (watchVisibility) return observeRoundVisibility(document, setTabVisibility);
  }, [watchVisibility, view.match.round]);
  const visibilityWarning = watchVisibility ? backgroundWarning(view.phase, tabVisibility) : null;
  const auction = view.phase === "bidding" || view.phase === "choosing_trump";
  const team = view.seat % 2;
  const last = state?.completedTricks.at(-1);
  const showingLast = Boolean(last && state?.trick.length === 0);
  const displayedTrick = showingLast ? last!.plays : state?.trick ?? [];
  const turnLabel = view.phase === "bidding" ? "Your turn to bid" : view.phase === "choosing_trump" ? "Choose your trump" : "Your turn to play";
  const title = table?.ended ? "Table ended" : done
    ? view.match.winner === team ? "Your team won the game" : "The opponents won the game"
    : view.phase === "complete" ? `Round ${view.match.round} complete`
    : view.phase === "audit" ? "Verifying hand"
    : preparing ? "Dealing round"
    : mine ? turnLabel : `Player ${(state?.turn ?? 0) + 1}’s turn`;
  const instruction = table?.ended ? "You can leave the table whenever you are ready." : preparing
    ? !view.connected ? "Waiting for all four players to connect."
      : view.phase === "setup" ? "Exchanging round keys with the table."
      : view.phase === "shuffle" ? view.message
      : "Decrypting your nine cards locally."
    : done ? `Match finished after ${view.match.completed.length} ${view.match.completed.length === 1 ? "round" : "rounds"}.`
    : view.phase === "complete" ? "Next round starts automatically."
    : view.phase === "audit" ? "Checking all 36 cards and plays against the signed transcript."
    : !view.connected ? "Reconnecting to peers — your hand is saved locally."
    : submitting ? "Sending move…"
    : view.phase === "bidding"
      ? mine ? "Bid up to your hand strength, pass, or call diamonds." : `Waiting for Player ${(state?.turn ?? 0) + 1} to bid.`
    : view.phase === "choosing_trump"
      ? mine ? "Pick the trump suit for this hand." : `Player ${(state?.turn ?? 0) + 1} won the auction and is choosing trump.`
    : mine
      ? state?.trick.length ? "Follow the led suit if able. Legal cards are highlighted." : "Lead any card from your hand."
      : `Waiting for Player ${(state?.turn ?? 0) + 1} to play.`;
  // Keep signed deck positions intact while ordering only the displayed cards.
  const cards = [...view.hand].sort((a, b) => compareSaskuHandCards(a.card, b.card));
  const firstBid = Math.max(3, (state?.highestBid?.value ?? 2) + 1);
  return <section className="live-round" aria-label="Live Sasku round" data-phase={view.phase} data-seat={view.seat} data-turn={state?.turn ?? ""} data-actions={view.state?.history.length ?? 0}>
    <header className={`live-heading${yourTurn ? " live-heading--your-turn" : ""}`}>
      <div>
        <p className="eyebrow">Sasku · Round {view.match.round} · Dealer: Player {((3 + view.match.round - 1) % 4) + 1}</p>
        <h2>{title}</h2>
        <p className="live-instruction" role="status">{instruction}</p>
      </div>
      <span className={`live-turn-badge ${yourTurn ? "is-yours" : ""}`}>
        {preparing ? "Dealing" : done ? "Match over" : yourTurn ? "Your turn" : `Seat ${view.seat + 1}`}
      </span>
    </header>
    {visibilityWarning && <p role="status" className="notice notice--network">{visibilityWarning}</p>}
    {table?.ended ? <p role="status" className="notice notice--error">{table.ended}</p>
      : !done && !!table?.disconnected.length && <div className="notice" aria-label="Disconnected players">
        <p role="status">{table.disconnected.map(seat => `Player ${seat + 1}`).join(", ")} {table.disconnected.length === 1 ? "is" : "are"} disconnected. Play resumes when all players reconnect.</p>
        {table.canVote && <div className="hand-action-buttons">
          <button className="button button--secondary" disabled={table.voted} onClick={() => void vote()?.catch(cause => setError(cause instanceof Error ? cause.message : "Could not vote"))}>
            {table.voted ? "Vote cast" : "Vote to end table"}
          </button>
          <span role="status">{table.votes} of {table.needed} connected players voted to end the table.</span>
        </div>}
      </div>}
    {(view.error || error) && <p role="alert" className="notice notice--error">{view.error ?? error}</p>}
    <div className="live-scoreboard" aria-label="Round scoreboard">
      <div>
        <span>Your team <small>Seats {team === 0 ? "1 + 3" : "2 + 4"}</small></span>
        <strong>{state?.cardPoints[team] ?? 0}<small> pts</small></strong>
      </div>
      <div className="live-contract">
        {trump ? <>
          <span>Trump{state?.contract?.kind === "named" ? ` · P${state.contract.declarerSeat + 1}` : " · Pass"}</span>
          <strong className={`trump-symbol${trump === "hearts" || trump === "diamonds" ? " suit-red" : ""}`} aria-label={trump}>{SASKU_SUIT_MARKS[trump]}</strong>
        </> : <>
          <span>Trump</span>
          <strong className="trump-unset">—</strong>
        </>}
      </div>
      <div>
        <span>Opponents <small>Seats {team === 0 ? "2 + 4" : "1 + 3"}</small></span>
        <strong>{state?.cardPoints[1 - team] ?? 0}<small> pts</small></strong>
      </div>
    </div>
    <div className="live-match-score" aria-label="Match scoreboard" role="status">
      <div className="live-match-score__main">
        <span className="live-match-score__label">Match score</span>
        <div className="live-match-score__totals">
          <span className="live-match-score__team"><small>Your team</small><strong>{view.match.totals[team]}</strong></span>
          <span className="live-match-score__divider" aria-hidden="true">:</span>
          <span className="live-match-score__team"><small>Opponents</small><strong>{view.match.totals[1 - team]}</strong></span>
        </div>
      </div>
      <div className="live-match-score__progress">
        <span>Target: 12 P</span>
        <span>{view.match.completed.length} {view.match.completed.length === 1 ? "round" : "rounds"} verified</span>
      </div>
    </div>
    {preparing ? <div className="live-preparation">
      <h3>{view.phase === "setup" ? "Setting up the round" : view.phase === "shuffle" ? "Shuffling and proving the deck" : "Dealing private hands"}</h3>
      <p>{view.message || "Your nine cards will appear automatically once all four browsers finish."}</p>
      <ol aria-label="Hand preparation">{["Keys", "Shuffle", "Deal"].map((label, i) => <li key={label} aria-current={i === ["setup", "shuffle", "dealing"].indexOf(view.phase) ? "step" : undefined} className={i < ["setup", "shuffle", "dealing"].indexOf(view.phase) ? "is-complete" : ""}><span>{i + 1}</span>{label}</li>)}</ol>
    </div> : <div className={`live-felt${auction ? " live-felt--auction" : ""}`} aria-label={showingLast ? "Last completed trick" : "Current live trick"}>
      {!auction && <div className="live-trick-status" role="status">
        <span>{showingLast ? "Previous trick" : roundDone ? "Hand complete" : `Trick ${Math.min((state?.completedTricks.length ?? 0) + 1, 9)} of 9`}</span>
        {showingLast && <strong>{last!.winner.seat === view.seat ? "Won by you" : `Won by Player ${last!.winner.seat + 1}`} · {last!.cardPoints} pts</strong>}
      </div>}
      <div className="live-trick-layout">
        {view.phase === "bidding" && <div className="live-auction-status">
          <span>{state?.highestBid ? "High bid" : "Auction"}</span>
          <strong>{state?.highestBid ? state.highestBid.value : "No bids yet"}</strong>
          {state?.highestBid && <small>Player {state.highestBid.seat + 1}</small>}
        </div>}
        {[0, 1, 2, 3].map(relative => {
          const seat = (view.seat + relative) % 4, play = displayedTrick.find(p => p.seat === seat);
          const active = state?.turn === seat && !done && view.phase !== "audit";
          return <div key={seat} className={`live-player live-player--${relative}${active ? " is-active" : ""}`} aria-current={active ? "true" : undefined}>
            <div className="live-player-label"><span>{relative === 0 ? "You" : `Player ${seat + 1}`}</span><small>{relative === 2 ? "Partner" : relative === 0 ? `Seat ${seat + 1}` : "Opponent"}</small></div>
            {play ? <div className={`live-played-card ${["hearts", "diamonds"].includes(parseSaskuCard(play.card).suit) ? "is-red" : ""}`} aria-label={`Player ${seat + 1}: ${saskuCardName(play.card)}`}><SaskuCardFace id={play.card} /></div>
              : <div className="live-card-space" aria-hidden="true">{active ? "Turn" : ""}</div>}
          </div>;
        })}
      </div>
    </div>}
    {!preparing && !roundDone && auction && <div className="live-actions">
      {view.phase === "bidding" ? <>
        <p className="live-actions__meta">Max bid for your hand: <strong>{view.strength}</strong>{state?.highestBid ? ` · High bid: ${state.highestBid.value} (Player ${state.highestBid.seat + 1})` : ""}</p>
        <div className="hand-action-buttons">
          {Array.from({ length: Math.max(0, (view.strength ?? 0) - firstBid + 1) }, (_, index) => firstBid + index).map(value => <button key={value} className="button button--primary" disabled={!enabled} onClick={() => void send({ type: "bid", value })}>Bid {value}</button>)}
          <button className="button button--secondary" disabled={!enabled} onClick={() => void send({ type: "pass" })}>Pass</button>
          <button className="button button--secondary" disabled={!enabled} onClick={() => void send({ type: "diamonds" })}>Call diamonds</button>
        </div>
      </> : <div className="hand-action-buttons trump-choices" role="group" aria-label="Choose trump">{SASKU_SUITS.map(suit => <button className={`trump-choice trump-choice--${suit}`} key={suit} disabled={!enabled} onClick={() => void send({ type: "choose_trump", suit })} aria-label={`Choose ${suit}`}><span className="trump-choice__mark" aria-hidden="true">{SASKU_SUIT_MARKS[suit]}</span><span className="trump-choice__name">{SUIT_LABELS[suit]}</span></button>)}</div>}
    </div>}
    <div className="live-hand-heading">
      <span>{roundDone ? "Hand finished" : "Your hand"}</span>
      {!roundDone && cards.length > 0 && <small>{cards.length} {cards.length === 1 ? "card" : "cards"} · ordered weak to strong</small>}
    </div>
    <div className="live-hand" aria-label="Your private hand">{cards.map(({ position, card, playable }) => {
      const suit = parseSaskuCard(card).suit, available = enabled && playable && view.phase === "playing";
      return <button key={position} className={`live-hand-card${suit === "hearts" || suit === "diamonds" ? " is-red" : ""}${available ? " is-playable" : ""}`}
        disabled={!available} aria-label={`Play ${saskuCardName(card)}`} onClick={() => void send({ type: "play", position })}>
        <SaskuCardFace id={card} />
      </button>;
    })}</div>
    {roundDone && <div className="live-result" role="status">
      {view.state?.audit?.result?.status === "valid" ? <>
        <p className="eyebrow">Hand audited</p>
        <h3>Your team +{view.state.audit.result.score.gamePoints[team]} P <span>· Opponents +{view.state.audit.result.score.gamePoints[1 - team]} P</span></h3>
        <p>All 36 cards, bids, and suit-following plays verified locally.</p>
      </> : <p>Hand audit detected a rule violation. Score rejected.</p>}
      <p>{done ? "Match complete. You can leave the table whenever you are ready." : "Dealing the next round automatically…"}</p>
    </div>}
    {view.match.completed.length > 0 && <details className="live-history"><summary>Round history <span>{view.match.completed.length} {view.match.completed.length === 1 ? "round" : "rounds"}</span></summary><ol>{view.match.completed.map(round => <li key={round.round}><strong>Round {round.round}</strong><span>Dealer: Player {round.dealer + 1} · Team 1 + 3: +{round.score.gamePoints[0]} P · Team 2 + 4: +{round.score.gamePoints[1]} P</span></li>)}</ol></details>}
    {state && state.completedTricks.length > 0 && <details className="live-history"><summary>Completed tricks <span>{state.completedTricks.length} / 9</span></summary><ol>{state.completedTricks.map((trick, index) => <li key={index}><strong>Trick {index + 1}</strong><span>Won by Player {trick.winner.seat + 1} · {trick.cardPoints} pts</span><div className="live-history-cards">{trick.plays.map(play => <div className="live-history-play" key={play.seat} role="img" aria-label={`Player ${play.seat + 1}: ${saskuCardName(play.card)}`}><small>P{play.seat + 1}</small><span className="live-history-card"><SaskuCardFace id={play.card} /></span></div>)}</div></li>)}</ol></details>}
  </section>;
}
