import { useState } from "react";
import {
  legalSaskuCards, parseSaskuCard, resolveSaskuTrick, winningSaskuPlay,
  type SaskuCardId, type SaskuPlay,
} from "@p2pcards/rules-sasku";
import { SASKU_SUIT_MARKS as SUITS, SaskuCardFace as CardFace, saskuCardName as cardName } from "./sasku-card-display";

interface Example {
  readonly title: string;
  readonly instruction: string;
  readonly hand: readonly SaskuCardId[];
  readonly trick: readonly SaskuPlay[];
}

const EXAMPLES: readonly Example[] = [
  {
    title: "Void in the led suit",
    instruction: "Hearts were led. Your only printed heart is a queen, which counts only as trump. You may trump or discard any card.",
    hand: ["QH", "10C", "8S", "9D", "6C", "7C", "7S", "8D", "AD"],
    trick: [{ seat: 0, card: "10H" }, { seat: 1, card: "AH" }, { seat: 2, card: "6H" }],
  },
  {
    title: "Follow the plain suit",
    instruction: "You have a non-court heart, so you must follow hearts. The queen's printed heart does not make it a following card.",
    hand: ["AH", "QH", "10C", "8S", "9D", "6C", "7C", "7S", "AD"],
    trick: [{ seat: 0, card: "10H" }, { seat: 1, card: "6H" }, { seat: 2, card: "7H" }],
  },
  {
    title: "A court leads trump",
    instruction: "The jack of hearts leads trump, not hearts. Follow with any trump you hold. You do not have to overtake the winning card.",
    hand: ["KD", "AD", "9D", "AH", "10C", "8S", "6C", "7C", "7S"],
    trick: [{ seat: 0, card: "JH" }, { seat: 1, card: "6D" }, { seat: 2, card: "7D" }],
  },
];

const TRUMP = "diamonds" as const;

export function SaskuTrickReference() {
  const [exampleIndex, setExampleIndex] = useState(0);
  const [chosen, setChosen] = useState<SaskuCardId | null>(null);
  const example = EXAMPLES[exampleIndex]!;
  const legal = legalSaskuCards(example.hand, example.trick, TRUMP);
  const selected = chosen !== null && legal.includes(chosen) ? chosen : null;
  const plays: readonly SaskuPlay[] = selected === null ? example.trick : [...example.trick, { seat: 3, card: selected }];
  const winner = winningSaskuPlay(plays, TRUMP)!;
  const result = selected === null ? null : resolveSaskuTrick(plays, TRUMP);

  return <details className="trick-reference">
    <summary>Sasku trick practice <span>Try the confirmed following rules</span></summary>
    <div className="practice-heading">
      <div><p className="eyebrow">A card at a time</p><h2>Follow the suit.<br /><em>Know the trump.</em></h2></div>
      <p>Public examples, not a live or cryptographically dealt hand. Each supplies its own leader and diamonds as trump, with demonstration play order 1, 2, 3, 4. No lobby or transcript is changed.</p>
    </div>
    <div className="practice-selector"><label htmlFor="sasku-trick-example">Practice situation</label>
      <select id="sasku-trick-example" value={exampleIndex} onChange={(event) => { setExampleIndex(Number(event.target.value)); setChosen(null); }}>
        {EXAMPLES.map((value, index) => <option key={value.title} value={index}>{value.title}</option>)}
      </select>
    </div>
    <div className="practice-layout">
      <section className="practice-table" aria-label="Example trick">
        <div className="practice-caption"><span>Plays, in order</span><strong>{SUITS.diamonds} Diamonds are trump</strong></div>
        <ol className="practice-plays">{Array.from({ length: 4 }, (_, index) => {
          const play = plays[index];
          return <li key={index}><span className="practice-seat">Seat {index + 1}</span>
            {play === undefined ? <div className="practice-empty">Your choice</div> : <div className={`practice-card ${parseSaskuCard(play.card).suit === "hearts" || parseSaskuCard(play.card).suit === "diamonds" ? "practice-card--red" : ""}`} aria-label={cardName(play.card)}><CardFace id={play.card} /></div>}
          </li>;
        })}</ol>
        <div className="practice-result" role="status">
          <h3>{result === null ? `Seat ${winner.seat + 1} is leading` : `Seat ${winner.seat + 1} takes the trick`}</h3>
          <p>The {cardName(winner.card)}{result === null ? " is winning. Choose a legal card to finish the example." : ` wins ${result.cardPoints} card points for partnership ${result.partnership === 0 ? "A" : "B"}.`}</p>
        </div>
      </section>
      <section className="practice-hand" aria-label="Original example hand for seat four">
        <p className="eyebrow">Original example hand / Seat 4</p>
        <p className="practice-instruction">{example.instruction}</p>
        <div className="practice-cards">{example.hand.map((id) => {
          const allowed = legal.includes(id);
          const card = parseSaskuCard(id);
          return <button key={id} className={`practice-card ${card.suit === "hearts" || card.suit === "diamonds" ? "practice-card--red" : ""} ${selected === id ? "practice-card--chosen" : ""}`}
            aria-label={`Play ${cardName(id)}`} aria-pressed={selected === id} disabled={!allowed || selected !== null}
            title={allowed ? "Legal choice" : "You must follow the effective led suit"} onClick={() => setChosen(id)}>
            <CardFace id={id} /><small>{selected === id ? "Played" : allowed ? "Legal" : "Cannot follow"}</small>
          </button>;
        })}</div>
        <p className="practice-legal-count">{legal.length} legal {legal.length === 1 ? "choice" : "choices"}. Courts belong only to trump; a void hand may discard freely.</p>
        <button className="button button--secondary" disabled={selected === null} onClick={() => setChosen(null)}>Try another card</button>
      </section>
    </div>
  </details>;
}
