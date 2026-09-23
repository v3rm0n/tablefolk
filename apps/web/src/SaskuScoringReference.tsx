import { useState } from "react";
import {
  SASKU_CARD_POINTS, SASKU_COURT_ORDER, SASKU_SUITS, scoreSaskuHand,
  type SaskuHandScore, type SaskuScoreKind, type SaskuSeat, type SaskuSuit,
} from "@p2pcards/rules-sasku";

const suitMarks: Record<SaskuSuit, string> = { clubs: "\u2663", spades: "\u2660", hearts: "\u2665", diamonds: "\u2666" };
const rankMarks = { king: "K", queen: "Q", jack: "J" } as const;
const descriptions: Record<SaskuScoreKind, { title: string; detail: string }> = {
  simple_win: { title: "Simple win", detail: "61 to 89 card points earns the named-trump base award." },
  seajann: { title: "Seaj\u00e4nn", detail: "Exactly 90 card points adds 1 game point to the base award." },
  jann: { title: "J\u00e4nn", detail: "91 or more card points adds 2 game points to the base award." },
  karvane: { title: "Karvane", detail: "The other partnership took no tricks. The 12-point award replaces the ordinary score." },
  pokk: { title: "Pokk", detail: "At 60 : 60, the partnership that did not name trump receives 2 game points." },
  pass_round_win: { title: "Pass-round win", detail: "Diamonds became trump by default. The winners receive 2 game points, with no bonuses." },
  pass_round_tie: { title: "Pass-round tie", detail: "At 60 : 60 in a pass-round, neither partnership receives game points." },
};

export function SaskuScoringReference() {
  const [cardPoints, setCardPoints] = useState(90);
  const [tricks, setTricks] = useState(5);
  const [passRound, setPassRound] = useState(false);
  const [suit, setSuit] = useState<SaskuSuit>("clubs");
  const [declarer, setDeclarer] = useState<SaskuSeat>(0);
  let score: SaskuHandScore | null = null;
  let error: string | null = null;
  try {
    score = scoreSaskuHand({
      cardPoints: [cardPoints, 120 - cardPoints], tricks: [tricks, 9 - tricks],
      contract: passRound ? { kind: "pass_round" } : { kind: "named", suit, declarerSeat: declarer },
    });
  } catch (cause) { error = cause instanceof Error ? cause.message : "Enter valid completed-hand totals"; }

  return <section className="scoring-reference" aria-labelledby="scoring-title">
    <div className="scoring-intro">
      <div><p className="eyebrow">Sasku rules</p><h1 id="scoring-title">Scoring<br /><em>reference.</em></h1></div>
      <p>Try the rules for a completed nine-trick hand. These are manual examples, not results from a played or verified game. Nothing here changes your lobby or its transcript.</p>
    </div>
    <div className="scoring-layout">
      <form className="scoring-controls" aria-label="Completed hand scoring" onSubmit={(event) => event.preventDefault()}>
        <div className="partnership-labels"><strong>A <span>Seats 1 + 3</span></strong><strong>B <span>Seats 2 + 4</span></strong></div>
        <div className="scoring-totals">
          <div><label htmlFor="sasku-points">Partnership A card points</label><input id="sasku-points" type="number" min={0} max={120} step={1}
            value={Number.isFinite(cardPoints) ? cardPoints : ""} onChange={(event) => setCardPoints(event.currentTarget.valueAsNumber)} /></div>
          <div><label htmlFor="sasku-other-points">Partnership B card points</label><output id="sasku-other-points">{Number.isFinite(cardPoints) ? 120 - cardPoints : "Not set"}</output></div>
          <div><label htmlFor="sasku-tricks">Partnership A tricks</label><input id="sasku-tricks" type="number" min={0} max={9} step={1}
            value={Number.isFinite(tricks) ? tricks : ""} onChange={(event) => setTricks(event.currentTarget.valueAsNumber)} /></div>
          <div><label htmlFor="sasku-other-tricks">Partnership B tricks</label><output id="sasku-other-tricks">{Number.isFinite(tricks) ? 9 - tricks : "Not set"}</output></div>
        </div>
        <label htmlFor="sasku-contract">How was trump chosen?</label>
        <select id="sasku-contract" value={passRound ? "pass_round" : "named"} onChange={(event) => setPassRound(event.target.value === "pass_round")}>
          <option value="named">A player named trump</option><option value="pass_round">Nobody bid: diamonds by default</option>
        </select>
        <div className="scoring-totals">
          <div><label htmlFor="sasku-trump">Trump suit</label><select id="sasku-trump" disabled={passRound} value={passRound ? "diamonds" : suit} onChange={(event) => setSuit(event.target.value as SaskuSuit)}>
            {SASKU_SUITS.map((value) => <option key={value} value={value}>{suitMarks[value]} {value[0]!.toUpperCase() + value.slice(1)}</option>)}
          </select></div>
          <div><label htmlFor="sasku-declarer">Who named trump?</label><select id="sasku-declarer" disabled={passRound} value={declarer} onChange={(event) => setDeclarer(Number(event.target.value) as SaskuSeat)}>
            {[0, 1, 2, 3].map((seat) => <option key={seat} value={seat}>Seat {seat + 1} ({seat % 2 === 0 ? "A" : "B"})</option>)}
          </select></div>
        </div>
      </form>
      <section className="scoring-result" aria-label="Example hand score" aria-live="polite">
        <p className="eyebrow">Example result</p>
        {score === null ? <><h3>Check the totals.</h3><p role="alert">{error}</p><p>Nine tricks account for all 120 card points. Some totals are impossible for the number of cards captured.</p></> : <>
          <h3>{descriptions[score.kind].title}</h3>
          <div className="scoring-awards"><div><span>Partnership A</span><output aria-label="Partnership A game points">{score.gamePoints[0]} <small>P</small></output></div><div><span>Partnership B</span><output aria-label="Partnership B game points">{score.gamePoints[1]} <small>P</small></output></div></div>
          <p>{descriptions[score.kind].detail}</p>
          <p className="scoring-breakdown">Base award {score.basePoints} P <span>+</span> bonus {score.bonusPoints} P</p>
        </>}
        <p className="scoring-disclaimer">This calculator does not validate bids, trick winners, card ownership, or whether players followed suit.</p>
      </section>
    </div>
    <div className="scoring-rules">
      <section><h3>Card points</h3><dl className="point-values">{Object.entries(SASKU_CARD_POINTS).map(([rank, points]) => <div key={rank}><dt>{rank === "other" ? "Other cards" : rank[0]!.toUpperCase() + rank.slice(1)}</dt><dd>{points}</dd></div>)}</dl></section>
      <section><h3>Permanent trumps</h3><p>Strongest first. Every court is above the non-court cards of the chosen trump suit.</p><ol className="court-order">{SASKU_COURT_ORDER.map((card) => <li key={`${card.suit}:${card.rank}`} aria-label={`${card.rank} of ${card.suit}`}><span aria-hidden="true">{rankMarks[card.rank]}{suitMarks[card.suit]}</span></li>)}</ol></section>
    </div>
  </section>;
}
