import { useState } from "react";
import {
  SASKU_CARD_POINTS, SASKU_COURT_ORDER, SASKU_SUITS, scoreSaskuHand,
  type SaskuHandScore, type SaskuScoreKind, type SaskuSeat, type SaskuSuit,
} from "@p2pcards/rules-sasku";

const suitMarks: Record<SaskuSuit, string> = { clubs: "\u2663", spades: "\u2660", hearts: "\u2665", diamonds: "\u2666" };
const rankMarks = { king: "K", queen: "Q", jack: "J" } as const;
const descriptions: Record<SaskuScoreKind, { title: string; detail: string }> = {
  simple_win: { title: "Simple win", detail: "Taking 61 to 89 card points awards the base game points for the named trump." },
  seajann: { title: "Seaj\u00e4nn", detail: "Exactly 90 card points adds +1 bonus game point to the base award." },
  jann: { title: "J\u00e4nn", detail: "91 or more card points adds +2 bonus game points to the base award." },
  karvane: { title: "Karvane", detail: "Taking all nine tricks awards 12 game points immediately, winning the match." },
  pokk: { title: "Pokk", detail: "At a 60 : 60 tie, the partnership that did not name trump scores 2 game points." },
  pass_round_win: { title: "Pass-round win", detail: "Nobody bid, making diamonds trump by default. The winning side scores 2 game points with no bonuses." },
  pass_round_tie: { title: "Pass-round tie", detail: "At a 60 : 60 tie in a pass-round, neither partnership scores." },
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
      <div><h1 id="scoring-title">Scoring reference</h1></div>
      <p>The 36-card deck contains 120 card points across nine tricks. First partnership to 12 game points (P) wins the match.</p>
    </div>
    <div className="scoring-layout">
      <form className="scoring-controls" aria-label="Completed hand scoring" onSubmit={(event) => event.preventDefault()}>
        <div className="partnership-labels"><strong>Partnership A <span>Seats 1 + 3</span></strong><strong>Partnership B <span>Seats 2 + 4</span></strong></div>
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
            {[0, 1, 2, 3].map((seat) => <option key={seat} value={seat}>Seat {seat + 1} (Partnership {seat % 2 === 0 ? "A" : "B"})</option>)}
          </select></div>
        </div>
      </form>
      <section className="scoring-result" aria-label="Example hand score" aria-live="polite">
        <p className="eyebrow">Hand outcome</p>
        {score === null ? <><h3>Invalid totals</h3><p role="alert">{error}</p><p>Nine tricks must account for all 120 card points, and a team with zero tricks cannot have card points.</p></> : <>
          <h3>{descriptions[score.kind].title}</h3>
          <div className="scoring-awards"><div><span>Partnership A</span><output aria-label="Partnership A game points">{score.gamePoints[0]} <small>P</small></output></div><div><span>Partnership B</span><output aria-label="Partnership B game points">{score.gamePoints[1]} <small>P</small></output></div></div>
          <p>{descriptions[score.kind].detail}</p>
          <p className="scoring-breakdown">Base {score.basePoints} P <span>+</span> bonus {score.bonusPoints} P</p>
        </>}
        <p className="scoring-disclaimer">Base points when winning own trump: 2 P (4 P in ♦). Winning opponents’ trump: 4 P (6 P in ♦).</p>
      </section>
    </div>
    <div className="scoring-rules">
      <section><h3>Card point values</h3><dl className="point-values">{Object.entries(SASKU_CARD_POINTS).map(([rank, points]) => <div key={rank}><dt>{rank === "other" ? "6, 7, 8, 9" : rank[0]!.toUpperCase() + rank.slice(1)}</dt><dd>{points} pts</dd></div>)}</dl></section>
      <section><h3>Permanent trumps (weakest to strongest)</h3><p>All 12 court cards are always trumps, ranking above the Ace and Ten of the chosen trump suit: Jacks &lt; Queens &lt; Kings, and ♦ &lt; ♥ &lt; ♠ &lt; ♣.</p><ol className="court-order">{[...SASKU_COURT_ORDER].reverse().map((card) => <li className={card.suit === "hearts" || card.suit === "diamonds" ? "suit-red" : undefined} key={`${card.suit}:${card.rank}`} aria-label={`${card.rank} of ${card.suit}`}><span aria-hidden="true">{rankMarks[card.rank]}{suitMarks[card.suit]}</span></li>)}</ol></section>
    </div>
  </section>;
}
