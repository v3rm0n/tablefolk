import { parseSaskuCard, type SaskuCardId, type SaskuSuit } from "@p2pcards/rules-sasku";

export const SASKU_SUIT_MARKS: Readonly<Record<SaskuSuit, string>> = Object.freeze({ clubs: "\u2663", spades: "\u2660", hearts: "\u2665", diamonds: "\u2666" });
const RANK_NAMES = { "6": "six", "7": "seven", "8": "eight", "9": "nine", "10": "ten", J: "jack", Q: "queen", K: "king", A: "ace" } as const;
const SUIT_PATHS: Record<SaskuSuit, string> = {
  hearts: "M12 22C9 18 1 12 1 7C1 0 9-1 12 5C15-1 23 0 23 7C23 12 15 18 12 22Z",
  diamonds: "M12 1L22 12L12 23L2 12Z",
  spades: "M12 1C9 5 1 10 1 15C1 21 8 23 11 17C11 20 9 22 7 23H17C15 22 13 20 13 17C16 23 23 21 23 15C23 10 15 5 12 1Z",
  clubs: "M10 16C6 24 0 20 1 14C2 10 6 10 8 12C2 5 7 0 12 1C17 0 22 5 16 12C18 10 22 10 23 14C24 20 18 24 14 16C13 19 14 22 18 23H6C10 22 11 19 10 16Z",
};
const PIPS: Record<string, readonly (readonly [number, number])[]> = {
  "6": [[32, 32], [68, 32], [32, 70], [68, 70], [32, 108], [68, 108]],
  "7": [[32, 32], [68, 32], [50, 51], [32, 70], [68, 70], [32, 108], [68, 108]],
  "8": [[32, 32], [68, 32], [50, 51], [32, 70], [68, 70], [50, 89], [32, 108], [68, 108]],
  "9": [[32, 30], [68, 30], [32, 56], [68, 56], [50, 70], [32, 84], [68, 84], [32, 110], [68, 110]],
  "10": [[32, 30], [68, 30], [50, 43], [32, 56], [68, 56], [32, 84], [68, 84], [50, 97], [32, 110], [68, 110]],
};

function Suit({ suit, x, y, size, inverted = false }: { suit: SaskuSuit; x: number; y: number; size: number; inverted?: boolean }) {
  return <g transform={`translate(${x} ${y})${inverted ? " rotate(180)" : ""} scale(${size / 24}) translate(-12 -12)`}><path d={SUIT_PATHS[suit]} fill="currentColor" /></g>;
}

/** Original double-ended vector court artwork, shared across suits and crisp at every card size. */
function CourtHalf({ rank, suit }: { rank: "J" | "Q" | "K"; suit: SaskuSuit }) {
  const ink = "#202d44", gold = "#d9ac44", red = "#b82735", skin = "#f4d8ae";
  return <g stroke={ink} strokeWidth=".8" strokeLinejoin="round">
    <path d="M25 70V59L40 52H60L75 59V70Z" fill={rank === "Q" ? red : ink} />
    <path d="M26 61L36 56L54 70H40ZM57 53L65 56L57 70H47Z" fill={gold} />
    <path d="M28 63L39 70M32 60L47 70M60 55L52 70M64 57L59 70" fill="none" stroke="#fff8e9" strokeWidth="1.1" />
    <path d="M40 51L50 60L61 51L58 48H43Z" fill="#fff8e9" />
    <path d="M43 50V44H56V51L50 56Z" fill={skin} />
    <path d="M38 35Q35 45 39 53L45 54L43 38H59L57 53L64 50L63 34Z" fill={rank === "Q" ? gold : ink} />
    <path d="M43 34Q50 29 58 35L57 45Q55 50 50 50Q45 49 43 44Z" fill={skin} />
    <path d="M44 38L48 38M53 38L56 38M51 39L49 44H52M48 47H53" fill="none" />
    <path d="M46 39V40M54 39V40" strokeWidth="1.4" />
    {rank === "K" ? <>
      <path d="M39 33L37 25L44 29L49 23L54 29L62 25L60 33Z" fill={gold} />
      <path d="M40 34H60V36H40Z" fill={red} />
      <circle cx="49.5" cy="29.5" r="1.5" fill={red} />
      <path d="M44 46Q47 43 50 46Q54 43 57 46L54 47L50 46L47 47Z" fill={ink} />
      <path d="M45 49L50 56L56 49L52 51H49Z" fill={ink} />
      <path d="M29 62V33L32 28L35 33V62Z" fill="#fff8e9" />
      <path d="M32 33V59M26 60H38" fill="none" stroke={gold} strokeWidth="1.8" />
      <path d="M29 63H35V69H29Z" fill={gold} />
    </> : rank === "Q" ? <>
      <path d="M39 33L40 26L46 29L50 24L55 29L61 26L61 33Z" fill={gold} />
      <path d="M40 34H60" stroke={red} strokeWidth="2" />
      <circle cx="41" cy="44" r="1.4" fill={gold} /><circle cx="60" cy="44" r="1.4" fill={gold} />
      <path d="M67 67L70 43M69 57Q62 54 65 50Q71 51 69 57M69 52Q75 50 74 46" fill="none" stroke="#32664e" strokeWidth="1.4" />
      {[0, 60, 120, 180, 240, 300].map(angle => <ellipse key={angle} cx="70" cy="36" rx="2.2" ry="3.6" fill={red} transform={`rotate(${angle} 70 40)`} />)}
      <circle cx="70" cy="40" r="2.3" fill={gold} />
      <path d="M46 53Q50 61 56 53" fill="none" stroke={gold} strokeWidth="1.7" />
    </> : <>
      <path d="M38 34Q37 23 50 25L61 30L59 35Z" fill={red} />
      <path d="M38 34H61V37H38Z" fill={gold} />
      <path d="M56 29Q60 17 67 24Q63 24 60 33" fill="#fff8e9" />
      <path d="M30 68V31M30 34L35 28L38 39H31" fill={gold} strokeWidth="1.3" />
      <path d="M43 48L46 51M58 46L55 51" fill="none" />
    </>}
    <path d="M64 62Q59 57 58 60L61 64L57 66L61 70H68Z" fill={skin} />
    <path d="M39 62L44 66L39 70L34 66Z" fill={red} stroke={gold} />
    <g stroke="none"><Suit suit={suit} x={50} y={65} size={7} /></g>
    <path d="M25 70H75" stroke={gold} strokeWidth="1.6" />
  </g>;
}

export function SaskuCardFace({ id }: { readonly id: SaskuCardId }) {
  const { rank, suit } = parseSaskuCard(id);
  const court = rank === "J" || rank === "Q" || rank === "K";
  return <svg aria-hidden="true" focusable="false" className="practice-face playing-card-face" viewBox="0 0 100 140" xmlns="http://www.w3.org/2000/svg" style={{ color: suit === "hearts" || suit === "diamonds" ? "#b51f32" : "#17202b" }}>
    <rect x=".5" y=".5" width="99" height="139" rx="6" fill="#fffdf8" stroke="#c9c5bb" />
    {[false, true].map(inverted => <g key={String(inverted)} transform={inverted ? "translate(100 140) rotate(180)" : undefined}>
      <text x="11" y="20" textAnchor="middle" fill="currentColor" fontFamily="Georgia, 'Times New Roman', serif" fontSize={rank === "10" ? "16" : "19"} fontWeight="bold" letterSpacing="-1">{rank}</text>
      <Suit suit={suit} x={11} y={30} size={12} />
    </g>)}
    {court ? <>
      <rect x="23" y="23" width="54" height="94" fill="#f8edce" stroke="#b5944d" strokeWidth="1" />
      <CourtHalf rank={rank} suit={suit} />
      <g transform="translate(100 140) rotate(180)"><CourtHalf rank={rank} suit={suit} /></g>
    </> : rank === "A" ? <Suit suit={suit} x={50} y={70} size={42} />
      : PIPS[rank]!.map(([x, y], index) => <Suit key={index} suit={suit} x={x} y={y} size={17} inverted={y > 70} />)}
  </svg>;
}

export function saskuCardName(id: SaskuCardId): string {
  const card = parseSaskuCard(id);
  return `${RANK_NAMES[card.rank]} of ${card.suit}`;
}
