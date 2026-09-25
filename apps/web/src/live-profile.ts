import { sha256 } from "@p2pcards/crypto";
import { encodeCanonical } from "@p2pcards/encoding";
import { parseHash256 } from "@p2pcards/protocol";
import cards from "../../../packages/rules-sasku/src/cards.ts?raw";
import hand from "../../../packages/rules-sasku/src/hand.ts?raw";
import scoring from "../../../packages/rules-sasku/src/scoring.ts?raw";
import match from "./sasku-match.ts?raw";

// The roster signatures bind this match policy and rules implementation.
export const FIRST_ROUND = 1;
export const FIRST_DEALER = 3;
export const FIRST_DEAL = Object.freeze([0, 1, 2, 3].map(to => Object.freeze({ to, count: 9 })));
export function liveRulesHash() {
  return parseHash256(sha256(encodeCanonical({ id: "sasku-match-candidate/2", cards, hand, scoring, match,
    setupRound: 0, round: FIRST_ROUND, dealer: FIRST_DEALER, deal: FIRST_DEAL,
    beacon: "all-four-commit-then-reveal; seed-recorded; seat-order-fixed",
    shuffle: "candidate-ristretto-4x9-parity-ac4fb67-sha512-cbor-v1",
    readiness: "authenticated-own-prefix-watermark-ack-v1; per-round-audit-result-marker-v1", matchTarget: 12, maxRounds: 32 })));
}
