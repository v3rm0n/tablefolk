import { bytesEqual, sha256 } from "@p2pcards/crypto";
import { encodeCanonical } from "@p2pcards/encoding";
import type { SaskuHandScore } from "@p2pcards/rules-sasku";
import { MAX_SASKU_MATCH_ROUNDS } from "./sasku-match";

const KIND = 2;
const BYTES = 34;

/** Ephemeral marker sent only on an authenticated, generation-bound peer channel. */
export function roundCompletionMarker(round: number, score: SaskuHandScore): Uint8Array {
  if (!Number.isSafeInteger(round) || round < 1 || round > MAX_SASKU_MATCH_ROUNDS) throw new Error("Invalid completed round");
  const digest = sha256(encodeCanonical({ profile: "sasku-round-complete/1", round,
    score: { kind: score.kind, winner: score.winner, gamePoints: [...score.gamePoints],
      basePoints: score.basePoints, bonusPoints: score.bonusPoints } }));
  const bytes = new Uint8Array(BYTES);
  bytes[0] = KIND; bytes[1] = round; bytes.set(digest, 2);
  return bytes;
}

export function parseRoundCompletionMarker(payload: Uint8Array): Uint8Array {
  if (!(payload instanceof Uint8Array) || payload.constructor !== Uint8Array || payload.length !== BYTES ||
      payload[0] !== KIND || payload[1]! < 1 || payload[1]! > MAX_SASKU_MATCH_ROUNDS) {
    throw new Error("Invalid Sasku round completion marker");
  }
  return payload.slice();
}

export function sameRoundCompletion(a: Uint8Array, b: Uint8Array): boolean {
  return bytesEqual(parseRoundCompletionMarker(a), parseRoundCompletionMarker(b));
}
