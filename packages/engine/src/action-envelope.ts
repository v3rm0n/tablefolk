import { bytesEqual, bytesToHex, importEd25519PublicKey } from "@p2pcards/crypto";
import { decodeActionBody, type ActionBody } from "@p2pcards/deck";
import { decodeAndVerifyEnvelope, parseGameId, parseIdentityPublicKey, type EnvelopeArtifact, type GameId, type IdentityPublicKey } from "@p2pcards/protocol";

export const MAX_ACTION_ENVELOPE_BYTES = 64 * 1024;

export interface ActionEnvelopeScope {
  readonly gameId: GameId;
  readonly round: number;
  readonly actionIndex: number;
  readonly roster: readonly IdentityPublicKey[];
  readonly expectedSeats: readonly number[];
}

export interface DecodedActionEnvelope {
  readonly received: EnvelopeArtifact;
  readonly seat: number;
  readonly action: ActionBody;
}

export type ActionEnvelopeErrorCode =
  | "invalid_envelope" | "wrong_game" | "wrong_round" | "wrong_type" | "wrong_phase"
  | "unknown_sender" | "unexpected_sender" | "malformed_body";

export class ActionEnvelopeError extends Error {
  readonly code: ActionEnvelopeErrorCode;
  constructor(code: ActionEnvelopeErrorCode, options?: ErrorOptions) {
    super(`ACTION envelope rejected: ${code}`, options);
    this.name = "ActionEnvelopeError";
    this.code = code;
  }
}

/** Verifies signature, scope, and body encoding only. Chains, reveal proofs, ownership, and rules still require validation. */
export function decodeActionEnvelope(bytes: Uint8Array, scope: ActionEnvelopeScope): DecodedActionEnvelope {
  if (!(bytes instanceof Uint8Array) || bytes.constructor !== Uint8Array ||
      bytes.length === 0 || bytes.length > MAX_ACTION_ENVELOPE_BYTES) {
    throw new ActionEnvelopeError("invalid_envelope");
  }
  if (typeof scope !== "object" || scope === null || Array.isArray(scope)) {
    throw new TypeError("Action envelope scope is required");
  }
  const gameId = parseGameId(scope.gameId);
  const { round, actionIndex } = scope;
  for (const value of [round, actionIndex]) {
    if (!Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) {
      throw new RangeError("Action round and index must be unsigned safe integers");
    }
  }
  if (!Array.isArray(scope.roster) || scope.roster.length < 3 || scope.roster.length > 8) {
    throw new RangeError("Action roster must contain 3 to 8 identities");
  }
  const seats = new Map<string, number>();
  for (let seat = 0; seat < scope.roster.length; seat += 1) {
    const identity = parseIdentityPublicKey(scope.roster[seat]);
    importEd25519PublicKey(identity);
    const key = bytesToHex(identity);
    if (seats.has(key)) { throw new TypeError("Action roster contains a duplicate identity"); }
    seats.set(key, seat);
  }
  if (!Array.isArray(scope.expectedSeats) || scope.expectedSeats.length === 0 || scope.expectedSeats.length > seats.size) {
    throw new RangeError("Action expected seats must be a nonempty subset of the roster");
  }
  const expected = new Set<number>();
  for (const seat of scope.expectedSeats) {
    if (!Number.isSafeInteger(seat) || seat < 0 || seat >= seats.size || Object.is(seat, -0) || expected.has(seat)) {
      throw new RangeError("Action expected seats must be distinct roster indices");
    }
    expected.add(seat);
  }
  let received: EnvelopeArtifact;
  try { received = decodeAndVerifyEnvelope(bytes); }
  catch (cause) { throw new ActionEnvelopeError("invalid_envelope", { cause }); }
  const envelope = received.envelope;
  if (!bytesEqual(envelope.game, gameId)) { throw new ActionEnvelopeError("wrong_game"); }
  const seat = seats.get(bytesToHex(envelope.from));
  if (seat === undefined) { throw new ActionEnvelopeError("unknown_sender"); }
  if (envelope.round !== round) { throw new ActionEnvelopeError("wrong_round"); }
  if (envelope.type !== "ACTION") { throw new ActionEnvelopeError("wrong_type"); }
  if (envelope.phase !== `round.${round}.play.${actionIndex}`) { throw new ActionEnvelopeError("wrong_phase"); }
  if (!expected.has(seat)) { throw new ActionEnvelopeError("unexpected_sender"); }
  let action: ActionBody;
  try { action = decodeActionBody(envelope.body); }
  catch (cause) { throw new ActionEnvelopeError("malformed_body", { cause }); }
  return Object.freeze({ received, seat, action });
}
