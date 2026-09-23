import {
  bytesEqual,
  bytesToHex,
  importEd25519PublicKey,
  type RistrettoPoint,
} from "@p2pcards/crypto";
import { decodeGameKeyShareBody } from "@p2pcards/deck";
import {
  decodeAndVerifyEnvelope,
  decodeRandCommitBody,
  decodeRandRevealBody,
  parseGameId,
  parseIdentityPublicKey,
  type EnvelopeArtifact,
  type GameId,
  type Hash256,
  type IdentityPublicKey,
} from "@p2pcards/protocol";

import {
  SetupCoordinator,
  type SetupIngestResult,
  type SetupRejectionReason,
  type SetupState,
} from "./setup-coordinator";

export type SetupEnvelopeRejectionReason =
  | SetupRejectionReason
  | "malformed_body"
  | "unknown_sender"
  | "wrong_game"
  | "wrong_phase"
  | "wrong_round"
  | "wrong_type";

export type SetupEnvelopeResult =
  | {
      readonly status: "accepted" | "duplicate";
      readonly seat: number;
      readonly state: SetupState;
      readonly received: EnvelopeArtifact;
      readonly setupResult: Extract<
        SetupIngestResult,
        { readonly status: "accepted" | "duplicate" }
      >;
    }
  | {
      readonly status: "rejected";
      readonly reason: SetupEnvelopeRejectionReason;
      readonly state: SetupState;
      readonly received: EnvelopeArtifact;
      readonly seat?: number;
    }
  | {
      readonly status: "failed";
      readonly reason: "aggregate_key_is_identity";
      readonly state: "failed";
      readonly seat: number;
      readonly received: EnvelopeArtifact;
      readonly setupResult: Extract<SetupIngestResult, { readonly status: "failed" }>;
    };

export class SetupEnvelopeCoordinator {
  readonly #gameId: GameId;
  readonly #round: number;
  readonly #roster: readonly IdentityPublicKey[];
  readonly #seats: ReadonlyMap<string, number>;
  readonly #setup: SetupCoordinator;

  constructor(gameId: GameId, round: number, roster: readonly IdentityPublicKey[]) {
    this.#gameId = parseGameId(gameId);
    if (!Number.isSafeInteger(round) || round < 0) {
      throw new RangeError("Setup envelope round must be an unsigned safe integer");
    }
    if (!Array.isArray(roster) || roster.length < 3 || roster.length > 8) {
      throw new RangeError("Setup envelope roster must contain 3 to 8 seats");
    }
    this.#round = round;

    const seats = new Map<string, number>();
    this.#roster = Object.freeze(
      roster.map((candidate, seat) => {
        const identity = parseIdentityPublicKey(candidate);
        try {
          importEd25519PublicKey(identity);
        } catch (cause) {
          throw new TypeError(`Setup roster seat ${seat} has an invalid identity`, { cause });
        }
        const key = bytesToHex(identity);
        if (seats.has(key)) {
          throw new TypeError(`Setup roster contains duplicate identity at seat ${seat}`);
        }
        seats.set(key, seat);
        return identity;
      }),
    );
    this.#seats = seats;
    this.#setup = new SetupCoordinator(this.#gameId, round, roster.length);
  }

  get gameId(): GameId {
    return parseGameId(this.#gameId);
  }

  get round(): number {
    return this.#round;
  }

  get roster(): readonly IdentityPublicKey[] {
    return Object.freeze(this.#roster.map(parseIdentityPublicKey));
  }

  get state(): SetupState {
    return this.#setup.state;
  }

  get pendingSenders(): readonly number[] {
    return this.#setup.pendingSenders;
  }

  get aggregateKey(): RistrettoPoint | null {
    return this.#setup.aggregateKey;
  }

  get seed(): Hash256 | null {
    return this.#setup.seed;
  }

  publicKeyAt(seat: number): RistrettoPoint | null {
    return this.#setup.publicKeyAt(seat);
  }

  commitmentAt(seat: number): Hash256 | null {
    return this.#setup.commitmentAt(seat);
  }

  classify(received: EnvelopeArtifact): SetupEnvelopeResult {
    return this.#process(received, false);
  }

  ingest(received: EnvelopeArtifact): SetupEnvelopeResult {
    return this.#process(received, true);
  }

  #process(candidate: EnvelopeArtifact, commit: boolean): SetupEnvelopeResult {
    const received = decodeAndVerifyEnvelope(candidate.canonicalBytes);
    const envelope = received.envelope;
    if (!bytesEqual(envelope.game, this.#gameId)) {
      return reject("wrong_game", this.#setup.state, received);
    }
    const seat = this.#seats.get(bytesToHex(envelope.from));
    if (seat === undefined) {
      return reject("unknown_sender", this.#setup.state, received);
    }
    if (envelope.round !== this.#round) {
      return reject("wrong_round", this.#setup.state, received, seat);
    }

    let setupResult: SetupIngestResult;
    if (envelope.type === "KEY_SHARE") {
      if (envelope.phase !== "setup.keys") {
        return reject("wrong_phase", this.#setup.state, received, seat);
      }
      let body: ReturnType<typeof decodeGameKeyShareBody>;
      try {
        body = decodeGameKeyShareBody(envelope.body);
      } catch {
        return reject("malformed_body", this.#setup.state, received, seat);
      }
      setupResult = commit
        ? this.#setup.acceptKeyShare(seat, body)
        : this.#setup.classifyKeyShare(seat, body);
    } else if (envelope.type === "RAND_COMMIT") {
      if (envelope.phase !== "setup.rand") {
        return reject("wrong_phase", this.#setup.state, received, seat);
      }
      let body: ReturnType<typeof decodeRandCommitBody>;
      try {
        body = decodeRandCommitBody(envelope.body);
      } catch {
        return reject("malformed_body", this.#setup.state, received, seat);
      }
      setupResult = commit
        ? this.#setup.acceptCommitment(seat, body.cm)
        : this.#setup.classifyCommitment(seat, body.cm);
    } else if (envelope.type === "RAND_REVEAL") {
      if (envelope.phase !== "setup.rand") {
        return reject("wrong_phase", this.#setup.state, received, seat);
      }
      let body: ReturnType<typeof decodeRandRevealBody>;
      try {
        body = decodeRandRevealBody(envelope.body);
      } catch {
        return reject("malformed_body", this.#setup.state, received, seat);
      }
      setupResult = commit
        ? this.#setup.acceptReveal(seat, body.s)
        : this.#setup.classifyReveal(seat, body.s);
    } else {
      return reject("wrong_type", this.#setup.state, received, seat);
    }

    return mapSetupResult(setupResult, received, seat);
  }
}

function mapSetupResult(
  setupResult: SetupIngestResult,
  received: EnvelopeArtifact,
  seat: number,
): SetupEnvelopeResult {
  if (setupResult.status === "failed") {
    return Object.freeze({
      status: "failed",
      reason: setupResult.reason,
      state: setupResult.state,
      seat,
      received,
      setupResult,
    });
  }
  if (setupResult.status === "rejected") {
    return reject(setupResult.reason, setupResult.state, received, seat);
  }
  return Object.freeze({
    status: setupResult.status,
    seat,
    state: setupResult.state,
    received,
    setupResult,
  });
}

function reject(
  reason: SetupEnvelopeRejectionReason,
  state: SetupState,
  received: EnvelopeArtifact,
  seat?: number,
): SetupEnvelopeResult {
  return seat === undefined
    ? Object.freeze({ status: "rejected", reason, state, received })
    : Object.freeze({ status: "rejected", reason, state, received, seat });
}
