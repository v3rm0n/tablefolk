import { bytesEqual, type RistrettoPoint } from "@p2pcards/crypto";
import {
  aggregatePublicKeys,
  verifyGameKeyShare,
  type GameKeyShare,
} from "@p2pcards/deck";
import {
  parseGameId,
  type GameId,
  type Hash256,
  type ProofContext,
  type RandomSecret,
} from "@p2pcards/protocol";

import {
  RandomnessBeacon,
  type BeaconIngestResult,
} from "./randomness-beacon";

export type SetupState =
  | "keys"
  | "rand_commit"
  | "rand_reveal"
  | "complete"
  | "failed";

export type SetupRejectionReason =
  | "commitment_mismatch"
  | "conflicting_commitment"
  | "conflicting_key_share"
  | "conflicting_reveal"
  | "invalid_key_proof"
  | "setup_failed"
  | "unexpected_commit"
  | "unexpected_reveal";

export type SetupIngestResult =
  | {
      readonly status: "accepted" | "duplicate";
      readonly seat: number;
      readonly state: SetupState;
    }
  | {
      readonly status: "rejected";
      readonly seat: number;
      readonly state: SetupState;
      readonly reason: SetupRejectionReason;
    }
  | {
      readonly status: "failed";
      readonly state: "failed";
      readonly reason: "aggregate_key_is_identity";
    };

export class SetupCoordinator {
  readonly #gameId: GameId;
  readonly #round: number;
  readonly #seatCount: number;
  readonly #beaconRequired: boolean;
  readonly #proofContext: ProofContext;
  readonly #keyShares: Array<GameKeyShare | null>;
  #state: SetupState = "keys";
  #aggregateKey: RistrettoPoint | null = null;
  #beacon: RandomnessBeacon | null = null;

  constructor(gameId: GameId, round: number, seatCount: number, beaconRequired = true) {
    if (!Number.isSafeInteger(round) || round < 0) {
      throw new RangeError("Setup round must be an unsigned safe integer");
    }
    if (!Number.isInteger(seatCount) || seatCount < 3 || seatCount > 8) {
      throw new RangeError("Setup seat count must be an integer from 3 through 8");
    }
    if (typeof beaconRequired !== "boolean") throw new TypeError("Invalid setup beacon policy");

    this.#gameId = parseGameId(gameId);
    this.#round = round;
    this.#seatCount = seatCount;
    this.#beaconRequired = beaconRequired;
    this.#proofContext = Object.freeze({
      gameId: this.#gameId,
      round,
      phase: "setup.keys",
    });
    this.#keyShares = Array.from({ length: seatCount }, () => null);
  }

  get state(): SetupState {
    return this.#state;
  }

  get pendingSenders(): readonly number[] {
    if (this.#state === "keys") {
      return Object.freeze(this.#keyShares.flatMap((share, seat) => share === null ? [seat] : []));
    }
    if (this.#state === "rand_commit" || this.#state === "rand_reveal") {
      return this.#beacon!.pendingSenders;
    }
    return Object.freeze([]);
  }

  get aggregateKey(): RistrettoPoint | null {
    return this.#aggregateKey;
  }

  get seed(): Hash256 | null {
    return this.#beacon?.seed ?? null;
  }

  publicKeyAt(seat: number): RistrettoPoint | null {
    this.#assertSeat(seat);
    return this.#keyShares[seat]?.H ?? null;
  }

  commitmentAt(seat: number): Hash256 | null {
    this.#assertSeat(seat);
    return this.#beacon?.commitmentAt(seat) ?? null;
  }

  classifyKeyShare(seat: number, share: GameKeyShare): SetupIngestResult {
    this.#assertSeat(seat);
    const existing = this.#keyShares[seat]!;
    if (existing !== null) {
      return setupResult(
        equalKeyShares(existing, share) ? "duplicate" : "rejected",
        seat,
        this.#state,
        "conflicting_key_share",
      );
    }
    if (this.#state === "failed") {
      return setupResult("rejected", seat, this.#state, "setup_failed");
    }
    if (this.#state !== "keys" || !verifyGameKeyShare(this.#proofContext, share)) {
      return setupResult("rejected", seat, this.#state, "invalid_key_proof");
    }

    const prospective = this.#keyShares.map((value, index) =>
      index === seat ? share : value,
    );
    if (!prospective.every((value) => value !== null)) {
      return setupResult("accepted", seat, this.#state);
    }

    try {
      aggregatePublicKeys(prospective.map((value) => value!.H));
    } catch (cause) {
      if (!(cause instanceof TypeError)) {
        throw cause;
      }
      return Object.freeze({
        status: "failed",
        state: "failed",
        reason: "aggregate_key_is_identity",
      });
    }

    return setupResult("accepted", seat, this.#beaconRequired ? "rand_commit" : "complete");
  }

  acceptKeyShare(seat: number, share: GameKeyShare): SetupIngestResult {
    const classification = this.classifyKeyShare(seat, share);
    if (classification.status === "duplicate" || classification.status === "rejected") {
      return classification;
    }

    this.#keyShares[seat] = copyKeyShare(share);
    if (classification.status === "failed") {
      this.#state = "failed";
      return classification;
    }
    if (classification.state === "rand_commit" || classification.state === "complete") {
      this.#aggregateKey = aggregatePublicKeys(
        this.#keyShares.map((value) => value!.H),
      );
      if (this.#beaconRequired) this.#beacon = new RandomnessBeacon(this.#gameId, this.#round, this.#seatCount);
    }
    this.#state = classification.state;
    return classification;
  }

  classifyCommitment(seat: number, commitment: Hash256): SetupIngestResult {
    this.#assertSeat(seat);
    if (this.#state === "failed") {
      return setupResult("rejected", seat, this.#state, "setup_failed");
    }
    if (this.#beacon === null) {
      return setupResult("rejected", seat, this.#state, "unexpected_commit");
    }

    const beaconResult = this.#beacon.classifyCommitment(seat, commitment);
    return mapBeaconResult(beaconResult, setupStateForBeacon(beaconResult.state));
  }

  acceptCommitment(seat: number, commitment: Hash256): SetupIngestResult {
    const classification = this.classifyCommitment(seat, commitment);
    if (classification.status !== "accepted") {
      return classification;
    }
    if (this.#beacon === null) {
      throw new Error("Setup beacon disappeared between classification and ingestion");
    }
    const beaconResult = this.#beacon.acceptCommitment(seat, commitment);
    this.#syncBeaconState();
    return mapBeaconResult(beaconResult, this.#state);
  }

  classifyReveal(seat: number, secret: RandomSecret): SetupIngestResult {
    this.#assertSeat(seat);
    if (this.#state === "failed") {
      return setupResult("rejected", seat, this.#state, "setup_failed");
    }
    if (this.#beacon === null) {
      return setupResult("rejected", seat, this.#state, "unexpected_reveal");
    }

    const beaconResult = this.#beacon.classifyReveal(seat, secret);
    return mapBeaconResult(beaconResult, setupStateForBeacon(beaconResult.state));
  }

  acceptReveal(seat: number, secret: RandomSecret): SetupIngestResult {
    const classification = this.classifyReveal(seat, secret);
    if (classification.status !== "accepted") {
      return classification;
    }
    if (this.#beacon === null) {
      throw new Error("Setup beacon disappeared between classification and ingestion");
    }
    const beaconResult = this.#beacon.acceptReveal(seat, secret);
    this.#syncBeaconState();
    return mapBeaconResult(beaconResult, this.#state);
  }

  #syncBeaconState(): void {
    if (this.#beacon?.state === "revealing") {
      this.#state = "rand_reveal";
    } else if (this.#beacon?.state === "complete") {
      this.#state = "complete";
    }
  }

  #assertSeat(seat: number): void {
    if (!Number.isInteger(seat) || seat < 0 || seat >= this.#seatCount) {
      throw new RangeError(`Setup seat must be an integer from 0 through ${this.#seatCount - 1}`);
    }
  }
}

function equalKeyShares(left: GameKeyShare, right: GameKeyShare): boolean {
  try {
    return (
      left.H.equals(right.H) &&
      left.pop.R.equals(right.pop.R) &&
      left.pop.z === right.pop.z
    );
  } catch {
    return false;
  }
}

function copyKeyShare(share: GameKeyShare): GameKeyShare {
  return Object.freeze({
    H: share.H,
    pop: Object.freeze({ R: share.pop.R, z: share.pop.z }),
  });
}

function setupStateForBeacon(state: "committing" | "revealing" | "complete"): SetupState {
  if (state === "revealing") {
    return "rand_reveal";
  }
  if (state === "complete") {
    return "complete";
  }
  return "rand_commit";
}

function mapBeaconResult(result: BeaconIngestResult, state: SetupState): SetupIngestResult {
  if (result.status === "rejected") {
    return setupResult("rejected", result.seat, state, result.reason);
  }
  return setupResult(result.status, result.seat, state);
}

function setupResult(
  status: "accepted" | "duplicate" | "rejected",
  seat: number,
  state: SetupState,
  reason?: SetupRejectionReason,
): SetupIngestResult {
  if (status === "rejected") {
    if (reason === undefined) {
      throw new Error("A rejected setup result requires a reason");
    }
    return Object.freeze({ status, seat, state, reason });
  }
  return Object.freeze({ status, seat, state });
}
