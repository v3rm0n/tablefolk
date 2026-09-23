import {
  bytesEqual,
  randomBytes,
  sha256,
  type RandomSource,
} from "@p2pcards/crypto";
import {
  beaconCommitment,
  parseGameId,
  parseHash256,
  parseRandomSecret,
  type GameId,
  type Hash256,
  type RandomSecret,
} from "@p2pcards/protocol";

export type BeaconState = "committing" | "revealing" | "complete";

export interface BeaconContribution {
  readonly secret: RandomSecret;
  readonly commitment: Hash256;
}

export type BeaconIngestResult =
  | {
      readonly status: "accepted";
      readonly seat: number;
      readonly state: BeaconState;
    }
  | {
      readonly status: "duplicate";
      readonly seat: number;
      readonly state: BeaconState;
    }
  | {
      readonly status: "rejected";
      readonly seat: number;
      readonly state: BeaconState;
      readonly reason:
        | "commitment_mismatch"
        | "conflicting_commitment"
        | "conflicting_reveal"
        | "unexpected_commit"
        | "unexpected_reveal";
    };

export function createBeaconContribution(
  gameId: GameId,
  round: number,
  seat: number,
  source?: RandomSource,
): BeaconContribution {
  const secret = parseRandomSecret(randomBytes(32, source));
  return Object.freeze({
    secret,
    commitment: parseHash256(beaconCommitment(gameId, round, seat, secret)),
  });
}

export class RandomnessBeacon {
  readonly #gameId: GameId;
  readonly #round: number;
  readonly #seatCount: number;
  readonly #commitments: Array<Hash256 | null>;
  readonly #reveals: Array<RandomSecret | null>;
  #state: BeaconState = "committing";
  #seed: Hash256 | null = null;

  constructor(gameId: GameId, round: number, seatCount: number) {
    if (!Number.isSafeInteger(round) || round < 0) {
      throw new RangeError("Beacon round must be an unsigned safe integer");
    }
    if (!Number.isInteger(seatCount) || seatCount < 3 || seatCount > 8) {
      throw new RangeError("Beacon seat count must be an integer from 3 through 8");
    }

    this.#gameId = parseGameId(gameId);
    this.#round = round;
    this.#seatCount = seatCount;
    this.#commitments = Array.from({ length: seatCount }, () => null);
    this.#reveals = Array.from({ length: seatCount }, () => null);
  }

  get state(): BeaconState {
    return this.#state;
  }

  get pendingSenders(): readonly number[] {
    const values = this.#state === "committing" ? this.#commitments : this.#reveals;
    return Object.freeze(values.flatMap((value, seat) => value === null ? [seat] : []));
  }

  get seed(): Hash256 | null {
    return this.#seed === null ? null : parseHash256(this.#seed);
  }

  commitmentAt(seat: number): Hash256 | null {
    this.#assertSeat(seat);
    const commitment = this.#commitments[seat]!;
    return commitment === null ? null : parseHash256(commitment);
  }

  classifyCommitment(seat: number, candidate: Hash256): BeaconIngestResult {
    this.#assertSeat(seat);
    const commitment = parseHash256(candidate);
    const existing = this.#commitments[seat]!;

    if (existing !== null) {
      return result(
        bytesEqual(existing, commitment) ? "duplicate" : "rejected",
        seat,
        this.#state,
        "conflicting_commitment",
      );
    }
    if (this.#state !== "committing") {
      return result("rejected", seat, this.#state, "unexpected_commit");
    }

    const remaining = this.#commitments.filter((value) => value === null).length;
    return result("accepted", seat, remaining === 1 ? "revealing" : this.#state);
  }

  acceptCommitment(seat: number, candidate: Hash256): BeaconIngestResult {
    const classification = this.classifyCommitment(seat, candidate);
    if (classification.status !== "accepted") {
      return classification;
    }
    this.#commitments[seat] = parseHash256(candidate);
    this.#state = classification.state;
    return classification;
  }

  classifyReveal(seat: number, candidate: RandomSecret): BeaconIngestResult {
    this.#assertSeat(seat);
    const secret = parseRandomSecret(candidate);
    const existing = this.#reveals[seat]!;

    if (existing !== null) {
      return result(
        bytesEqual(existing, secret) ? "duplicate" : "rejected",
        seat,
        this.#state,
        "conflicting_reveal",
      );
    }
    if (this.#state !== "revealing") {
      return result("rejected", seat, this.#state, "unexpected_reveal");
    }

    const commitment = this.#commitments[seat]!;
    const expected = beaconCommitment(this.#gameId, this.#round, seat, secret);
    if (!bytesEqual(commitment, expected)) {
      return result("rejected", seat, this.#state, "commitment_mismatch");
    }

    const remaining = this.#reveals.filter((value) => value === null).length;
    return result("accepted", seat, remaining === 1 ? "complete" : this.#state);
  }

  acceptReveal(seat: number, candidate: RandomSecret): BeaconIngestResult {
    const classification = this.classifyReveal(seat, candidate);
    if (classification.status !== "accepted") {
      return classification;
    }
    this.#reveals[seat] = parseRandomSecret(candidate);
    this.#state = classification.state;
    if (this.#state === "complete") {
      this.#seed = parseHash256(sha256(...(this.#reveals as RandomSecret[])));
    }
    return classification;
  }

  #assertSeat(seat: number): void {
    if (!Number.isInteger(seat) || seat < 0 || seat >= this.#seatCount) {
      throw new RangeError(`Beacon seat must be an integer from 0 through ${this.#seatCount - 1}`);
    }
  }
}

function result(
  status: BeaconIngestResult["status"],
  seat: number,
  state: BeaconState,
  reason?: Extract<BeaconIngestResult, { status: "rejected" }>["reason"],
): BeaconIngestResult {
  if (status === "rejected") {
    if (reason === undefined) {
      throw new Error("A rejected beacon result requires a reason");
    }
    return Object.freeze({ status, seat, state, reason });
  }
  return Object.freeze({ status, seat, state });
}
