import {
  addRistrettoScalars,
  bytesToHex,
  RISTRETTO_SCALAR_ONE,
  RISTRETTO_SCALAR_ORDER,
  RistrettoPoint,
  scalarFromBigInt,
  type RandomSource,
} from "@p2pcards/crypto";
import {
  createGameKeyShare,
  type GameKeyShare,
} from "@p2pcards/deck";
import {
  beaconCommitment,
  parseGameId,
  parseHash256,
  parseRandomSecret,
  type ProofContext,
} from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";

import { SetupCoordinator } from "./setup-coordinator";

const GAME_ID = parseGameId(new Uint8Array(16).fill(7));
const ROUND = 0;
const KEY_CONTEXT: ProofContext = Object.freeze({
  gameId: GAME_ID,
  round: ROUND,
  phase: "setup.keys",
});
const KEY_SHARES = [1n, 2n, 3n].map((secret, seat) => keyShare(secret, seat + 11));
const SECRETS = [3, 4, 5].map((value) => parseRandomSecret(new Uint8Array(32).fill(value)));
const COMMITMENTS = SECRETS.map((secret, seat) =>
  parseHash256(beaconCommitment(GAME_ID, ROUND, seat, secret)),
);

describe("setup coordinator", () => {
  it("derives immutable progress from accepted keys and the current beacon phase", () => {
    const setup = new SetupCoordinator(GAME_ID, ROUND, 3);
    const initial = setup.pendingSenders;
    expect(initial).toEqual([0, 1, 2]);
    expect(Object.isFrozen(initial)).toBe(true);
    expect(Reflect.set(initial, "length", 0)).toBe(false);
    expect(setup.commitmentAt(0)).toBeNull();
    setup.acceptCommitment(0, COMMITMENTS[0]!);
    setup.acceptKeyShare(2, KEY_SHARES[2]!);
    expect(setup.pendingSenders).toEqual([0, 1]);
    expect(initial).toEqual([0, 1, 2]);
    setup.acceptKeyShare(0, KEY_SHARES[0]!);
    setup.classifyKeyShare(1, KEY_SHARES[1]!);
    expect(setup.pendingSenders).toEqual([1]);
    setup.acceptKeyShare(1, KEY_SHARES[1]!);
    expect(setup.pendingSenders).toEqual([0, 1, 2]);
    expect(setup.acceptKeyShare(0, KEY_SHARES[0]!)).toMatchObject({ status: "duplicate", state: "rand_commit" });

    const commitment = parseHash256(COMMITMENTS[2]);
    setup.acceptCommitment(2, commitment);
    commitment.fill(0xff);
    const exposed = setup.commitmentAt(2)!;
    expect(exposed).toEqual(COMMITMENTS[2]);
    expect(exposed.buffer).not.toBe(setup.commitmentAt(2)!.buffer);
    exposed.fill(0);
    expect(setup.commitmentAt(2)).toEqual(COMMITMENTS[2]);
    setup.classifyCommitment(0, COMMITMENTS[0]!);
    expect(setup.pendingSenders).toEqual([0, 1]);
    expect(setup.commitmentAt(0)).toBeNull();
    setup.acceptCommitment(0, COMMITMENTS[0]!);
    setup.acceptCommitment(1, COMMITMENTS[1]!);
    expect(setup.pendingSenders).toEqual([0, 1, 2]);
    expect(setup.acceptCommitment(2, COMMITMENTS[2]!)).toMatchObject({ status: "duplicate", state: "rand_reveal" });
    setup.acceptReveal(0, SECRETS[1]!);
    expect(setup.pendingSenders).toEqual([0, 1, 2]);

    setup.acceptReveal(1, SECRETS[1]!);
    expect(setup.pendingSenders).toEqual([0, 2]);
    expect(Object.isFrozen(setup.pendingSenders)).toBe(true);
    setup.acceptReveal(0, SECRETS[0]!);
    setup.classifyReveal(2, SECRETS[2]!);
    expect(setup.pendingSenders).toEqual([2]);
    setup.acceptReveal(2, SECRETS[2]!);
    expect(setup.acceptKeyShare(0, KEY_SHARES[0]!)).toMatchObject({ status: "duplicate", state: "complete" });
    expect(setup.acceptCommitment(2, COMMITMENTS[2]!)).toMatchObject({ status: "duplicate", state: "complete" });
    expect(setup.acceptReveal(2, SECRETS[2]!)).toMatchObject({ status: "duplicate", state: "complete" });
    expect(setup.pendingSenders).toEqual([]);
    expect(Object.isFrozen(setup.pendingSenders)).toBe(true);
    expect(setup.commitmentAt(2)).toEqual(COMMITMENTS[2]);
  });

  it("classifies setup phase transitions without consuming contributions", () => {
    const setup = new SetupCoordinator(GAME_ID, ROUND, 3);
    setup.acceptKeyShare(0, KEY_SHARES[0]!);
    setup.acceptKeyShare(1, KEY_SHARES[1]!);

    expect(setup.classifyKeyShare(2, KEY_SHARES[2]!)).toMatchObject({
      status: "accepted",
      state: "rand_commit",
    });
    expect(setup.state).toBe("keys");
    expect(setup.publicKeyAt(2)).toBeNull();
    expect(setup.aggregateKey).toBeNull();
    setup.acceptKeyShare(2, KEY_SHARES[2]!);
    setup.acceptCommitment(0, COMMITMENTS[0]!);
    setup.acceptCommitment(1, COMMITMENTS[1]!);

    expect(setup.classifyCommitment(2, COMMITMENTS[2]!)).toMatchObject({
      status: "accepted",
      state: "rand_reveal",
    });
    expect(setup.state).toBe("rand_commit");
  });

  it("collects valid keys and drives the full beacon in arrival-independent order", () => {
    const setup = new SetupCoordinator(GAME_ID, ROUND, 3);

    expect(setup.acceptKeyShare(2, KEY_SHARES[2]!)).toMatchObject({
      status: "accepted",
      state: "keys",
    });
    expect(setup.acceptKeyShare(0, KEY_SHARES[0]!)).toMatchObject({
      status: "accepted",
      state: "keys",
    });
    expect(setup.acceptKeyShare(1, KEY_SHARES[1]!)).toMatchObject({
      status: "accepted",
      state: "rand_commit",
    });
    expect(setup.aggregateKey!.equals(RistrettoPoint.base().multiply(scalarFromBigInt(6n)))).toBe(
      true,
    );
    expect(setup.publicKeyAt(1)!.equals(KEY_SHARES[1]!.H)).toBe(true);

    setup.acceptCommitment(1, COMMITMENTS[1]!);
    setup.acceptCommitment(2, COMMITMENTS[2]!);
    expect(setup.acceptCommitment(0, COMMITMENTS[0]!)).toMatchObject({
      status: "accepted",
      state: "rand_reveal",
    });

    setup.acceptReveal(2, SECRETS[2]!);
    setup.acceptReveal(0, SECRETS[0]!);
    expect(setup.acceptReveal(1, SECRETS[1]!)).toMatchObject({
      status: "accepted",
      state: "complete",
    });
    expect(bytesToHex(setup.seed!)).toBe(
      "6009f5811453c05262122ffbe94a7cda19c1f05e61753f378d183b1525e370ae",
    );
  });

  it("rejects beacon traffic until key setup completes", () => {
    const setup = new SetupCoordinator(GAME_ID, ROUND, 3);

    expect(setup.acceptCommitment(0, COMMITMENTS[0]!)).toMatchObject({
      status: "rejected",
      reason: "unexpected_commit",
    });
    expect(setup.acceptReveal(0, SECRETS[0]!)).toMatchObject({
      status: "rejected",
      reason: "unexpected_reveal",
    });
  });

  it("rejects invalid proofs without consuming the seat", () => {
    const setup = new SetupCoordinator(GAME_ID, ROUND, 3);
    const valid = KEY_SHARES[0]!;
    const invalid: GameKeyShare = {
      H: valid.H,
      pop: {
        R: valid.pop.R,
        z: addRistrettoScalars(valid.pop.z, RISTRETTO_SCALAR_ONE),
      },
    };

    expect(setup.acceptKeyShare(0, invalid)).toMatchObject({
      status: "rejected",
      reason: "invalid_key_proof",
      state: "keys",
    });
    expect(setup.publicKeyAt(0)).toBeNull();
    expect(setup.pendingSenders).toEqual([0, 1, 2]);
    expect(setup.acceptKeyShare(0, valid)).toMatchObject({ status: "accepted" });
  });

  it("distinguishes duplicate and conflicting key shares", () => {
    const setup = new SetupCoordinator(GAME_ID, ROUND, 3);
    setup.acceptKeyShare(0, KEY_SHARES[0]!);

    expect(setup.acceptKeyShare(0, KEY_SHARES[0]!)).toMatchObject({ status: "duplicate" });
    expect(setup.acceptKeyShare(0, KEY_SHARES[1]!)).toMatchObject({
      status: "rejected",
      reason: "conflicting_key_share",
    });
  });

  it("does not retain a mutable key-share wrapper", () => {
    const setup = new SetupCoordinator(GAME_ID, ROUND, 3);
    const original = KEY_SHARES[0]!;
    const mutable = {
      H: original.H,
      pop: { R: original.pop.R, z: original.pop.z },
    };
    setup.acceptKeyShare(0, mutable);

    mutable.H = KEY_SHARES[1]!.H;
    mutable.pop.z = KEY_SHARES[1]!.pop.z;
    expect(setup.publicKeyAt(0)!.equals(original.H)).toBe(true);
    expect(setup.acceptKeyShare(0, original)).toMatchObject({ status: "duplicate" });
  });

  it("terminates without arrival-order blame when valid keys aggregate to identity", () => {
    const setup = new SetupCoordinator(GAME_ID, ROUND, 3);
    const cancellingShares = [
      keyShare(1n, 21),
      keyShare(2n, 22),
      keyShare(RISTRETTO_SCALAR_ORDER - 3n, 23),
    ];

    setup.acceptKeyShare(2, cancellingShares[2]!);
    setup.acceptKeyShare(0, cancellingShares[0]!);
    expect(setup.classifyKeyShare(1, cancellingShares[1]!)).toMatchObject({ status: "failed" });
    expect(setup.pendingSenders).toEqual([1]);
    expect(setup.acceptKeyShare(1, cancellingShares[1]!)).toEqual({
      status: "failed",
      state: "failed",
      reason: "aggregate_key_is_identity",
    });
    expect(setup.aggregateKey).toBeNull();
    expect(setup.pendingSenders).toEqual([]);
    expect(Object.isFrozen(setup.pendingSenders)).toBe(true);
    expect(setup.commitmentAt(0)).toBeNull();
    expect(setup.acceptKeyShare(1, cancellingShares[1]!)).toMatchObject({ status: "duplicate", state: "failed" });
    expect(setup.acceptCommitment(0, COMMITMENTS[0]!)).toMatchObject({
      status: "rejected",
      reason: "setup_failed",
    });
    expect(setup.pendingSenders).toEqual([]);
  });

  it("propagates deterministic beacon rejection and duplicate outcomes", () => {
    const setup = keyedSetup();
    setup.acceptCommitment(0, COMMITMENTS[0]!);
    expect(setup.acceptCommitment(0, COMMITMENTS[0]!)).toMatchObject({ status: "duplicate" });
    expect(setup.acceptCommitment(0, COMMITMENTS[1]!)).toMatchObject({
      status: "rejected",
      reason: "conflicting_commitment",
    });
    expect(setup.acceptReveal(0, SECRETS[0]!)).toMatchObject({
      status: "rejected",
      reason: "unexpected_reveal",
    });

    setup.acceptCommitment(1, COMMITMENTS[1]!);
    setup.acceptCommitment(2, COMMITMENTS[2]!);
    expect(setup.acceptReveal(0, SECRETS[1]!)).toMatchObject({
      status: "rejected",
      reason: "commitment_mismatch",
    });
  });

  it("validates constructor and seat bounds", () => {
    expect(() => new SetupCoordinator(GAME_ID, -1, 3)).toThrow(RangeError);
    expect(() => new SetupCoordinator(GAME_ID, 0, 2)).toThrow(RangeError);
    expect(() => new SetupCoordinator(GAME_ID, 0, 9)).toThrow(RangeError);
    expect(() => new SetupCoordinator(GAME_ID, 0, 3).publicKeyAt(3)).toThrow(RangeError);
    for (const seat of [-1, 3, 0.5, NaN, Infinity]) {
      expect(() => new SetupCoordinator(GAME_ID, ROUND, 3).commitmentAt(seat)).toThrow(RangeError);
    }
  });
});

function keyedSetup(): SetupCoordinator {
  const setup = new SetupCoordinator(GAME_ID, ROUND, 3);
  KEY_SHARES.forEach((share, seat) => setup.acceptKeyShare(seat, share));
  return setup;
}

function keyShare(secret: bigint, nonce: number): GameKeyShare {
  return createGameKeyShare(KEY_CONTEXT, scalarFromBigInt(secret), scalarSource(nonce));
}

function scalarSource(value: number): RandomSource {
  return {
    fill(target) {
      target.fill(0);
      target[0] = value;
    },
  };
}
