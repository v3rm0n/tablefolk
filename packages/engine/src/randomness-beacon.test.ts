import { bytesToHex, type RandomSource } from "@p2pcards/crypto";
import {
  beaconCommitment,
  parseGameId,
  parseHash256,
  parseRandomSecret,
} from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";

import { createBeaconContribution, RandomnessBeacon } from "./randomness-beacon";

const GAME_ID = parseGameId(new Uint8Array(16).fill(4));
const ROUND = 1;
const SECRETS = [0, 1, 2].map((value) => parseRandomSecret(new Uint8Array(32).fill(value)));
const COMMITMENTS = SECRETS.map((secret, seat) =>
  parseHash256(beaconCommitment(GAME_ID, ROUND, seat, secret)),
);

describe("commit/reveal randomness beacon", () => {
  it("exposes frozen, seat-ordered current-phase progress and copied commitments only", () => {
    const beacon = new RandomnessBeacon(GAME_ID, ROUND, 3);
    const initial = beacon.pendingSenders;
    expect(initial).toEqual([0, 1, 2]);
    expect(Object.isFrozen(initial)).toBe(true);
    expect(Reflect.set(initial, "0", 7)).toBe(false);
    expect(beacon.commitmentAt(2)).toBeNull();

    const commitment = parseHash256(COMMITMENTS[2]);
    beacon.acceptCommitment(2, commitment);
    commitment.fill(0xff);
    expect(beacon.pendingSenders).toEqual([0, 1]);
    expect(initial).toEqual([0, 1, 2]);
    const exposed = beacon.commitmentAt(2)!;
    expect(exposed).toEqual(COMMITMENTS[2]);
    expect(exposed.buffer).not.toBe(beacon.commitmentAt(2)!.buffer);
    exposed.fill(0);
    expect(beacon.commitmentAt(2)).toEqual(COMMITMENTS[2]);

    beacon.acceptCommitment(0, COMMITMENTS[0]!);
    beacon.classifyCommitment(1, COMMITMENTS[1]!);
    expect(beacon.pendingSenders).toEqual([1]);
    expect(beacon.commitmentAt(1)).toBeNull();
    beacon.acceptCommitment(1, COMMITMENTS[1]!);
    expect(beacon.pendingSenders).toEqual([0, 1, 2]);
    expect(beacon.acceptCommitment(1, COMMITMENTS[1]!)).toMatchObject({ status: "duplicate", state: "revealing" });
    expect(beacon.acceptReveal(1, SECRETS[0]!)).toMatchObject({ status: "rejected" });
    expect(beacon.pendingSenders).toEqual([0, 1, 2]);

    beacon.acceptReveal(1, SECRETS[1]!);
    expect(beacon.pendingSenders).toEqual([0, 2]);
    expect(Object.isFrozen(beacon.pendingSenders)).toBe(true);
    beacon.acceptReveal(0, SECRETS[0]!);
    beacon.classifyReveal(2, SECRETS[2]!);
    expect(beacon.pendingSenders).toEqual([2]);
    beacon.acceptReveal(2, SECRETS[2]!);
    expect(beacon.pendingSenders).toEqual([]);
    expect(Object.isFrozen(beacon.pendingSenders)).toBe(true);
    expect(beacon.acceptReveal(2, SECRETS[2]!)).toMatchObject({ status: "duplicate", state: "complete" });
    expect(beacon.acceptCommitment(2, COMMITMENTS[2]!)).toMatchObject({ status: "duplicate", state: "complete" });
    expect(beacon.pendingSenders).toEqual([]);
    expect(beacon.commitmentAt(2)).toEqual(COMMITMENTS[2]);
  });

  it("classifies phase-completing contributions without mutating state", () => {
    const beacon = new RandomnessBeacon(GAME_ID, ROUND, 3);
    beacon.acceptCommitment(0, COMMITMENTS[0]!);
    beacon.acceptCommitment(1, COMMITMENTS[1]!);

    expect(beacon.classifyCommitment(2, COMMITMENTS[2]!)).toMatchObject({
      status: "accepted",
      state: "revealing",
    });
    expect(beacon.state).toBe("committing");
    beacon.acceptCommitment(2, COMMITMENTS[2]!);
    beacon.acceptReveal(0, SECRETS[0]!);
    beacon.acceptReveal(1, SECRETS[1]!);

    expect(beacon.classifyReveal(2, SECRETS[2]!)).toMatchObject({
      status: "accepted",
      state: "complete",
    });
    expect(beacon.state).toBe("revealing");
    expect(beacon.seed).toBeNull();
  });

  it("creates a contribution exclusively through the injected source", () => {
    const contribution = createBeaconContribution(GAME_ID, ROUND, 1, fillSource(0x5a));

    expect(contribution.secret).toEqual(new Uint8Array(32).fill(0x5a));
    expect(contribution.commitment).toEqual(
      beaconCommitment(GAME_ID, ROUND, 1, contribution.secret),
    );
  });

  it("moves from all commitments to seat-ordered reveals and a stable seed", () => {
    const beacon = new RandomnessBeacon(GAME_ID, ROUND, 3);

    expect(beacon.acceptCommitment(2, COMMITMENTS[2]!)).toMatchObject({
      status: "accepted",
      state: "committing",
    });
    expect(beacon.acceptCommitment(0, COMMITMENTS[0]!)).toMatchObject({
      status: "accepted",
      state: "committing",
    });
    expect(beacon.acceptCommitment(1, COMMITMENTS[1]!)).toMatchObject({
      status: "accepted",
      state: "revealing",
    });

    expect(beacon.acceptReveal(2, SECRETS[2]!)).toMatchObject({
      status: "accepted",
      state: "revealing",
    });
    expect(beacon.acceptReveal(0, SECRETS[0]!)).toMatchObject({
      status: "accepted",
      state: "revealing",
    });
    expect(beacon.acceptReveal(1, SECRETS[1]!)).toMatchObject({
      status: "accepted",
      state: "complete",
    });

    expect(bytesToHex(beacon.seed!)).toBe(
      "934d1dbfb88c30da48404c96d98e39955ff1586d9382c2ceb15264cb23ea1710",
    );
  });

  it("rejects a reveal before every commitment", () => {
    const beacon = new RandomnessBeacon(GAME_ID, ROUND, 3);
    beacon.acceptCommitment(0, COMMITMENTS[0]!);

    expect(beacon.acceptReveal(0, SECRETS[0]!)).toMatchObject({
      status: "rejected",
      reason: "unexpected_reveal",
    });
    expect(beacon.seed).toBeNull();
  });

  it("rejects a reveal that does not open its seat commitment", () => {
    const beacon = committedBeacon();

    expect(beacon.acceptReveal(0, SECRETS[1]!)).toMatchObject({
      status: "rejected",
      reason: "commitment_mismatch",
    });
    expect(beacon.state).toBe("revealing");
  });

  it("distinguishes exact duplicates from conflicting values", () => {
    const beacon = new RandomnessBeacon(GAME_ID, ROUND, 3);
    beacon.acceptCommitment(0, COMMITMENTS[0]!);

    expect(beacon.acceptCommitment(0, COMMITMENTS[0]!)).toMatchObject({ status: "duplicate" });
    expect(beacon.acceptCommitment(0, COMMITMENTS[1]!)).toMatchObject({
      status: "rejected",
      reason: "conflicting_commitment",
    });

    beacon.acceptCommitment(1, COMMITMENTS[1]!);
    beacon.acceptCommitment(2, COMMITMENTS[2]!);
    beacon.acceptReveal(0, SECRETS[0]!);
    expect(beacon.acceptReveal(0, SECRETS[0]!)).toMatchObject({ status: "duplicate" });
    expect(beacon.acceptReveal(0, SECRETS[1]!)).toMatchObject({
      status: "rejected",
      reason: "conflicting_reveal",
    });
  });

  it("defensively copies accepted values and returned seeds", () => {
    const commitments = COMMITMENTS.map((value) => parseHash256(value));
    const secrets = SECRETS.map((value) => parseRandomSecret(value));
    const beacon = new RandomnessBeacon(GAME_ID, ROUND, 3);
    commitments.forEach((commitment, seat) => beacon.acceptCommitment(seat, commitment));
    commitments.forEach((commitment) => commitment.fill(0));
    secrets.forEach((secret, seat) => beacon.acceptReveal(seat, secret));
    secrets.forEach((secret) => secret.fill(0));

    const firstSeed = beacon.seed!;
    firstSeed.fill(0);
    expect(bytesToHex(beacon.seed!)).toBe(
      "934d1dbfb88c30da48404c96d98e39955ff1586d9382c2ceb15264cb23ea1710",
    );
  });

  it("validates constructor and seat bounds", () => {
    expect(() => new RandomnessBeacon(GAME_ID, -1, 3)).toThrow(RangeError);
    expect(() => new RandomnessBeacon(GAME_ID, 0, 2)).toThrow(RangeError);
    expect(() => new RandomnessBeacon(GAME_ID, 0, 9)).toThrow(RangeError);
    expect(() => new RandomnessBeacon(GAME_ID, 0, 3).acceptCommitment(3, COMMITMENTS[0]!)).toThrow(
      RangeError,
    );
    for (const seat of [-1, 3, 0.5, NaN, Infinity]) {
      expect(() => new RandomnessBeacon(GAME_ID, ROUND, 3).commitmentAt(seat)).toThrow(RangeError);
    }
  });
});

function committedBeacon(): RandomnessBeacon {
  const beacon = new RandomnessBeacon(GAME_ID, ROUND, 3);
  COMMITMENTS.forEach((commitment, seat) => beacon.acceptCommitment(seat, commitment));
  return beacon;
}

function fillSource(value: number): RandomSource {
  return {
    fill(target) {
      target.fill(value);
    },
  };
}
