import {
  RISTRETTO_SCALAR_ORDER,
  RistrettoPoint,
  scalarFromBigInt,
  type RandomSource,
} from "@p2pcards/crypto";
import { describe, expect, it, vi } from "vitest";

import { CardPointTable } from "./card-points";
import {
  aggregatePublicKeys,
  decryptionShare,
  initialMaskedCard,
  removeDecryptionShares,
  type MaskedCard,
} from "./elgamal";
import { createUnprovenDeckShuffle } from "./shuffle";

const point = (value: bigint) => RistrettoPoint.base().multiply(scalarFromBigInt(value));
const key = point(15n);
const initial = [2n, 3n, 5n, 7n].map((value) => initialMaskedCard(point(value)));

describe("unproven deck shuffle preparation", () => {
  it("uses output-to-input permutation indices and output-indexed randomizers", () => {
    // Fisher-Yates swaps (3,1), (2,0), (1,0): output takes inputs [3,2,0,1].
    const result = createUnprovenDeckShuffle(
      initial,
      key,
      scriptedSource([1n, 0n, 0n, 11n, 13n, 17n, 19n]),
    );
    expect(result.witness.permutation).toEqual([3, 2, 0, 1]);
    expect(result.witness.randomizers).toEqual([11n, 13n, 17n, 19n]);

    // Independent coefficient calculation: A'=r*G; B'=(message + 15*r)*G.
    const expected = [[11n, 172n], [13n, 200n], [17n, 257n], [19n, 288n]] as const;
    result.outputDeck.forEach((card, index) => {
      expect(card.A.equals(point(expected[index]![0]))).toBe(true);
      expect(card.B.equals(point(expected[index]![1]))).toBe(true);
      expect(result.inputDeck[index]!.A.isIdentity()).toBe(true);
      expect(result.inputDeck[index]!.B.equals(initial[index]!.B)).toBe(true);
    });
  });

  it("preserves all 36 cards through four sequential shuffles and recipient-only opening", () => {
    const table = new CardPointTable({
      id: "shuffle-test/36@1",
      cards: Array.from({ length: 36 }, (_, index) => `card:${index}`),
    });
    const secrets = [3n, 5n, 7n, 11n].map(scalarFromBigInt);
    const aggregateKey = aggregatePublicKeys(secrets.map((secret) => point(secret)));
    let deck = Array.from({ length: table.size }, (_, index) => initialMaskedCard(table.pointAt(index))) as readonly MaskedCard[];
    let originalPositions = Array.from({ length: table.size }, (_, index) => index);

    for (let seat = 0; seat < secrets.length; seat += 1) {
      const before = deck.map((card) => [card.A.toBytes(), card.B.toBytes()]);
      const result = createUnprovenDeckShuffle(deck, aggregateKey, countingSource(1000n * BigInt(seat + 1)));
      originalPositions = result.witness.permutation.map((position) => originalPositions[position]!);
      expect(deck.map((card) => [card.A.toBytes(), card.B.toBytes()])).toEqual(before);
      expect([...result.witness.permutation].sort((a, b) => a - b)).toEqual(
        Array.from({ length: table.size }, (_, index) => index),
      );
      deck = result.outputDeck;
    }

    const opened: string[] = [];
    deck.forEach((card, position) => {
      const recipient = position % secrets.length;
      const otherShares = secrets.flatMap((secret, seat) =>
        seat === recipient ? [] : [decryptionShare(secret, card.A)],
      );
      const partial = removeDecryptionShares(card, otherShares);
      expect(table.identify(partial)).toBeNull();
      const plaintext = partial.subtract(decryptionShare(secrets[recipient]!, card.A));
      const cardId = table.identify(plaintext);
      expect(cardId).toBe(table.cardIdAt(originalPositions[position]!));
      opened.push(cardId!);
    });
    expect(new Set(opened).size).toBe(table.size);
  });

  it("retains permutation and scalar rejection sampling", () => {
    const source = scriptedSource([0xffff_ffffn, 0n, 1n, 0n, RISTRETTO_SCALAR_ORDER, 3n, 5n, 7n]);
    const result = createUnprovenDeckShuffle(initial.slice(0, 3), key, source);
    expect(result.witness.permutation).toEqual([2, 1, 0]);
    expect(result.witness.randomizers).toEqual([3n, 5n, 7n]);
    expect(source.fill).toHaveBeenCalledTimes(8);
  });

  it("draws a fresh witness for each invocation", () => {
    const source = scriptedSource([1n, 2n, 3n, 0n, 5n, 7n]);
    const first = createUnprovenDeckShuffle(initial.slice(0, 2), key, source);
    const second = createUnprovenDeckShuffle(initial.slice(0, 2), key, source);
    expect(first.witness.randomizers).toEqual([2n, 3n]);
    expect(second.witness.randomizers).toEqual([5n, 7n]);
    expect(first.witness.permutation).toEqual([0, 1]);
    expect(second.witness.permutation).toEqual([1, 0]);
    expect(source.fill).toHaveBeenCalledTimes(6);
  });

  it("captures the key and entire input before RNG callbacks can change caller inputs", () => {
    const mutableKey = point(15n);
    const mutableDeck = initial.map((card) => ({ A: card.A, B: card.B }));
    const source = scriptedSource([1n, 0n, 0n, 11n, 13n, 17n, 19n]);
    const result = createUnprovenDeckShuffle(mutableDeck, mutableKey, {
      fill(target) {
        mutableDeck.length = 0;
        mutableKey.toBytes = () => RistrettoPoint.identity().toBytes();
        source.fill(target);
      },
    });
    expect(result.aggregateKey.equals(key)).toBe(true);
    expect(result.inputDeck).toHaveLength(4);
    expect(result.outputDeck[0]!.B.equals(point(172n))).toBe(true);
    expect(result.inputDeck[0]!.B.equals(initial[0]!.B)).toBe(true);
    expect(Object.isFrozen(result.witness.permutation)).toBe(true);
    expect(Object.isFrozen(result.witness.randomizers)).toBe(true);
    expect(Object.isFrozen(result.outputDeck)).toBe(true);
  });

  it.each([0, 1, 129])("rejects a deck of size %s before requesting randomness", (size) => {
    const source = { fill: vi.fn() };
    expect(() => createUnprovenDeckShuffle(Array.from({ length: size }, () => initial[0]!), key, source))
      .toThrow(RangeError);
    expect(source.fill).not.toHaveBeenCalled();
  });

  it("accepts the existing maximum deck size without choosing a proof matrix", () => {
    const deck = Array.from({ length: 128 }, (_, index) => initialMaskedCard(point(BigInt(index + 1))));
    const result = createUnprovenDeckShuffle(deck, key, countingSource(1n));
    expect(result.outputDeck).toHaveLength(128);
    expect(new Set(result.witness.permutation).size).toBe(128);
  });

  it("rejects identity keys, sparse decks and malformed points before randomness", () => {
    const source = { fill: vi.fn() };
    expect(() => createUnprovenDeckShuffle(initial, RistrettoPoint.identity(), source)).toThrow(/identity/);
    expect(() => createUnprovenDeckShuffle(new Array<MaskedCard>(4), key, source)).toThrow(TypeError);
    expect(() => createUnprovenDeckShuffle({ length: 4 } as unknown as MaskedCard[], key, source)).toThrow(TypeError);
    const invalid = [initial[0]!, { A: initial[0]!.A, B: {} as RistrettoPoint }];
    expect(() => createUnprovenDeckShuffle(invalid, key, source)).toThrow(TypeError);
    expect(source.fill).not.toHaveBeenCalled();
  });

  it("propagates entropy failures without substituting predictable randomizers", () => {
    const failure = new Error("Entropy unavailable");
    let calls = 0;
    expect(() => createUnprovenDeckShuffle(initial, key, {
      fill(target) {
        calls += 1;
        if (calls === 5) throw failure;
        target[0] = 1;
      },
    })).toThrow(failure);
    expect(calls).toBe(5);
  });
});

function scriptedSource(values: readonly bigint[]) {
  let next = 0;
  return {
    fill: vi.fn((target: Uint8Array) => {
      const value = values[next++];
      if (value === undefined) throw new Error("Test random source exhausted");
      fillInteger(target, value);
    }),
  };
}

function countingSource(start: bigint): RandomSource {
  let next = start;
  return { fill: (target) => fillInteger(target, next++) };
}

function fillInteger(target: Uint8Array, value: bigint): void {
  for (let index = 0; index < target.length; index += 1) {
    target[index] = Number(value & 0xffn);
    value >>= 8n;
  }
}
