import { describe, expect, it } from "vitest";

import { randomPermutation } from "./permutation";
import type { RandomSource } from "./random";

describe("uniform Fisher-Yates permutations", () => {
  it("uses one bounded random choice for each descending position", () => {
    expect(randomPermutation(5, uint32Source([0, 1, 2, 0]))).toEqual([3, 4, 2, 1, 0]);
  });

  it("returns every source index exactly once", () => {
    const result = randomPermutation(16, uint32Source(Array.from({ length: 15 }, (_, i) => i)));
    expect([...result].sort((left, right) => left - right)).toEqual(
      Array.from({ length: 16 }, (_, index) => index),
    );
  });

  it("handles empty and singleton permutations without requesting randomness", () => {
    const source: RandomSource = {
      fill() {
        throw new Error("Randomness should not be requested");
      },
    };
    expect(randomPermutation(0, source)).toEqual([]);
    expect(randomPermutation(1, source)).toEqual([0]);
  });

  it.each([-1, 1.5, 0x1_0000_0000])("rejects invalid size %s", (size) => {
    expect(() => randomPermutation(size, uint32Source([]))).toThrow(RangeError);
  });
});

function uint32Source(values: readonly number[]): RandomSource {
  let index = 0;
  return {
    fill(target) {
      const value = values[index];
      if (value === undefined) {
        throw new Error("Test random source exhausted");
      }
      index += 1;
      target[0] = value & 0xff;
      target[1] = (value >>> 8) & 0xff;
      target[2] = (value >>> 16) & 0xff;
      target[3] = (value >>> 24) & 0xff;
    },
  };
}
