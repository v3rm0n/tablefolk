import { randomUint32Below, type RandomSource } from "./random";

export function randomPermutation(size: number, source?: RandomSource): readonly number[] {
  if (!Number.isInteger(size) || size < 0 || size > 0xffff_ffff) {
    throw new RangeError("Permutation size must be an integer from 0 through 2^32 - 1");
  }

  const permutation = Array.from({ length: size }, (_, index) => index);
  for (let index = size - 1; index > 0; index -= 1) {
    const swapIndex = randomUint32Below(index + 1, source);
    const value = permutation[index]!;
    permutation[index] = permutation[swapIndex]!;
    permutation[swapIndex] = value;
  }
  return Object.freeze(permutation);
}
