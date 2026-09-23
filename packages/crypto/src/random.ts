export interface RandomSource {
  fill(target: Uint8Array): void;
}

interface CryptoWithRandomValues {
  getRandomValues<T extends Uint8Array>(target: T): T;
}

const GET_RANDOM_VALUES_LIMIT = 65_536;
const UINT32_RANGE = 0x1_0000_0000;

export const systemRandomSource: RandomSource = Object.freeze({
  fill(target: Uint8Array): void {
    assertPlainByteArray(target);
    const crypto = (globalThis as { readonly crypto?: CryptoWithRandomValues }).crypto;
    if (crypto === undefined || typeof crypto.getRandomValues !== "function") {
      throw new Error("crypto.getRandomValues is unavailable");
    }

    for (let offset = 0; offset < target.length; offset += GET_RANDOM_VALUES_LIMIT) {
      crypto.getRandomValues(target.subarray(offset, offset + GET_RANDOM_VALUES_LIMIT));
    }
  },
});

export function randomBytes(length: number, source: RandomSource = systemRandomSource): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new RangeError("Random byte length must be a non-negative safe integer");
  }
  if (typeof source !== "object" || source === null || typeof source.fill !== "function") {
    throw new TypeError("Random source must implement fill(target)");
  }

  const bytes = new Uint8Array(length);
  source.fill(bytes);
  return bytes;
}

export function randomUint32Below(
  upperExclusive: number,
  source: RandomSource = systemRandomSource,
): number {
  if (!Number.isInteger(upperExclusive) || upperExclusive < 1 || upperExclusive > UINT32_RANGE) {
    throw new RangeError("Upper bound must be an integer from 1 through 2^32");
  }

  const acceptanceLimit = UINT32_RANGE - (UINT32_RANGE % upperExclusive);
  for (;;) {
    const bytes = randomBytes(4, source);
    const candidate =
      (bytes[0]! +
        bytes[1]! * 0x100 +
        bytes[2]! * 0x1_0000 +
        bytes[3]! * 0x100_0000) >>>
      0;
    if (candidate < acceptanceLimit) {
      return candidate % upperExclusive;
    }
  }
}

function assertPlainByteArray(value: unknown): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.constructor !== Uint8Array) {
    throw new TypeError("Random output target must be a plain Uint8Array");
  }
}
