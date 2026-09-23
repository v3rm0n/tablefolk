import { ristretto255, ristretto255_hasher } from "@noble/curves/ed25519.js";
import { bytesToNumberLE } from "@noble/curves/utils.js";

import { bytesEqual } from "./bytes";
import { randomBytes, type RandomSource } from "./random";

type NobleRistrettoPoint = InstanceType<(typeof ristretto255)["Point"]>;

declare const scalarBrand: unique symbol;
export type RistrettoScalar = bigint & { readonly [scalarBrand]: true };

export const RISTRETTO_POINT_LENGTH = 32;
export const RISTRETTO_SCALAR_LENGTH = 32;
export const RISTRETTO_UNIFORM_BYTES_LENGTH = 64;
export const RISTRETTO_SCALAR_ORDER = ristretto255.Point.Fn.ORDER;
export const RISTRETTO_SCALAR_ZERO = 0n as RistrettoScalar;
export const RISTRETTO_SCALAR_ONE = 1n as RistrettoScalar;

export class RistrettoEncodingError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "RistrettoEncodingError";
  }
}

export class RistrettoPoint {
  readonly #point: NobleRistrettoPoint;

  private constructor(point: NobleRistrettoPoint) {
    this.#point = point;
  }

  static base(): RistrettoPoint {
    return new RistrettoPoint(ristretto255.Point.BASE);
  }

  static identity(): RistrettoPoint {
    return new RistrettoPoint(ristretto255.Point.ZERO);
  }

  static fromBytes(bytes: Uint8Array): RistrettoPoint {
    assertPlainBytes(bytes, "Ristretto point");
    if (bytes.length !== RISTRETTO_POINT_LENGTH) {
      throw new RistrettoEncodingError(
        `Ristretto point must contain exactly ${RISTRETTO_POINT_LENGTH} bytes; got ${bytes.length}`,
      );
    }

    try {
      const point = ristretto255.Point.fromBytes(bytes);
      if (!bytesEqual(point.toBytes(), bytes)) {
        throw new RistrettoEncodingError("Ristretto point encoding is not canonical");
      }
      return new RistrettoPoint(point);
    } catch (cause) {
      if (cause instanceof RistrettoEncodingError) {
        throw cause;
      }
      throw new RistrettoEncodingError("Invalid Ristretto point encoding", { cause });
    }
  }

  static fromUniformBytes(bytes: Uint8Array): RistrettoPoint {
    assertPlainBytes(bytes, "Ristretto uniform input");
    if (bytes.length !== RISTRETTO_UNIFORM_BYTES_LENGTH) {
      throw new RistrettoEncodingError(
        `Ristretto uniform input must contain exactly ${RISTRETTO_UNIFORM_BYTES_LENGTH} bytes; got ${bytes.length}`,
      );
    }

    const derive = ristretto255_hasher.deriveToCurve;
    if (derive === undefined) {
      throw new Error("Ristretto element derivation is unavailable");
    }
    return new RistrettoPoint(derive(bytes));
  }

  toBytes(): Uint8Array {
    return this.#point.toBytes();
  }

  add(other: RistrettoPoint): RistrettoPoint {
    return new RistrettoPoint(this.#point.add(other.#point));
  }

  subtract(other: RistrettoPoint): RistrettoPoint {
    return new RistrettoPoint(this.#point.subtract(other.#point));
  }

  negate(): RistrettoPoint {
    return new RistrettoPoint(this.#point.negate());
  }

  multiply(scalar: RistrettoScalar): RistrettoPoint {
    assertScalar(scalar);
    if (scalar === RISTRETTO_SCALAR_ZERO) {
      return RistrettoPoint.identity();
    }
    return new RistrettoPoint(this.#point.multiply(scalar));
  }

  equals(other: RistrettoPoint): boolean {
    return this.#point.equals(other.#point);
  }

  isIdentity(): boolean {
    return this.#point.is0();
  }
}

export function scalarFromBigInt(value: bigint): RistrettoScalar {
  if (typeof value !== "bigint" || value < 0n || value >= RISTRETTO_SCALAR_ORDER) {
    throw new RangeError("Ristretto scalar must be in the canonical range 0 <= s < q");
  }
  return value as RistrettoScalar;
}

export function decodeRistrettoScalar(bytes: Uint8Array): RistrettoScalar {
  assertPlainBytes(bytes, "Ristretto scalar");
  if (bytes.length !== RISTRETTO_SCALAR_LENGTH) {
    throw new RistrettoEncodingError(
      `Ristretto scalar must contain exactly ${RISTRETTO_SCALAR_LENGTH} bytes; got ${bytes.length}`,
    );
  }

  try {
    const scalar = ristretto255.Point.Fn.fromBytes(bytes);
    if (!bytesEqual(ristretto255.Point.Fn.toBytes(scalar), bytes)) {
      throw new RistrettoEncodingError("Ristretto scalar encoding is not canonical");
    }
    return scalarFromBigInt(scalar);
  } catch (cause) {
    if (cause instanceof RistrettoEncodingError) {
      throw cause;
    }
    throw new RistrettoEncodingError("Invalid Ristretto scalar encoding", { cause });
  }
}

export function encodeRistrettoScalar(scalar: RistrettoScalar): Uint8Array {
  assertScalar(scalar);
  return ristretto255.Point.Fn.toBytes(scalar);
}

export function reduceWideRistrettoScalar(bytes: Uint8Array): RistrettoScalar {
  assertPlainBytes(bytes, "Ristretto wide scalar input");
  if (bytes.length !== RISTRETTO_UNIFORM_BYTES_LENGTH) {
    throw new RistrettoEncodingError(
      `Ristretto wide scalar input must contain exactly ${RISTRETTO_UNIFORM_BYTES_LENGTH} bytes; got ${bytes.length}`,
    );
  }
  return scalarFromBigInt(bytesToNumberLE(bytes) % RISTRETTO_SCALAR_ORDER);
}

export function randomNonZeroRistrettoScalar(
  source?: RandomSource,
): RistrettoScalar {
  for (;;) {
    const bytes = randomBytes(RISTRETTO_SCALAR_LENGTH, source);
    bytes[RISTRETTO_SCALAR_LENGTH - 1] = bytes[RISTRETTO_SCALAR_LENGTH - 1]! & 0x1f;
    const candidate = bytesToNumberLE(bytes);
    if (candidate > 0n && candidate < RISTRETTO_SCALAR_ORDER) {
      return candidate as RistrettoScalar;
    }
  }
}

export function addRistrettoScalars(
  left: RistrettoScalar,
  right: RistrettoScalar,
): RistrettoScalar {
  assertScalar(left);
  assertScalar(right);
  return ristretto255.Point.Fn.add(left, right) as RistrettoScalar;
}

export function subtractRistrettoScalars(
  left: RistrettoScalar,
  right: RistrettoScalar,
): RistrettoScalar {
  assertScalar(left);
  assertScalar(right);
  return ristretto255.Point.Fn.sub(left, right) as RistrettoScalar;
}

export function multiplyRistrettoScalars(
  left: RistrettoScalar,
  right: RistrettoScalar,
): RistrettoScalar {
  assertScalar(left);
  assertScalar(right);
  return ristretto255.Point.Fn.mul(left, right) as RistrettoScalar;
}

export function negateRistrettoScalar(value: RistrettoScalar): RistrettoScalar {
  assertScalar(value);
  return ristretto255.Point.Fn.neg(value) as RistrettoScalar;
}

function assertScalar(value: bigint): asserts value is RistrettoScalar {
  scalarFromBigInt(value);
}

function assertPlainBytes(value: unknown, label: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.constructor !== Uint8Array) {
    throw new TypeError(`${label} must be a plain Uint8Array`);
  }
}
