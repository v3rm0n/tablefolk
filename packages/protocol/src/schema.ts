import type { CborMap, CborValue } from "@p2pcards/encoding";

export class ProtocolSchemaError extends Error {
  readonly path: string;

  constructor(path: string, message: string, options?: ErrorOptions) {
    super(`${path}: ${message}`, options);
    this.name = "ProtocolSchemaError";
    this.path = path;
  }
}

export function expectExactMap<const Keys extends readonly string[]>(
  value: CborValue,
  expectedKeys: Keys,
  path: string,
): CborMap & Record<Keys[number], CborValue> {
  if (!isCborMap(value)) {
    throw new ProtocolSchemaError(path, "must be a CBOR map");
  }

  const actualKeys = Object.keys(value);
  if (
    actualKeys.length !== expectedKeys.length ||
    expectedKeys.some((key) => !Object.hasOwn(value, key))
  ) {
    throw new ProtocolSchemaError(path, `fields must be exactly: ${expectedKeys.join(", ")}`);
  }
  return value as CborMap & Record<Keys[number], CborValue>;
}

export function expectArray(value: CborValue, path: string): readonly CborValue[] {
  if (!Array.isArray(value)) {
    throw new ProtocolSchemaError(path, "must be an array");
  }
  return value;
}

export function expectByteString(value: CborValue, path: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.constructor !== Uint8Array) {
    throw new ProtocolSchemaError(path, "must be a byte string");
  }
  return value;
}

export function expectUnsignedInteger(
  value: CborValue,
  path: string,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > maximum
  ) {
    throw new ProtocolSchemaError(path, `must be an unsigned integer no greater than ${maximum}`);
  }
  return value;
}

export function expectNonEmptyText(value: CborValue, path: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new ProtocolSchemaError(path, "must be a non-empty text string");
  }
  return value;
}

function isCborMap(value: CborValue): value is CborMap {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof Uint8Array)
  );
}
