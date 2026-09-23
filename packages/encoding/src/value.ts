import { CanonicalCborError } from "./errors";

export type CborPrimitive = null | boolean | number | string | Uint8Array;
export interface CborArray extends ReadonlyArray<CborValue> {}
export interface CborMap {
  readonly [key: string]: CborValue;
}
export type CborValue = CborPrimitive | CborArray | CborMap;

export const MAX_CBOR_NESTING_DEPTH = 32;

export function assertCborValue(value: unknown): asserts value is CborValue {
  validateValue(value, "$", 0, new Set<object>());
}

export function normalizeDecodedValue(value: unknown): CborValue {
  return normalizeValue(value, "$", 0);
}

function validateValue(
  value: unknown,
  path: string,
  depth: number,
  ancestors: Set<object>,
): void {
  assertDepth(depth, path);

  if (value === null || typeof value === "boolean") {
    return;
  }

  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw unsupported(path, "must be a safe integer other than negative zero");
    }
    return;
  }

  if (typeof value === "string") {
    assertWellFormedString(value, path);
    return;
  }

  if (value instanceof Uint8Array) {
    if (value.constructor !== Uint8Array) {
      throw unsupported(path, "must use Uint8Array rather than a subclass");
    }
    return;
  }

  if (Array.isArray(value)) {
    withAncestor(value, path, ancestors, () => {
      for (let index = 0; index < value.length; index += 1) {
        if (!(index in value)) {
          throw unsupported(`${path}[${index}]`, "array entries cannot be sparse");
        }
        validateValue(value[index], `${path}[${index}]`, depth + 1, ancestors);
      }
    });
    return;
  }

  if (isPlainRecord(value)) {
    withAncestor(value, path, ancestors, () => {
      for (const key of Reflect.ownKeys(value)) {
        if (typeof key !== "string") {
          throw unsupported(path, "map keys must be text strings");
        }

        assertWellFormedString(key, `${path} key`);
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
          throw unsupported(`${path}.${key}`, "map entries must be enumerable data properties");
        }
        validateValue(descriptor.value, `${path}.${key}`, depth + 1, ancestors);
      }
    });
    return;
  }

  throw unsupported(path, `contains unsupported value type ${describeType(value)}`);
}

function normalizeValue(value: unknown, path: string, depth: number): CborValue {
  assertDepth(depth, path);

  if (value === null || typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw unsupported(path, "decoded number is not a supported integer");
    }
    return value;
  }

  if (typeof value === "string") {
    assertWellFormedString(value, path);
    return value;
  }

  if (value instanceof Uint8Array && value.constructor === Uint8Array) {
    return value.slice();
  }

  if (Array.isArray(value)) {
    return value.map((item, index) => normalizeValue(item, `${path}[${index}]`, depth + 1));
  }

  if (value instanceof Map) {
    const normalized: Record<string, CborValue> = Object.create(null) as Record<
      string,
      CborValue
    >;

    for (const [key, item] of value) {
      if (typeof key !== "string") {
        throw unsupported(path, "decoded map key is not a text string");
      }
      assertWellFormedString(key, `${path} key`);
      normalized[key] = normalizeValue(item, `${path}.${key}`, depth + 1);
    }

    return normalized;
  }

  throw unsupported(path, `decoded unsupported value type ${describeType(value)}`);
}

function withAncestor(
  value: object,
  path: string,
  ancestors: Set<object>,
  visit: () => void,
): void {
  if (ancestors.has(value)) {
    throw unsupported(path, "contains a cyclic reference");
  }

  ancestors.add(value);
  try {
    visit();
  } finally {
    ancestors.delete(value);
  }
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function assertDepth(depth: number, path: string): void {
  if (depth > MAX_CBOR_NESTING_DEPTH) {
    throw unsupported(path, `exceeds the maximum nesting depth of ${MAX_CBOR_NESTING_DEPTH}`);
  }
}

function assertWellFormedString(value: string, path: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);

    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff) {
        throw unsupported(path, "contains an unpaired high surrogate");
      }
      index += 1;
      continue;
    }

    if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw unsupported(path, "contains an unpaired low surrogate");
    }
  }
}

function describeType(value: unknown): string {
  if (value === undefined) {
    return "undefined";
  }
  if (typeof value !== "object" || value === null) {
    return typeof value;
  }
  return value.constructor?.name ?? "object";
}

function unsupported(path: string, detail: string): CanonicalCborError {
  return new CanonicalCborError("UNSUPPORTED_VALUE", `${path} ${detail}`);
}
