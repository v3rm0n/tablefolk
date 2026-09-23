import { decode, encode } from "cbor2";

import { CanonicalCborError } from "./errors";
import {
  assertCborValue,
  MAX_CBOR_NESTING_DEPTH,
  normalizeDecodedValue,
  type CborValue,
} from "./value";

const EMPTY_TAG_DECODERS = new Map();

declare const canonicalCborBrand: unique symbol;

export type CanonicalCbor = Uint8Array & { readonly [canonicalCborBrand]: true };

export function encodeCanonical(value: CborValue): CanonicalCbor {
  assertCborValue(value);

  try {
    return encode(value, {
      cde: true,
      rejectBigInts: true,
      rejectDuplicateKeys: true,
      rejectFloats: true,
      rejectUndefined: true,
    }) as CanonicalCbor;
  } catch (cause) {
    if (cause instanceof CanonicalCborError) {
      throw cause;
    }
    throw new CanonicalCborError("MALFORMED", "Unable to encode canonical CBOR", { cause });
  }
}

export function decodeCanonical(bytes: Uint8Array): CborValue {
  if (!(bytes instanceof Uint8Array) || bytes.constructor !== Uint8Array) {
    throw new CanonicalCborError("UNSUPPORTED_VALUE", "CBOR input must be a Uint8Array");
  }
  if (bytes.length === 0) {
    throw new CanonicalCborError("MALFORMED", "CBOR input is empty");
  }

  let normalized: CborValue;
  try {
    const decoded: unknown = decode(bytes, {
      cde: true,
      collapseBigInts: false,
      ignoreGlobalTags: true,
      maxDepth: MAX_CBOR_NESTING_DEPTH,
      preferBigInt: false,
      preferMap: true,
      rejectBigInts: true,
      rejectDuplicateKeys: true,
      rejectFloats: true,
      rejectSimple: true,
      rejectStreaming: true,
      rejectUndefined: true,
      tags: EMPTY_TAG_DECODERS,
    });
    normalized = normalizeDecodedValue(decoded);
  } catch (cause) {
    if (cause instanceof CanonicalCborError) {
      throw cause;
    }
    throw new CanonicalCborError("MALFORMED", "Unable to decode canonical CBOR", { cause });
  }

  const reencoded = encodeCanonical(normalized);
  if (!bytesEqual(bytes, reencoded)) {
    throw new CanonicalCborError(
      "NON_CANONICAL",
      "CBOR input does not have exactly one canonical encoding",
    );
  }

  return normalized;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }

  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      return false;
    }
  }
  return true;
}
