import type { CborMap, CborValue } from "@p2pcards/encoding";

import {
  parseHash256,
  parseRandomSecret,
  type Hash256,
  type RandomSecret,
} from "./fields";
import { expectByteString, expectExactMap, ProtocolSchemaError } from "./schema";

export interface RandCommitBody {
  readonly cm: Hash256;
}

export interface RandRevealBody {
  readonly s: RandomSecret;
}

export function encodeRandCommitBody(body: RandCommitBody): CborMap {
  return { cm: parseHash256(body.cm) };
}

export function decodeRandCommitBody(value: CborValue): RandCommitBody {
  const body = expectExactMap(value, ["cm"] as const, "RAND_COMMIT.body");
  try {
    return Object.freeze({ cm: parseHash256(expectByteString(body["cm"], "RAND_COMMIT.body.cm")) });
  } catch (cause) {
    if (cause instanceof ProtocolSchemaError) {
      throw cause;
    }
    throw new ProtocolSchemaError("RAND_COMMIT.body.cm", "must be a 32-byte hash", { cause });
  }
}

export function encodeRandRevealBody(body: RandRevealBody): CborMap {
  return { s: parseRandomSecret(body.s) };
}

export function decodeRandRevealBody(value: CborValue): RandRevealBody {
  const body = expectExactMap(value, ["s"] as const, "RAND_REVEAL.body");
  try {
    return Object.freeze({
      s: parseRandomSecret(expectByteString(body["s"], "RAND_REVEAL.body.s")),
    });
  } catch (cause) {
    if (cause instanceof ProtocolSchemaError) {
      throw cause;
    }
    throw new ProtocolSchemaError("RAND_REVEAL.body.s", "must be a 32-byte secret", { cause });
  }
}
