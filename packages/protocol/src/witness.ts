import { bytesToHex } from "@p2pcards/crypto";
import type { CborMap, CborValue } from "@p2pcards/encoding";

import {
  parseHash256,
  parseIdentityPublicKey,
  type Hash256,
  type IdentityPublicKey,
} from "./fields";
import {
  expectArray,
  expectByteString,
  expectExactMap,
  expectUnsignedInteger,
  ProtocolSchemaError,
} from "./schema";

export interface WitnessHead {
  readonly from: IdentityPublicKey;
  readonly seq: number;
  readonly hash: Hash256;
}

export interface WitnessBody {
  readonly heads: readonly WitnessHead[];
  readonly stateHash?: Hash256;
}

const MAX_WITNESS_HEADS = 8;
const BODY_KEYS = ["heads"] as const;
const BODY_WITH_STATE_KEYS = ["heads", "state_hash"] as const;
const HEAD_KEYS = ["from", "seq", "hash"] as const;

export function encodeWitnessBody(body: WitnessBody): CborMap {
  const heads = normalizeHeads(body.heads);
  const encodedHeads = heads.map((head) => ({
    from: head.from,
    seq: head.seq,
    hash: head.hash,
  }));
  if (body.stateHash !== undefined) {
    return {
      heads: encodedHeads,
      state_hash: decodeHash(body.stateHash, "WITNESS.body.state_hash"),
    };
  }
  return { heads: encodedHeads };
}

export function decodeWitnessBody(value: CborValue): WitnessBody {
  const body = expectExactMap(
    value,
    hasMapKey(value, "state_hash") ? BODY_WITH_STATE_KEYS : BODY_KEYS,
    "WITNESS.body",
  );
  const encodedHeads = expectArray(body["heads"], "WITNESS.body.heads");
  if (encodedHeads.length > MAX_WITNESS_HEADS) {
    throw new ProtocolSchemaError("WITNESS.body.heads", "must contain at most 8 entries");
  }

  const heads = encodedHeads.map((candidate, index): WitnessHead => {
    const path = `WITNESS.body.heads[${index}]`;
    const head = expectExactMap(candidate, HEAD_KEYS, path);
    return Object.freeze({
      from: decodeIdentity(head["from"], `${path}.from`),
      seq: expectUnsignedInteger(head["seq"], `${path}.seq`),
      hash: decodeHash(head["hash"], `${path}.hash`),
    });
  });
  rejectDuplicateSenders(heads);
  const frozenHeads = Object.freeze(heads);
  if (Object.hasOwn(body, "state_hash")) {
    return Object.freeze({
      heads: frozenHeads,
      stateHash: decodeHash(body["state_hash"]!, "WITNESS.body.state_hash"),
    });
  }
  return Object.freeze({ heads: frozenHeads });
}

function normalizeHeads(heads: readonly WitnessHead[]): readonly WitnessHead[] {
  if (!Array.isArray(heads) || heads.length > MAX_WITNESS_HEADS) {
    throw new ProtocolSchemaError("WITNESS.body.heads", "must contain at most 8 entries");
  }
  const normalized = heads.map((head, index): WitnessHead => {
    const path = `WITNESS.body.heads[${index}]`;
    if (typeof head !== "object" || head === null) {
      throw new ProtocolSchemaError(path, "must be a head object");
    }
    return Object.freeze({
      from: decodeIdentity(head.from, `${path}.from`),
      seq: expectUnsignedInteger(head.seq, `${path}.seq`),
      hash: decodeHash(head.hash, `${path}.hash`),
    });
  });
  rejectDuplicateSenders(normalized);
  return normalized;
}

function rejectDuplicateSenders(heads: readonly WitnessHead[]): void {
  const senders = new Set<string>();
  for (const [index, head] of heads.entries()) {
    const sender = bytesToHex(head.from);
    if (senders.has(sender)) {
      throw new ProtocolSchemaError(
        "WITNESS.body.heads",
        `contains duplicate sender at index ${index}`,
      );
    }
    senders.add(sender);
  }
}

function decodeIdentity(value: CborValue, path: string): IdentityPublicKey {
  try {
    return parseIdentityPublicKey(expectByteString(value, path));
  } catch (cause) {
    if (cause instanceof ProtocolSchemaError) {
      throw cause;
    }
    throw new ProtocolSchemaError(path, "must be a 32-byte identity key", { cause });
  }
}

function decodeHash(value: CborValue, path: string): Hash256 {
  try {
    return parseHash256(expectByteString(value, path));
  } catch (cause) {
    if (cause instanceof ProtocolSchemaError) {
      throw cause;
    }
    throw new ProtocolSchemaError(path, "must be a 32-byte hash", { cause });
  }
}

function hasMapKey(value: CborValue, key: string): boolean {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof Uint8Array) &&
    Object.hasOwn(value, key)
  );
}
