import {
  decodeRistrettoScalar,
  encodeRistrettoScalar,
  RistrettoPoint,
} from "@p2pcards/crypto";
import type { CborMap, CborValue } from "@p2pcards/encoding";
import {
  expectArray,
  expectByteString,
  expectExactMap,
  expectUnsignedInteger,
  parseRistrettoPointEncoding,
  parseScalarEncoding,
  ProtocolSchemaError,
} from "@p2pcards/protocol";

import type {
  ChaumPedersenProof,
  GameKeyShare,
  ProvenDecryptionShare,
  SchnorrProofOfPossession,
} from "./proofs";

export interface PositionShare extends ProvenDecryptionShare {
  readonly pos: number;
}

export interface SharesBody {
  readonly to: number;
  readonly items: readonly PositionShare[];
}

const KEY_SHARE_KEYS = ["H_i", "pop"] as const;
const POP_KEYS = ["R", "z"] as const;
const SHARES_KEYS = ["to", "items"] as const;
const SHARE_ITEM_KEYS = ["pos", "S", "R1", "R2", "z"] as const;

export function encodeGameKeyShareBody(share: GameKeyShare): CborMap {
  return {
    H_i: share.H.toBytes(),
    pop: encodeSchnorrProof(share.pop),
  };
}

export function decodeGameKeyShareBody(value: CborValue): GameKeyShare {
  const body = expectExactMap(value, KEY_SHARE_KEYS, "KEY_SHARE.body");
  const pop = expectExactMap(body["pop"], POP_KEYS, "KEY_SHARE.body.pop");
  return Object.freeze({
    H: decodePoint(body["H_i"], "KEY_SHARE.body.H_i"),
    pop: Object.freeze({
      R: decodePoint(pop["R"], "KEY_SHARE.body.pop.R"),
      z: decodeScalar(pop["z"], "KEY_SHARE.body.pop.z"),
    }),
  });
}

export function encodeSharesBody(body: SharesBody): CborMap {
  requireSeat(body.to, "SHARES.body.to");
  requireItems(body.items);
  return {
    to: body.to,
    items: body.items.map((item) => encodePositionShare(item)),
  };
}

export function decodeSharesBody(value: CborValue): SharesBody {
  const body = expectExactMap(value, SHARES_KEYS, "SHARES.body");
  const to = expectUnsignedInteger(body["to"], "SHARES.body.to", 7);
  const encodedItems = expectArray(body["items"], "SHARES.body.items");
  const items = encodedItems.map((item, index) =>
    decodePositionShare(item, `SHARES.body.items[${index}]`),
  );
  requireItems(items);
  return Object.freeze({ to, items: Object.freeze(items) });
}

export function encodePositionShare(item: PositionShare): CborMap {
  requirePosition(item.pos, "share.pos");
  return {
    pos: item.pos,
    S: item.S.toBytes(),
    R1: item.proof.R1.toBytes(),
    R2: item.proof.R2.toBytes(),
    z: encodeRistrettoScalar(item.proof.z),
  };
}

export function decodePositionShare(value: CborValue, path = "share"): PositionShare {
  const item = expectExactMap(value, SHARE_ITEM_KEYS, path);
  return Object.freeze({
    pos: expectUnsignedInteger(item["pos"], `${path}.pos`, 127),
    S: decodePoint(item["S"], `${path}.S`),
    proof: Object.freeze({
      R1: decodePoint(item["R1"], `${path}.R1`),
      R2: decodePoint(item["R2"], `${path}.R2`),
      z: decodeScalar(item["z"], `${path}.z`),
    } satisfies ChaumPedersenProof),
  });
}

function encodeSchnorrProof(proof: SchnorrProofOfPossession): CborMap {
  return {
    R: proof.R.toBytes(),
    z: encodeRistrettoScalar(proof.z),
  };
}

function decodePoint(value: CborValue, path: string): RistrettoPoint {
  try {
    const bytes = parseRistrettoPointEncoding(expectByteString(value, path));
    return RistrettoPoint.fromBytes(bytes);
  } catch (cause) {
    if (cause instanceof ProtocolSchemaError) {
      throw cause;
    }
    throw new ProtocolSchemaError(path, "must be a canonical Ristretto point", { cause });
  }
}

function decodeScalar(value: CborValue, path: string) {
  try {
    const bytes = parseScalarEncoding(expectByteString(value, path));
    return decodeRistrettoScalar(bytes);
  } catch (cause) {
    if (cause instanceof ProtocolSchemaError) {
      throw cause;
    }
    throw new ProtocolSchemaError(path, "must be a canonical Ristretto scalar", { cause });
  }
}

function requireItems(items: readonly PositionShare[]): void {
  if (items.length === 0 || items.length > 128) {
    throw new ProtocolSchemaError("SHARES.body.items", "must contain 1 to 128 entries");
  }

  const positions = new Set<number>();
  for (const item of items) {
    requirePosition(item.pos, "SHARES.body.items[].pos");
    if (positions.has(item.pos)) {
      throw new ProtocolSchemaError("SHARES.body.items", `contains duplicate position ${item.pos}`);
    }
    positions.add(item.pos);
  }
}

function requireSeat(value: number, path: string): void {
  if (!Number.isInteger(value) || value < 0 || value > 7) {
    throw new ProtocolSchemaError(path, "must be an integer from 0 through 7");
  }
}

function requirePosition(value: number, path: string): void {
  if (!Number.isInteger(value) || value < 0 || value > 127) {
    throw new ProtocolSchemaError(path, "must be an integer from 0 through 127");
  }
}
