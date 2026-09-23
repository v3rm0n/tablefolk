import { decodeCanonical, encodeCanonical, type CborMap, type CborValue } from "@p2pcards/encoding";
import { expectArray, expectExactMap, expectNonEmptyText, expectUnsignedInteger, ProtocolSchemaError } from "@p2pcards/protocol";

import { decodePositionShare, encodePositionShare, type PositionShare } from "./wire";

export const MAX_ACTION_KIND_BYTES = 64;
export const MAX_ACTION_DATA_BYTES = 4096;
export const MAX_ACTION_REVEALS = 128;

export interface ActionBody {
  readonly kind: string;
  readonly data: CborValue;
  readonly reveal: readonly number[];
  readonly shares: readonly PositionShare[];
}

export interface AuditDiscloseBody {
  readonly items: readonly PositionShare[];
}

const ACTION_KEYS = ["kind", "data", "reveal", "shares"] as const;

/** Serializes proof statements; neither codec verifies their equations or position ownership. */
export function encodeActionBody(body: ActionBody): CborMap {
  expectExactMap(body as unknown as CborValue, ACTION_KEYS, "ACTION.body");
  const wire = { kind: body.kind, data: body.data, reveal: body.reveal, shares: encodeItems(body.shares, "ACTION.body.shares") };
  const decoded = decodeActionBody(wire);
  return { ...wire, data: decoded.data, reveal: decoded.reveal };
}

export function decodeActionBody(value: CborValue): ActionBody {
  const body = expectExactMap(value, ACTION_KEYS, "ACTION.body");
  const kind = expectNonEmptyText(body["kind"], "ACTION.body.kind");
  if (kind.length > MAX_ACTION_KIND_BYTES || !/^[a-z][a-z0-9_]*$/.test(kind)) {
    throw new ProtocolSchemaError("ACTION.body.kind", `must be a lowercase ASCII identifier of 1 to ${MAX_ACTION_KIND_BYTES} bytes`);
  }
  const positions = expectArray(body["reveal"], "ACTION.body.reveal");
  const encodedShares = expectArray(body["shares"], "ACTION.body.shares");
  if (positions.length > MAX_ACTION_REVEALS || encodedShares.length !== positions.length) {
    throw new ProtocolSchemaError("ACTION.body", "must contain 0 to 128 reveals and exactly one share per reveal");
  }
  const seen = new Set<number>();
  const reveal = Array.from(positions, (value, index) => {
    const pos = expectUnsignedInteger(value, `ACTION.body.reveal[${index}]`, 127);
    if (Object.is(pos, -0) || seen.has(pos)) {
      throw new ProtocolSchemaError("ACTION.body.reveal", "positions must be unique non-negative integers, not negative zero");
    }
    seen.add(pos);
    return pos;
  });
  const shares = Array.from(encodedShares, (value, index) => {
    const share = decodePositionShare(value, `ACTION.body.shares[${index}]`);
    if (Object.is(share.pos, -0) || share.pos !== reveal[index]) {
      throw new ProtocolSchemaError("ACTION.body.shares", "share positions must match reveal positions in the same order");
    }
    return share;
  });
  let data: CborValue;
  try {
    const bytes = encodeCanonical(body["data"]);
    if (bytes.length > MAX_ACTION_DATA_BYTES) {
      throw new ProtocolSchemaError("ACTION.body.data", `must encode within ${MAX_ACTION_DATA_BYTES} bytes`);
    }
    data = decodeCanonical(bytes);
  } catch (cause) {
    if (cause instanceof ProtocolSchemaError) { throw cause; }
    throw new ProtocolSchemaError("ACTION.body.data", "must be a supported canonical CBOR value", { cause });
  }
  return Object.freeze({ kind, data, reveal: Object.freeze(reveal), shares: Object.freeze(shares) });
}

export function encodeAuditDiscloseBody(body: AuditDiscloseBody): CborMap {
  expectExactMap(body as unknown as CborValue, ["items"], "AUDIT_DISCLOSE.body");
  const wire = { items: encodeItems(body.items, "AUDIT_DISCLOSE.body.items") };
  decodeAuditDiscloseBody(wire);
  return wire;
}

export function decodeAuditDiscloseBody(value: CborValue): AuditDiscloseBody {
  const body = expectExactMap(value, ["items"], "AUDIT_DISCLOSE.body");
  const encodedItems = expectArray(body["items"], "AUDIT_DISCLOSE.body.items");
  if (encodedItems.length > MAX_ACTION_REVEALS) {
    throw new ProtocolSchemaError("AUDIT_DISCLOSE.body.items", "must contain 0 to 128 entries");
  }
  const seen = new Set<number>();
  const items = Array.from(encodedItems, (value, index) => {
    const item = decodePositionShare(value, `AUDIT_DISCLOSE.body.items[${index}]`);
    if (Object.is(item.pos, -0) || seen.has(item.pos)) {
      throw new ProtocolSchemaError("AUDIT_DISCLOSE.body.items", "positions must be unique non-negative integers, not negative zero");
    }
    seen.add(item.pos);
    return item;
  });
  return Object.freeze({ items: Object.freeze(items) });
}

function encodeItems(items: readonly PositionShare[], path: string): readonly CborMap[] {
  if (!Array.isArray(items) || items.length > MAX_ACTION_REVEALS) {
    throw new ProtocolSchemaError(path, "must contain 0 to 128 entries");
  }
  return Array.from(items, (item, index) => {
    try { return encodePositionShare(item); }
    catch (cause) { throw new ProtocolSchemaError(`${path}[${index}]`, "must be a position share", { cause }); }
  });
}
