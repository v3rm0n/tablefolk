import { bytesToHex, hexToBytes, RistrettoPoint, scalarFromBigInt, type RandomSource } from "@p2pcards/crypto";
import { decodeCanonical, encodeCanonical, type CborMap, type CborValue } from "@p2pcards/encoding";
import { parseGameId, ProtocolSchemaError } from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";

import {
  decodeActionBody, decodeAuditDiscloseBody, encodeActionBody, encodeAuditDiscloseBody,
  MAX_ACTION_DATA_BYTES, MAX_ACTION_KIND_BYTES, type ActionBody,
} from "./action-wire";
import { createProvenDecryptionShare, verifyProvenDecryptionShare } from "./proofs";
import { encodePositionShare, type PositionShare } from "./wire";

// Encoding fixture only: canonical points/scalar do not imply a valid DLEQ statement.
const POINT_HEX = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76";
const SHARE_HEX = "a561535820" + POINT_HEX + "617a582001" + "00".repeat(31) +
  "6252315820" + POINT_HEX + "6252325820" + POINT_HEX + "63706f7302";
const PASS = { kind: "pass", data: {}, reveal: [], shares: [] } satisfies ActionBody;

describe("ACTION wire body", () => {
  it("matches independently laid-out canonical pass and positional-play fixtures", () => {
    const passHex = "a46464617461a0646b696e6464706173736672657665616c806673686172657380";
    expect(bytesToHex(encodeCanonical(encodeActionBody(PASS)))).toBe(passHex);
    expect(decodeActionBody(decodeCanonical(hexToBytes(passHex)))).toEqual(PASS);
    const play = { kind: "play", data: {}, reveal: [2], shares: [share(2)] };
    const playHex = "a46464617461a0646b696e6464706c61796672657665616c81026673686172657381" + SHARE_HEX;
    expect(bytesToHex(encodeCanonical(encodeActionBody(play)))).toBe(playHex);
    expect(encodeActionBody(decodeActionBody(decodeCanonical(hexToBytes(playHex))))).toEqual(encodeActionBody(play));
  });

  it("round-trips a real proof bound to the action phase, without claiming codec proof verification", () => {
    const context = { gameId: parseGameId(new Uint8Array(16).fill(9)), round: 2, phase: "round.2.play.7" };
    const secret = scalarFromBigInt(3n);
    const publicKey = RistrettoPoint.base().multiply(secret);
    const cardA = RistrettoPoint.base().multiply(scalarFromBigInt(5n));
    const source: RandomSource = { fill: (bytes) => { bytes.fill(0); bytes[0] = 7; } };
    const item = { pos: 2, ...createProvenDecryptionShare(context, 2, secret, cardA, source) };
    const body = decodeActionBody(decodeCanonical(encodeCanonical(encodeActionBody({
      kind: "play", data: {}, reveal: [2], shares: [item],
    }))));
    expect(verifyProvenDecryptionShare(context, 2, publicKey, cardA, body.shares[0]!)).toBe(true);
    expect(verifyProvenDecryptionShare({ ...context, phase: "round.2.play.8" }, 2, publicKey, cardA, body.shares[0]!)).toBe(false);
    const falseProof = decodeActionBody(encodeActionBody({
      ...body, shares: [{ ...item, proof: { ...item.proof, z: scalarFromBigInt(1n) } }],
    }));
    expect(verifyProvenDecryptionShare(context, 2, publicKey, cardA, falseProof.shares[0]!)).toBe(false);
    const auditContext = { ...context, phase: "round.2.audit" };
    const audit = decodeAuditDiscloseBody(encodeAuditDiscloseBody({ items: [
      { pos: 2, ...createProvenDecryptionShare(auditContext, 2, secret, cardA, source) },
    ] }));
    expect(verifyProvenDecryptionShare(auditContext, 2, publicKey, cardA, audit.items[0]!)).toBe(true);
    expect(verifyProvenDecryptionShare(context, 2, publicKey, cardA, audit.items[0]!)).toBe(false);
  });

  it("preserves reveal order and permits the complete bounded position set", () => {
    const reveal = Array.from({ length: 128 }, (_, index) => 127 - index);
    const body = decodeActionBody(encodeActionBody({ kind: "reveal_many", data: null, reveal, shares: reveal.map(share) }));
    expect(body.reveal).toEqual(reveal);
    expect(body.shares.map(({ pos }) => pos)).toEqual(reveal);
    expect(Object.isFrozen(body)).toBe(true);
    expect(Object.isFrozen(body.reveal)).toBe(true);
    expect(Object.isFrozen(body.shares)).toBe(true);
  });

  it("bounds encoded data and kind length without counting JS characters as arbitrary wire bytes", () => {
    expect(decodeActionBody(encodeActionBody({ ...PASS, kind: "a".repeat(MAX_ACTION_KIND_BYTES) })).kind).toHaveLength(64);
    const data = new Uint8Array(MAX_ACTION_DATA_BYTES - 3);
    expect(encodeCanonical(data)).toHaveLength(MAX_ACTION_DATA_BYTES);
    expect(decodeActionBody(encodeActionBody({ ...PASS, data })).data).toEqual(data);
    expect(() => encodeActionBody({ ...PASS, data: new Uint8Array(data.length + 1) })).toThrow(ProtocolSchemaError);
    expect(() => decodeActionBody({ ...PASS, data: new Uint8Array(data.length + 1) })).toThrow(ProtocolSchemaError);
  });

  it.each(["", "a".repeat(65), "Pass", "a-b", "pass\n", "pass\r\n", "_pass", "0pass", "\u00e9", "\ud800"])(
    "rejects non-profile action kinds: %j", (kind) => {
      expect(() => encodeActionBody({ ...PASS, kind })).toThrow(ProtocolSchemaError);
      expect(() => decodeActionBody({ ...PASS, kind })).toThrow(ProtocolSchemaError);
    },
  );

  it.each([
    null, {}, { ...PASS, extra: true }, { kind: "pass", data: {}, reveal: [] },
    { ...PASS, reveal: "0" }, { ...PASS, shares: {} },
    { ...PASS, reveal: [0], shares: [] }, { ...PASS, reveal: [], shares: [encodePositionShare(share(0))] },
    { ...PASS, reveal: [0, 0], shares: [encodePositionShare(share(0)), encodePositionShare(share(0))] },
    { ...PASS, reveal: [0, 1], shares: [encodePositionShare(share(1)), encodePositionShare(share(0))] },
    { ...PASS, reveal: [0], shares: [encodePositionShare(share(-0))] },
    { ...PASS, reveal: [0], shares: new Array<CborValue>(1) },
    { ...PASS, reveal: new Array<CborValue>(1), shares: [encodePositionShare(share(0))] },
    { ...PASS, reveal: new Array<number>(129).fill(0), shares: new Array<CborValue>(129).fill(null) },
  ] as CborValue[])("rejects invalid action shape or reveal/share correspondence: %j", (body) => {
    expect(() => decodeActionBody(body)).toThrow(ProtocolSchemaError);
  });

  it.each([-0, -1, 128, 0.5, NaN, Number.MAX_SAFE_INTEGER])("rejects invalid reveal position %s", (pos) => {
    expect(() => decodeActionBody({ ...PASS, reveal: [pos], shares: [encodePositionShare(share(0))] })).toThrow(ProtocolSchemaError);
  });

  it.each([undefined, NaN, Infinity, -0, 1.5, 1n, new Date(0), new Map(), () => 0])(
    "rejects non-CBOR action data: %s", (data) => {
      expect(() => encodeActionBody({ ...PASS, data: data as CborValue })).toThrow(ProtocolSchemaError);
    },
  );

  it("rejects cyclic, sparse, and over-nested data and invalid encoder collections", () => {
    const cyclic: Record<string, CborValue> = {};
    cyclic["self"] = cyclic;
    let deep: CborValue = null;
    for (let index = 0; index < 33; index += 1) deep = [deep];
    for (const data of [cyclic, deep, new Array<CborValue>(1)]) {
      expect(() => encodeActionBody({ ...PASS, data })).toThrow(ProtocolSchemaError);
    }
    for (const shares of [null, new Array<PositionShare>(1), new Array<PositionShare>(129)]) {
      expect(() => encodeActionBody({ ...PASS, shares: shares as readonly PositionShare[] })).toThrow(ProtocolSchemaError);
    }
  });

  it.each([
    { extra: true }, { S: new Uint8Array(31) }, { S: new Uint8Array(32).fill(1) },
    { R1: new Uint8Array(32).fill(0xff) }, { R2: new Uint8Array(33) }, { z: new Uint8Array(32).fill(0xff) },
  ])("rejects noncanonical or extended share fields: %j", (overrides) => {
    const body = { ...PASS, reveal: [2], shares: [{ ...encodePositionShare(share(2)), ...overrides }] };
    expect(() => decodeActionBody(body)).toThrow(ProtocolSchemaError);
    expect(() => decodeAuditDiscloseBody({ items: body.shares })).toThrow(ProtocolSchemaError);
  });

  it("copies data, positions, and proof bytes at both codec boundaries", () => {
    const original = { kind: "play", data: { nested: [new Uint8Array([1, 2])] }, reveal: [2], shares: [share(2)] };
    const wire = encodeActionBody(original);
    original.data.nested[0]!.fill(0xff);
    original.reveal[0] = 9;
    const decoded = decodeActionBody(wire);
    const stable = encodeCanonical(encodeActionBody(decoded));
    ((wire["data"] as CborMap)["nested"] as Uint8Array[])[0]!.fill(0xee);
    ((wire["shares"] as CborMap[])[0]!["S"] as Uint8Array).fill(0xdd);
    expect(decoded.data).toEqual({ nested: [new Uint8Array([1, 2])] });
    expect(decoded.reveal).toEqual([2]);
    expect(encodeCanonical(encodeActionBody(decoded))).toEqual(stable);
  });
});

describe("AUDIT_DISCLOSE wire body", () => {
  it("has exact empty and populated canonical fixtures, including when every card was already played", () => {
    expect(bytesToHex(encodeCanonical(encodeAuditDiscloseBody({ items: [] })))).toBe("a1656974656d7380");
    const fixture = "a1656974656d7381" + SHARE_HEX;
    expect(bytesToHex(encodeCanonical(encodeAuditDiscloseBody({ items: [share(2)] })))).toBe(fixture);
    expect(encodeAuditDiscloseBody(decodeAuditDiscloseBody(decodeCanonical(hexToBytes(fixture))))).toEqual({ items: [encodePositionShare(share(2))] });
  });

  it("preserves bounded item order and rejects duplicates, extension fields, and oversized/sparse arrays", () => {
    const items = Array.from({ length: 128 }, (_, index) => share(127 - index));
    expect(decodeAuditDiscloseBody(encodeAuditDiscloseBody({ items })).items.map(({ pos }) => pos)).toEqual(items.map(({ pos }) => pos));
    for (const bad of [
      {}, { items: [], extra: 0 }, { items: {} }, { items: new Array<CborValue>(129) },
      { items: new Array<CborValue>(1) }, { items: [encodePositionShare(share(2)), encodePositionShare(share(2))] },
      { items: [encodePositionShare(share(-0))] },
    ] as CborValue[]) {
      expect(() => decodeAuditDiscloseBody(bad)).toThrow(ProtocolSchemaError);
    }
    expect(() => encodeAuditDiscloseBody({ items: [share(2), share(2)] })).toThrow(ProtocolSchemaError);
  });
});

function share(pos: number): PositionShare {
  return { pos, S: RistrettoPoint.base(), proof: { R1: RistrettoPoint.base(), R2: RistrettoPoint.base(), z: scalarFromBigInt(1n) } };
}
