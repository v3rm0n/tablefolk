import {
  bytesToHex,
  deriveEd25519PublicKey,
  hexToBytes,
  importEd25519SecretKey,
} from "@p2pcards/crypto";
import { encodeCanonical } from "@p2pcards/encoding";
import { describe, expect, it, vi } from "vitest";

import { encodeRandCommitBody, encodeRandRevealBody } from "./beacon-messages";
import { ENVELOPE_MESSAGE_TYPES, ENVELOPE_VERSION } from "./envelope";
import {
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  parseRandomSecret,
  ProtocolFieldError,
} from "./fields";
import { snapshotSetupBeaconScope, type SetupBeaconScope } from "./index";

const GAME_ID_HEX = "000102030405060708090a0b0c0d0e0f";
const IDENTITIES = Array.from({ length: 9 }, (_, seat) =>
  parseIdentityPublicKey(
    deriveEd25519PublicKey(importEd25519SecretKey(new Uint8Array(32).fill(seat + 1))),
  ),
);
const SCOPE_FIELDS = ["gameId", "round", "roster", "sender"] as const;

function setupScope(count = 3, senderSeat = 0) {
  const roster = IDENTITIES.slice(0, count).map(parseIdentityPublicKey);
  return {
    gameId: parseGameId(hexToBytes(GAME_ID_HEX)),
    round: 0,
    roster,
    sender: parseIdentityPublicKey(roster[senderSeat]!),
  } satisfies SetupBeaconScope;
}

describe("local v1 setup beacon scope", () => {
  it.each([3, 4, 5, 6, 7, 8].flatMap((count) =>
    Array.from({ length: count }, (_, senderSeat) => ({ count, senderSeat })),
  ))("snapshots $count ordered identities with sender at seat $senderSeat", ({ count, senderSeat }) => {
    const source = setupScope(count, senderSeat);
    const snapshot = snapshotSetupBeaconScope(source);

    expect(snapshot).toEqual(source);
    expect(Reflect.ownKeys(snapshot)).toEqual(SCOPE_FIELDS);
    expect(snapshot).not.toBe(source);
    expect(snapshot.roster).not.toBe(source.roster);
    expect(snapshot.gameId.buffer).not.toBe(source.gameId.buffer);
    expect(snapshot.sender).toEqual(source.roster[senderSeat]);
    expect(snapshot.sender.buffer).not.toBe(source.sender.buffer);
    expect(snapshot.sender.buffer).not.toBe(snapshot.roster[senderSeat]!.buffer);
    expect(snapshot.roster).toHaveLength(count);
    snapshot.roster.forEach((identity, seat) => {
      expect(identity).toEqual(IDENTITIES[seat]);
      expect(identity.buffer).not.toBe(source.roster[seat]!.buffer);
    });
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot.roster)).toBe(true);
  });

  it("preserves roster order instead of sorting identities or assigning a seat field", () => {
    const source = setupScope(8, 5);
    source.roster.reverse();

    const snapshot = snapshotSetupBeaconScope(source);

    expect(snapshot.roster).toEqual([...IDENTITIES.slice(0, 8)].reverse());
    expect(snapshot.sender).toEqual(snapshot.roster[2]);
    expect(Reflect.ownKeys(snapshot)).toEqual(SCOPE_FIELDS);
  });

  it.each([0, 1, 17, Number.MAX_SAFE_INTEGER])("accepts safe non-negative round %s", (round) => {
    expect(snapshotSetupBeaconScope({ ...setupScope(), round }).round).toBe(round);
  });

  it("accepts null-prototype data records and already-frozen snapshots", () => {
    const source = setupScope();
    Object.setPrototypeOf(source, null);
    Object.freeze(source.roster);
    Object.freeze(source);

    const first = snapshotSetupBeaconScope(source);
    const second = snapshotSetupBeaconScope(first);

    expect(first).toEqual(setupScope());
    expect(second).toEqual(first);
    expect(second).not.toBe(first);
    expect(second.roster).not.toBe(first.roster);
    expect(second.gameId.buffer).not.toBe(first.gameId.buffer);
    expect(second.sender.buffer).not.toBe(first.sender.buffer);
    second.roster.forEach((identity, seat) => {
      expect(identity.buffer).not.toBe(first.roster[seat]!.buffer);
    });
  });

  it("freezes only the copied outer record and roster, not caller-owned values or byte contents", () => {
    const source = setupScope();
    const snapshot = snapshotSetupBeaconScope(source);

    expect(Object.isFrozen(source)).toBe(false);
    expect(Object.isFrozen(source.roster)).toBe(false);
    expect(Reflect.set(snapshot, "round", 1)).toBe(false);
    expect(Reflect.set(snapshot.roster, "0", IDENTITIES[3])).toBe(false);
    expect(Reflect.set(snapshot.roster, "length", 0)).toBe(false);
    expect(Reflect.deleteProperty(snapshot, "sender")).toBe(false);
    expect(Reflect.deleteProperty(snapshot.roster, "1")).toBe(false);
    for (const bytes of [snapshot.gameId, snapshot.sender, ...snapshot.roster]) {
      expect(Object.isFrozen(bytes)).toBe(false);
      bytes.fill(0xa5);
      expect(bytes.every((byte) => byte === 0xa5)).toBe(true);
    }
    expect(source).toEqual(setupScope());
  });

  it("keeps exported values unchanged after input bytes, roster, and properties mutate", () => {
    const source = setupScope();
    const snapshot = snapshotSetupBeaconScope(source);

    source.gameId.fill(0xff);
    source.sender.fill(0xee);
    source.roster.forEach((identity) => identity.fill(0xdd));
    source.roster.reverse();
    source.roster.push(parseIdentityPublicKey(IDENTITIES[3]));
    source.gameId = parseGameId(new Uint8Array(16));
    source.round = 42;
    source.roster = [];
    source.sender = parseIdentityPublicKey(IDENTITIES[4]);

    expect(snapshot).toEqual(setupScope());
  });

  it("keeps input, sibling snapshots, and an aliased sender independent of exported byte mutations", () => {
    const source = setupScope(3, 1);
    source.sender = source.roster[1]!;
    const first = snapshotSetupBeaconScope(source);
    const second = snapshotSetupBeaconScope(source);

    first.gameId.fill(0xaa);
    first.sender.fill(0xbb);
    expect(first.roster[1]).toEqual(IDENTITIES[1]);
    first.roster.forEach((identity) => identity.fill(0xcc));

    expect(first.sender).toEqual(new Uint8Array(32).fill(0xbb));
    expect(source).toEqual(setupScope(3, 1));
    expect(second).toEqual(setupScope(3, 1));
  });

  it.each([null, undefined, true, 0, "scope", [], new Date(0)])(
    "rejects non-record input %#",
    (candidate) => {
      expect(() => snapshotSetupBeaconScope(candidate as unknown as SetupBeaconScope)).toThrow(
        new TypeError("Setup beacon scope must be a plain object"),
      );
    },
  );

  it("rejects inherited fields, class instances, and custom-prototype records", () => {
    class ScopeRecord {}
    const source = setupScope();
    for (const candidate of [
      Object.create(source) as SetupBeaconScope,
      Object.assign(new ScopeRecord(), source),
      Object.assign(Object.create({ phase: "setup.rand" }) as object, source),
    ]) {
      expect(() => snapshotSetupBeaconScope(candidate)).toThrow(
        new TypeError("Setup beacon scope must be a plain object"),
      );
    }
  });

  it.each(SCOPE_FIELDS)("rejects a missing %s field", (field) => {
    const candidate = setupScope();
    Reflect.deleteProperty(candidate, field);

    expect(() => snapshotSetupBeaconScope(candidate)).toThrow(
      new TypeError("Setup beacon scope requires exactly gameId, round, roster, and sender"),
    );
  });

  it.each([
    ["phase", "setup.rand"],
    ["seat", 0],
    ["v", 1],
    ["type", "SETUP_BEACON"],
  ] as const)("rejects an extra %s data field", (field, value) => {
    expect(() => snapshotSetupBeaconScope({ ...setupScope(), [field]: value })).toThrow(
      new TypeError("Setup beacon scope requires exactly gameId, round, roster, and sender"),
    );
  });

  it.each(["phase", "seat", "v", "type", "extra", Symbol("extra")])(
    "rejects extra field %s, even when non-enumerable, without invoking it",
    (field) => {
      for (const enumerable of [true, false]) {
        const candidate = setupScope();
        const getter = vi.fn(() => "setup.rand");
        Object.defineProperty(candidate, field, { enumerable, get: getter });

        expect(() => snapshotSetupBeaconScope(candidate)).toThrow(
          new TypeError("Setup beacon scope requires exactly gameId, round, roster, and sender"),
        );
        expect(getter).not.toHaveBeenCalled();
      }
    },
  );

  it.each(SCOPE_FIELDS)("rejects non-enumerable %s data", (field) => {
    const candidate = setupScope();
    Object.defineProperty(candidate, field, { enumerable: false });

    expect(() => snapshotSetupBeaconScope(candidate)).toThrow(
      new TypeError("Setup beacon scope fields must be enumerable data properties"),
    );
  });

  it.each(SCOPE_FIELDS)("rejects accessor %s before invoking its getter or setter", (field) => {
    const candidate = setupScope();
    const value = candidate[field];
    const getter = vi.fn(() => value);
    const setter = vi.fn();
    Object.defineProperty(candidate, field, { enumerable: true, get: getter, set: setter });

    expect(() => snapshotSetupBeaconScope(candidate)).toThrow(
      new TypeError("Setup beacon scope fields must be enumerable data properties"),
    );
    expect(getter).not.toHaveBeenCalled();
    expect(setter).not.toHaveBeenCalled();
  });

  it.each([
    ["gameId", undefined],
    ["gameId", new Uint8Array(15)],
    ["gameId", new Uint8Array(17)],
    ["gameId", new Uint16Array(8)],
    ["sender", undefined],
    ["sender", null],
    ["sender", new Uint8Array(31)],
    ["sender", new Uint8Array(33)],
  ] as const)("rejects malformed %s bytes in case %#", (field, value) => {
    const candidate = { ...setupScope(), [field]: value } as unknown as SetupBeaconScope;

    expect(() => snapshotSetupBeaconScope(candidate)).toThrow(ProtocolFieldError);
  });

  it.each([
    ["negative zero", -0],
    ["negative", -1],
    ["fractional", 0.5],
    ["unsafe", Number.MAX_SAFE_INTEGER + 1],
    ["NaN", NaN],
    ["positive infinity", Infinity],
    ["negative infinity", -Infinity],
    ["text", "0"],
    ["bigint", 0n],
    ["null", null],
    ["undefined", undefined],
  ] as const)("rejects %s rounds", (_label, round) => {
    const candidate = { ...setupScope(), round } as unknown as SetupBeaconScope;

    expect(() => snapshotSetupBeaconScope(candidate)).toThrow(
      new RangeError("Setup beacon round must be a non-negative safe integer"),
    );
  });

  it.each([0, 1, 2, 9])("rejects a roster with %s entries", (count) => {
    const candidate = setupScope();
    candidate.roster = IDENTITIES.slice(0, count).map(parseIdentityPublicKey);

    expect(() => snapshotSetupBeaconScope(candidate)).toThrow(
      new RangeError("Setup beacon roster must contain three through eight identities"),
    );
  });

  it("rejects array-like rosters before reading length or element getters", () => {
    const candidate = setupScope();
    const getter = vi.fn(() => 3);
    const roster = Object.defineProperties({}, {
      length: { get: getter },
      0: { get: getter },
      1: { get: getter },
      2: { get: getter },
    });

    expect(() => snapshotSetupBeaconScope({ ...candidate, roster } as SetupBeaconScope)).toThrow(
      new RangeError("Setup beacon roster must contain three through eight identities"),
    );
    expect(getter).not.toHaveBeenCalled();
  });

  it.each([0, 1, 2])("rejects a sparse roster with missing seat %s", (seat) => {
    const candidate = setupScope();
    Reflect.deleteProperty(candidate.roster, String(seat));

    expect(() => snapshotSetupBeaconScope(candidate)).toThrow(
      new TypeError("Setup beacon roster must be a dense data array"),
    );
  });

  it.each([0, 1, 2])("rejects accessor roster seat %s before invoking it", (seat) => {
    const candidate = setupScope();
    const identity = candidate.roster[seat];
    const getter = vi.fn(() => identity);
    Object.defineProperty(candidate.roster, String(seat), { enumerable: true, get: getter });

    expect(() => snapshotSetupBeaconScope(candidate)).toThrow(
      new TypeError("Setup beacon roster must be a dense data array"),
    );
    expect(getter).not.toHaveBeenCalled();
  });

  it("does not fill a roster hole by invoking an inherited identity getter", () => {
    const candidate = setupScope();
    const getter = vi.fn(() => IDENTITIES[1]);
    const prototype = Object.create(Array.prototype) as object;
    Object.defineProperty(prototype, "1", { get: getter });
    Reflect.deleteProperty(candidate.roster, "1");
    Object.setPrototypeOf(candidate.roster, prototype);

    expect(() => snapshotSetupBeaconScope(candidate)).toThrow(
      new TypeError("Setup beacon roster must be a dense data array"),
    );
    expect(getter).not.toHaveBeenCalled();
  });

  it.each([
    { count: 3, nextLength: 0 },
    { count: 3, nextLength: 8 },
    { count: 8, nextLength: 3 },
  ])("captures proxy roster length $count once despite a later $nextLength", ({ count, nextLength }) => {
    const candidate = setupScope(count, count - 1);
    const expected = [...candidate.roster];
    const readLength = vi.fn().mockReturnValueOnce(count).mockReturnValue(nextLength);
    candidate.roster = new Proxy(candidate.roster, {
      get(target, key, receiver) {
        if (key === "length") { return readLength(); }
        return Reflect.get(target, key, receiver);
      },
    });

    const snapshot = snapshotSetupBeaconScope(candidate);

    expect(readLength).toHaveBeenCalledTimes(1);
    expect(snapshot.roster).toEqual(expected);
    expect(snapshot.sender).toEqual(expected[count - 1]);
  });

  it.each([0, 2, 9, -0, -1, 3.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, "3", 3n, undefined])(
    "rejects invalid proxy roster count %# before inspecting entries",
    (count) => {
      const candidate = setupScope();
      const readLength = vi.fn().mockReturnValueOnce(count).mockReturnValue(3);
      const inspectSeat = vi.fn(Reflect.getOwnPropertyDescriptor);
      candidate.roster = new Proxy(candidate.roster, {
        get(target, key, receiver) {
          if (key === "length") { return readLength(); }
          return Reflect.get(target, key, receiver);
        },
        getOwnPropertyDescriptor(target, key) {
          return inspectSeat(target, key);
        },
      });

      expect(() => snapshotSetupBeaconScope(candidate)).toThrow(
        new RangeError("Setup beacon roster must contain three through eight identities"),
      );
      expect(readLength).toHaveBeenCalledTimes(1);
      expect(inspectSeat).not.toHaveBeenCalled();
    },
  );

  it("rejects duplicate identities by bytes, not object identity", () => {
    const candidate = setupScope();
    candidate.roster[2] = parseIdentityPublicKey(candidate.roster[0]);

    expect(candidate.roster[2]).not.toBe(candidate.roster[0]);
    expect(() => snapshotSetupBeaconScope(candidate)).toThrow(
      new TypeError("Setup beacon roster cannot repeat identities"),
    );
  });

  it.each([
    ["small-order zero", "00".repeat(32)],
    ["identity point", "01" + "00".repeat(31)],
    ["non-canonical point", "ed" + "ff".repeat(30) + "7f"],
    ["invalid point", "ff".repeat(32)],
  ])("rejects Ed25519 %s even after an earlier valid sender", (_label, hex) => {
    const candidate = setupScope();
    candidate.roster[2] = parseIdentityPublicKey(hexToBytes(hex));

    expect(() => snapshotSetupBeaconScope(candidate)).toThrow(
      new TypeError("Ed25519 public key is not a strict, prime-subgroup RFC 8032 point encoding"),
    );
  });

  it.each([undefined, null, new Uint8Array(31), new Uint8Array(33)])(
    "rejects malformed roster entry %#",
    (identity) => {
      const candidate = setupScope();
      const roster = [candidate.roster[0], candidate.roster[1], identity];

      expect(() => snapshotSetupBeaconScope({ ...candidate, roster } as SetupBeaconScope)).toThrow(
        ProtocolFieldError,
      );
    },
  );

  it("rejects a valid foreign sender and an invalid Ed25519 sender", () => {
    const candidate = setupScope();
    for (const sender of [IDENTITIES[8]!, parseIdentityPublicKey(new Uint8Array(32))]) {
      expect(() => snapshotSetupBeaconScope({ ...candidate, sender })).toThrow(
        new TypeError("Setup beacon sender must belong to the roster"),
      );
    }
  });

  it("keeps the scope local without adding a v1 wire message or beacon body fields", () => {
    const snapshot = snapshotSetupBeaconScope(setupScope());

    expect(Reflect.ownKeys(snapshot)).toEqual(SCOPE_FIELDS);
    expect(ENVELOPE_VERSION).toBe(1);
    expect(ENVELOPE_MESSAGE_TYPES).toEqual([
      "JOIN", "ROSTER", "READY", "KEY_SHARE", "RAND_COMMIT", "RAND_REVEAL", "SHUFFLE",
      "SHARES", "ACTION", "AUDIT_DISCLOSE", "WITNESS", "SYNC_REQ", "SYNC_RESP", "TIMEOUT_VOTE",
      "VIOLATION",
    ]);
    expect(bytesToHex(encodeCanonical(encodeRandCommitBody({
      cm: parseHash256(new Uint8Array(32).fill(0x11)),
    })))).toBe("a162636d5820" + "11".repeat(32));
    expect(bytesToHex(encodeCanonical(encodeRandRevealBody({
      s: parseRandomSecret(new Uint8Array(32).fill(0x22)),
    })))).toBe("a161735820" + "22".repeat(32));
  });
});
