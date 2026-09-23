import { bytesToHex, hexToBytes } from "@p2pcards/crypto";
import { decodeCanonical, encodeCanonical } from "@p2pcards/encoding";
import { describe, expect, it } from "vitest";

import {
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  type IdentityPublicKey,
} from "./fields";
import {
  decodeJoinBody,
  decodeReadyBody,
  decodeRosterBody,
  encodeJoinBody,
  encodeReadyBody,
  encodeRosterBody,
  hashRosterBody,
  type RosterBody,
} from "./lobby";
import { ProtocolSchemaError } from "./schema";

const GAME_ID = parseGameId(hexToBytes("000102030405060708090a0b0c0d0e0f"));
const RULES_HASH = parseHash256(new Uint8Array(32).fill(0xaa));
const ICE_CONFIG_HASH = parseHash256(new Uint8Array(32).fill(0xbb));
const IDENTITIES = [1, 2, 3].map(identity);

describe("lobby body codecs", () => {
  it("round-trips JOIN and matches its canonical byte fixture", () => {
    const body = {
      pkId: IDENTITIES[0]!,
      rulesHash: RULES_HASH,
      clientVersion: "1.2.3",
    };
    const encoded = encodeCanonical(encodeJoinBody(body));

    expect(bytesToHex(encoded)).toBe(
      "a365706b5f69645820" +
        "01".repeat(32) +
        "6a72756c65735f686173685820" +
        "aa".repeat(32) +
        "6e636c69656e745f76657273696f6e65312e322e33",
    );
    expect(decodeJoinBody(decodeCanonical(encoded))).toEqual(body);
  });

  it("round-trips ROSTER and fixes its canonical hash", () => {
    const body = rosterBody();
    const encoded = encodeCanonical(encodeRosterBody(body));

    expect(bytesToHex(encoded)).toBe(
      "a4657365617473835820" +
        "01".repeat(32) +
        "5820" +
        "02".repeat(32) +
        "5820" +
        "03".repeat(32) +
        "6767616d655f696450000102030405060708090a0b0c0d0e0f" +
        "6a72756c65735f686173685820" +
        "aa".repeat(32) +
        "6f6963655f636f6e6669675f686173685820" +
        "bb".repeat(32),
    );
    expect(bytesToHex(hashRosterBody(body))).toBe(
      "7056c77db5b915537a748dcd0d809bdcbfcdfb4241aa043fe6441e1c620566d7",
    );
    expect(decodeRosterBody(decodeCanonical(encoded))).toEqual(body);
  });

  it("round-trips READY and binds it to the canonical roster body", () => {
    const rosterHash = hashRosterBody(rosterBody());
    const encoded = encodeCanonical(encodeReadyBody({ rosterHash }));

    expect(bytesToHex(encoded)).toBe(
      "a16b726f737465725f686173685820" +
        "7056c77db5b915537a748dcd0d809bdcbfcdfb4241aa043fe6441e1c620566d7",
    );
    expect(decodeReadyBody(decodeCanonical(encoded))).toEqual({ rosterHash });
    expect(bytesToHex(hashRosterBody({ ...rosterBody(), seats: [...IDENTITIES].reverse() }))).not.toBe(
      bytesToHex(rosterHash),
    );
  });

  it("rejects extension fields, malformed byte fields, and empty client versions", () => {
    expect(() =>
      decodeJoinBody({
        pk_id: new Uint8Array(32),
        rules_hash: new Uint8Array(32),
        client_version: "1",
        extra: true,
      }),
    ).toThrow(ProtocolSchemaError);
    expect(() =>
      decodeJoinBody({
        pk_id: new Uint8Array(31),
        rules_hash: new Uint8Array(32),
        client_version: "1",
      }),
    ).toThrow(ProtocolSchemaError);
    expect(() =>
      decodeJoinBody({
        pk_id: new Uint8Array(32),
        rules_hash: new Uint8Array(31),
        client_version: "1",
      }),
    ).toThrow(ProtocolSchemaError);
    expect(() =>
      decodeJoinBody({
        pk_id: new Uint8Array(32),
        rules_hash: new Uint8Array(32),
        client_version: "",
      }),
    ).toThrow(ProtocolSchemaError);
    expect(() => decodeReadyBody({ roster_hash: new Uint8Array(31) })).toThrow(
      ProtocolSchemaError,
    );
  });

  it("allows intermediate one-seat rosters but rejects empty, oversized, and duplicate rosters", () => {
    expect(decodeRosterBody(encodeRosterBody({ ...rosterBody(), seats: [IDENTITIES[0]!] })).seats).toHaveLength(
      1,
    );
    expect(
      decodeRosterBody(
        encodeRosterBody({
          ...rosterBody(),
          seats: Array.from({ length: 8 }, (_, index) => identity(index + 1)),
        }),
      ).seats,
    ).toHaveLength(8);

    expect(() => encodeRosterBody({ ...rosterBody(), seats: [] })).toThrow(ProtocolSchemaError);
    expect(() =>
      encodeRosterBody({
        ...rosterBody(),
        seats: Array.from({ length: 9 }, (_, index) => identity(index + 1)),
      }),
    ).toThrow(ProtocolSchemaError);
    expect(() =>
      encodeRosterBody({ ...rosterBody(), seats: [IDENTITIES[0]!, IDENTITIES[0]!] }),
    ).toThrow(ProtocolSchemaError);
  });

  it("copies mutable byte fields at both codec boundaries", () => {
    const source = rosterBody();
    const encoded = encodeRosterBody(source);
    source.gameId.fill(0xff);
    source.rulesHash.fill(0xff);
    source.iceConfigHash.fill(0xff);
    source.seats[0]!.fill(0xff);

    const decoded = decodeRosterBody(encoded);
    const stable = encodeCanonical(encodeRosterBody(decoded));
    (encoded["game_id"] as Uint8Array).fill(0xee);
    (encoded["rules_hash"] as Uint8Array).fill(0xee);
    (encoded["ice_config_hash"] as Uint8Array).fill(0xee);
    (encoded["seats"] as Uint8Array[])[0]!.fill(0xee);

    expect(encodeCanonical(encodeRosterBody(decoded))).toEqual(stable);
  });
});

function identity(value: number): IdentityPublicKey {
  return parseIdentityPublicKey(new Uint8Array(32).fill(value));
}

function rosterBody(): RosterBody {
  return {
    gameId: parseGameId(GAME_ID),
    rulesHash: parseHash256(RULES_HASH),
    iceConfigHash: parseHash256(ICE_CONFIG_HASH),
    seats: IDENTITIES.map(parseIdentityPublicKey),
  };
}
