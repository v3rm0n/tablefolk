import {
  asciiToBytes,
  bytesToHex,
  hexToBytes,
  importEd25519SecretKey,
} from "@p2pcards/crypto";
import { decodeCanonical, encodeCanonical, type CborMap } from "@p2pcards/encoding";
import { describe, expect, it } from "vitest";

import { parseDtlsFingerprint, parseGameId } from "./fields";
import {
  decodeAndVerifyHello,
  HelloValidationError,
  MAX_HELLO_BYTES,
  signHello,
} from "./hello";

const SECRET_KEY = importEd25519SecretKey(
  hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
);
const PUBLIC_KEY_HEX =
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const GAME_ID = parseGameId(hexToBytes("000102030405060708090a0b0c0d0e0f"));
const LOCAL_FP = parseDtlsFingerprint(new Uint8Array(32).fill(0x11));
const REMOTE_FP = parseDtlsFingerprint(new Uint8Array(32).fill(0x22));
const SIGNATURE_HEX =
  "e9c7d62009ae81449a8c18010995f6843e3b59968176ed9ed6c07f3a7e5f70d" +
  "eb3c453ff2e44f4f7b01eb8f525182cd1c719b710145c92e594fa0df1e4e3f407";

describe("signed channel HELLO", () => {
  it("matches an independently signed canonical fixture", () => {
    const artifact = signHello(GAME_ID, LOCAL_FP, REMOTE_FP, SECRET_KEY);

    expect(bytesToHex(artifact.hello.pkId)).toBe(PUBLIC_KEY_HEX);
    expect(bytesToHex(artifact.hello.signature)).toBe(SIGNATURE_HEX);
    expect(bytesToHex(artifact.canonicalBytes)).toBe(
      "a4" +
        "637369675840" +
        SIGNATURE_HEX +
        "65706b5f69645820" +
        PUBLIC_KEY_HEX +
        "686c6f63616c5f66705820" +
        "11".repeat(32) +
        "6972656d6f74655f66705820" +
        "22".repeat(32),
    );
    expect(decodeAndVerifyHello(artifact.canonicalBytes, GAME_ID)).toEqual(artifact);
  });

  it("copies fingerprints and encoded bytes at both trust boundaries", () => {
    const local = parseDtlsFingerprint(LOCAL_FP);
    const remote = parseDtlsFingerprint(REMOTE_FP);
    const artifact = signHello(GAME_ID, local, remote, SECRET_KEY);
    local.fill(0xff);
    remote.fill(0xff);
    expect(artifact.hello.localFingerprint).toEqual(LOCAL_FP);
    expect(artifact.hello.remoteFingerprint).toEqual(REMOTE_FP);

    const encoded = artifact.canonicalBytes.slice();
    const verified = decodeAndVerifyHello(encoded, GAME_ID);
    encoded.fill(0xff);
    expect(verified.canonicalBytes).toEqual(artifact.canonicalBytes);
    expect(verified.hello.localFingerprint).toEqual(LOCAL_FP);
  });

  it("rejects the wrong game, swapped fingerprints, and signature corruption", () => {
    const artifact = signHello(GAME_ID, LOCAL_FP, REMOTE_FP, SECRET_KEY);
    const wrongGame = parseGameId(new Uint8Array(16).fill(1));
    expect(() => decodeAndVerifyHello(artifact.canonicalBytes, wrongGame)).toThrowError(
      expect.objectContaining({ code: "INVALID_SIGNATURE" }),
    );

    const decoded = decodeCanonical(artifact.canonicalBytes) as CborMap;
    expect(() =>
      decodeAndVerifyHello(
        encodeCanonical({
          ...decoded,
          local_fp: decoded["remote_fp"]!,
          remote_fp: decoded["local_fp"]!,
        }),
        GAME_ID,
      ),
    ).toThrowError(expect.objectContaining({ code: "INVALID_SIGNATURE" }));
    const signature = (decoded["sig"] as Uint8Array).slice();
    signature[0] = signature[0]! ^ 1;
    expect(() =>
      decodeAndVerifyHello(encodeCanonical({ ...decoded, sig: signature }), GAME_ID),
    ).toThrowError(expect.objectContaining({ code: "INVALID_SIGNATURE" }));
  });

  it("rejects extension fields, malformed lengths, non-canonical bytes, and oversized input", () => {
    const artifact = signHello(GAME_ID, LOCAL_FP, REMOTE_FP, SECRET_KEY);
    const decoded = decodeCanonical(artifact.canonicalBytes) as CborMap;
    expect(() =>
      decodeAndVerifyHello(encodeCanonical({ ...decoded, extra: true }), GAME_ID),
    ).toThrow(HelloValidationError);
    expect(() =>
      decodeAndVerifyHello(
        encodeCanonical({ ...decoded, local_fp: new Uint8Array(31) }),
        GAME_ID,
      ),
    ).toThrowError(expect.objectContaining({ code: "MALFORMED_HELLO" }));

    const nonCanonical = new Uint8Array([
      0xa4,
      0x65,
      ...asciiToBytes("pk_id"),
      0x58,
      0x20,
      ...artifact.hello.pkId,
      0x63,
      ...asciiToBytes("sig"),
      0x58,
      0x40,
      ...artifact.hello.signature,
      0x68,
      ...asciiToBytes("local_fp"),
      0x58,
      0x20,
      ...artifact.hello.localFingerprint,
      0x69,
      ...asciiToBytes("remote_fp"),
      0x58,
      0x20,
      ...artifact.hello.remoteFingerprint,
    ]);
    expect(() => decodeAndVerifyHello(nonCanonical, GAME_ID)).toThrowError(
      expect.objectContaining({ code: "MALFORMED_HELLO" }),
    );
    expect(() =>
      decodeAndVerifyHello(new Uint8Array(MAX_HELLO_BYTES + 1), GAME_ID),
    ).toThrowError(expect.objectContaining({ code: "MALFORMED_HELLO" }));
  });
});
