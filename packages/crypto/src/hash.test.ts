import { describe, expect, it } from "vitest";

import { asciiToBytes, bytesToHex } from "./bytes";
import { sha256, sha512 } from "./hash";

describe("SHA-2", () => {
  it.each([
    ["", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    ["abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
  ])("matches the SHA-256 known-answer vector for %j", (input, expected) => {
    expect(bytesToHex(sha256(asciiToBytes(input)))).toBe(expected);
  });

  it.each([
    [
      "",
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    ],
    [
      "abc",
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ],
  ])("matches the SHA-512 known-answer vector for %j", (input, expected) => {
    expect(bytesToHex(sha512(asciiToBytes(input)))).toBe(expected);
  });

  it("hashes multiple parts as one unframed byte sequence", () => {
    expect(sha256(asciiToBytes("a"), asciiToBytes("bc"))).toEqual(
      sha256(asciiToBytes("abc")),
    );
  });

  it("rejects non-byte inputs at runtime", () => {
    expect(() => sha256("abc" as unknown as Uint8Array)).toThrow(TypeError);
  });
});
