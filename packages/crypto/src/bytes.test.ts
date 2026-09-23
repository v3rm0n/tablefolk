import { describe, expect, it } from "vitest";

import { asciiToBytes, bytesEqual, bytesToHex, concatBytes, hexToBytes } from "./bytes";

describe("byte utilities", () => {
  it("concatenates byte arrays without aliasing the inputs", () => {
    const first = new Uint8Array([1, 2]);
    const second = new Uint8Array([3]);
    const result = concatBytes(first, second);

    first[0] = 9;
    second[0] = 9;

    expect(result).toEqual(new Uint8Array([1, 2, 3]));
  });

  it("encodes the protocol domain character set as ASCII", () => {
    expect(bytesToHex(asciiToBytes("p2pcards/v1/msg"))).toBe(
      "70327063617264732f76312f6d7367",
    );
  });

  it("rejects non-ASCII domain input", () => {
    expect(() => asciiToBytes("p2pcards/\u00e4")).toThrow(TypeError);
  });

  it("strictly converts hexadecimal bytes", () => {
    expect(hexToBytes("00aF10")).toEqual(new Uint8Array([0, 175, 16]));
    expect(() => hexToBytes("abc")).toThrow(TypeError);
    expect(() => hexToBytes("zz")).toThrow(TypeError);
  });

  it("compares equal-length byte arrays", () => {
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(bytesEqual(new Uint8Array([1]), new Uint8Array([1, 0]))).toBe(false);
  });
});
