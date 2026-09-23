import { describe, expect, it } from "vitest";

import {
  expectArray,
  expectByteString,
  expectExactMap,
  expectNonEmptyText,
  expectUnsignedInteger,
  ProtocolSchemaError,
} from "./schema";

describe("protocol schema guards", () => {
  it("accepts exact maps without depending on insertion order", () => {
    expect(expectExactMap({ b: 2, a: 1 }, ["a", "b"], "value")).toEqual({ b: 2, a: 1 });
  });

  it("rejects missing, additional, and non-map values", () => {
    expect(() => expectExactMap({ a: 1 }, ["a", "b"], "value")).toThrow(
      ProtocolSchemaError,
    );
    expect(() => expectExactMap({ a: 1, b: 2 }, ["a"], "value")).toThrow(
      ProtocolSchemaError,
    );
    expect(() => expectExactMap([], [], "value")).toThrow(ProtocolSchemaError);
  });

  it("validates arrays, byte strings, text, and bounded unsigned integers", () => {
    expect(expectArray([1], "items")).toEqual([1]);
    expect(expectByteString(new Uint8Array([1]), "bytes")).toEqual(new Uint8Array([1]));
    expect(expectNonEmptyText("phase", "phase")).toBe("phase");
    expect(expectUnsignedInteger(7, "seat", 7)).toBe(7);

    expect(() => expectArray({}, "items")).toThrow(ProtocolSchemaError);
    expect(() => expectByteString([1], "bytes")).toThrow(ProtocolSchemaError);
    expect(() => expectNonEmptyText("", "phase")).toThrow(ProtocolSchemaError);
    expect(() => expectUnsignedInteger(8, "seat", 7)).toThrow(ProtocolSchemaError);
  });
});
