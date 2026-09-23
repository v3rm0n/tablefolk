import { describe, expect, it, vi } from "vitest";

import { randomBytes, randomUint32Below, type RandomSource } from "./random";

describe("random byte boundary", () => {
  it("fills a fresh allocation through an injected source", () => {
    const source: RandomSource = {
      fill(target) {
        for (let index = 0; index < target.length; index += 1) {
          target[index] = index + 1;
        }
      },
    };

    expect(randomBytes(4, source)).toEqual(new Uint8Array([1, 2, 3, 4]));
  });

  it("requests zero bytes without special-casing the source", () => {
    const fill = vi.fn<(target: Uint8Array) => void>();
    expect(randomBytes(0, { fill })).toEqual(new Uint8Array());
    expect(fill).toHaveBeenCalledOnce();
  });

  it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
    "rejects invalid length %s",
    (length) => {
      expect(() => randomBytes(length, { fill() {} })).toThrow(RangeError);
    },
  );

  it("rejects an invalid source", () => {
    expect(() => randomBytes(1, {} as RandomSource)).toThrow(TypeError);
  });

  it("rejection-samples an unbiased uint32 below a bound", () => {
    const source = uint32Source([0xffff_ffff, 17]);
    expect(randomUint32Below(10, source)).toBe(7);
  });

  it("supports the complete uint32 range", () => {
    expect(randomUint32Below(0x1_0000_0000, uint32Source([0xffff_ffff]))).toBe(
      0xffff_ffff,
    );
  });

  it.each([0, -1, 1.5, 0x1_0000_0001])("rejects invalid uint32 bound %s", (bound) => {
    expect(() => randomUint32Below(bound, uint32Source([0]))).toThrow(RangeError);
  });
});

function uint32Source(values: readonly number[]): RandomSource {
  let index = 0;
  return {
    fill(target) {
      const value = values[index];
      if (value === undefined) {
        throw new Error("Test random source exhausted");
      }
      index += 1;
      target[0] = value & 0xff;
      target[1] = (value >>> 8) & 0xff;
      target[2] = (value >>> 16) & 0xff;
      target[3] = (value >>> 24) & 0xff;
    },
  };
}
