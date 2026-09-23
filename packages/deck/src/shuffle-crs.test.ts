/// <reference types="node" />

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { bytesToHex, hexToBytes, RistrettoPoint } from "@p2pcards/crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

import { deriveShuffleCrs36, SHUFFLE_CRS_36_PROFILE } from "./shuffle-crs";

const vectors = JSON.parse(readFileSync(
  new URL("../test-vectors/shuffle-crs-36.json", import.meta.url), "utf8",
)) as { role: string; index: number; input: string; digest: string; point: string }[];

afterEach(() => vi.restoreAllMocks());

describe("candidate 36-card shuffle CRS", () => {
  it("matches every framed hash and compressed-point regression vector", () => {
    const map = vi.spyOn(RistrettoPoint, "fromUniformBytes");
    const crs = deriveShuffleCrs36();
    const points = [crs.proofGenerator, crs.blindingGenerator, ...crs.messageGenerators];
    expect(points).toHaveLength(11);
    expect(map).toHaveBeenCalledTimes(11);
    vectors.forEach((vector, i) => {
      // Node's SHA-512 independently checks the stored framing/digest pair.
      expect(createHash("sha512").update(hexToBytes(vector.input)).digest("hex"))
        .toBe(vector.digest);
      expect(bytesToHex(map.mock.calls[i]![0])).toBe(vector.digest);
      expect(bytesToHex(points[i]!.toBytes())).toBe(vector.point);
    });
    expect(crs.profile).toBe(SHUFFLE_CRS_36_PROFILE);
    expect([crs.rows, crs.columns]).toEqual([4, 9]);
    expect(crs.encryptionGenerator.equals(RistrettoPoint.base())).toBe(true);
  });

  it("returns detached immutable parameters and distinct nonidentity bases", () => {
    const first = deriveShuffleCrs36();
    const second = deriveShuffleCrs36();
    expect(first).not.toBe(second);
    expect(first.messageGenerators).not.toBe(second.messageGenerators);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.messageGenerators)).toBe(true);
    const points = [first.encryptionGenerator, first.proofGenerator,
      first.blindingGenerator, ...first.messageGenerators];
    for (const [i, point] of points.entries()) {
      expect(point.isIdentity()).toBe(false);
      for (const earlier of points.slice(0, i)) {
        expect(point.equals(earlier)).toBe(false);
        expect(point.equals(earlier.negate())).toBe(false);
      }
    }
    first.messageGenerators[0]!.toBytes().fill(0);
    expect(first.messageGenerators[0]!.equals(second.messageGenerators[0]!)).toBe(true);
  });

  it.each(["identity", "base", "negative base", "repeated", "negative repeated"])(
    "fails closed on a %s derived point without retries", (kind) => {
      const original = RistrettoPoint.fromUniformBytes;
      const valid = original(hexToBytes(vectors[0]!.digest));
      const map = vi.spyOn(RistrettoPoint, "fromUniformBytes");
      if (kind === "repeated" || kind === "negative repeated") {
        map.mockReturnValueOnce(valid).mockReturnValueOnce(
          kind === "repeated" ? valid : valid.negate(),
        );
      } else {
        map.mockReturnValueOnce(kind === "identity" ? RistrettoPoint.identity()
          : kind === "base" ? RistrettoPoint.base() : RistrettoPoint.base().negate());
      }
      expect(() => deriveShuffleCrs36()).toThrow(/profile revision required/);
      expect(map).toHaveBeenCalledTimes(kind.includes("repeated") ? 2 : 1);
    },
  );

  it("propagates mapping failures without returning partial parameters", () => {
    vi.spyOn(RistrettoPoint, "fromUniformBytes").mockImplementation(() => {
      throw new Error("mapping unavailable");
    });
    expect(() => deriveShuffleCrs36()).toThrow("mapping unavailable");
  });
});
