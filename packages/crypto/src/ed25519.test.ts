import { describe, expect, it } from "vitest";

import { bytesToHex, hexToBytes } from "./bytes";
import {
  deriveEd25519PublicKey,
  generateEd25519KeyPair,
  importEd25519PublicKey,
  importEd25519SecretKey,
  signEd25519,
  verifyEd25519,
} from "./ed25519";
import type { RandomSource } from "./random";

const RFC_8032_VECTORS = [
  {
    secretKey: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    publicKey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    message: "",
    signature:
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901" +
      "555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  },
  {
    secretKey: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    publicKey: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    message: "72",
    signature:
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
      "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  },
] as const;

describe("Ed25519 identity operations", () => {
  it.each(RFC_8032_VECTORS)(
    "matches RFC 8032 signing vector %#",
    ({ secretKey, publicKey, message, signature }) => {
      const secret = importEd25519SecretKey(hexToBytes(secretKey));
      const publicBytes = importEd25519PublicKey(hexToBytes(publicKey));
      const messageBytes = hexToBytes(message);

      expect(bytesToHex(deriveEd25519PublicKey(secret))).toBe(publicKey);
      expect(bytesToHex(signEd25519(messageBytes, secret))).toBe(signature);
      expect(verifyEd25519(hexToBytes(signature), messageBytes, publicBytes)).toBe(true);
    },
  );

  it("generates a deterministic pair through an injected random source", () => {
    const seed = hexToBytes(RFC_8032_VECTORS[0].secretKey);
    const source: RandomSource = {
      fill(target) {
        target.set(seed);
      },
    };

    const pair = generateEd25519KeyPair(source);

    expect(bytesToHex(pair.secretKey)).toBe(RFC_8032_VECTORS[0].secretKey);
    expect(bytesToHex(pair.publicKey)).toBe(RFC_8032_VECTORS[0].publicKey);
  });

  it("copies imported secret and public key bytes", () => {
    const sourceSecret = hexToBytes(RFC_8032_VECTORS[0].secretKey);
    const sourcePublic = hexToBytes(RFC_8032_VECTORS[0].publicKey);
    const secret = importEd25519SecretKey(sourceSecret);
    const publicKey = importEd25519PublicKey(sourcePublic);

    sourceSecret.fill(0);
    sourcePublic.fill(0);

    expect(bytesToHex(secret)).toBe(RFC_8032_VECTORS[0].secretKey);
    expect(bytesToHex(publicKey)).toBe(RFC_8032_VECTORS[0].publicKey);
  });

  it("returns false for tampered or malformed untrusted inputs", () => {
    const vector = RFC_8032_VECTORS[0];
    const signature = hexToBytes(vector.signature);
    signature[0] = signature[0]! ^ 1;

    expect(verifyEd25519(signature, hexToBytes(vector.message), hexToBytes(vector.publicKey))).toBe(
      false,
    );
    expect(verifyEd25519(new Uint8Array(63), new Uint8Array(), hexToBytes(vector.publicKey))).toBe(
      false,
    );
    expect(verifyEd25519(new Uint8Array(64), new Uint8Array(), new Uint8Array(31))).toBe(
      false,
    );
    expect(verifyEd25519(new Uint8Array(64), new Uint8Array(), new Uint8Array(32))).toBe(
      false,
    );
  });

  it("rejects malformed imported key material", () => {
    expect(() => importEd25519SecretKey(new Uint8Array(31))).toThrow(RangeError);
    expect(() => importEd25519PublicKey(new Uint8Array(32))).toThrow(TypeError);
  });
});
