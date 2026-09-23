import { sha256 as nobleSha256, sha512 as nobleSha512 } from "@noble/hashes/sha2.js";

declare const digestBrand: unique symbol;

export type Sha256Digest = Uint8Array & { readonly [digestBrand]: "SHA-256" };
export type Sha512Digest = Uint8Array & { readonly [digestBrand]: "SHA-512" };

export function sha256(...parts: readonly Uint8Array[]): Sha256Digest {
  const hash = nobleSha256.create();
  for (const part of parts) {
    assertByteArray(part);
    hash.update(part);
  }
  return hash.digest() as Sha256Digest;
}

export function sha512(...parts: readonly Uint8Array[]): Sha512Digest {
  const hash = nobleSha512.create();
  for (const part of parts) {
    assertByteArray(part);
    hash.update(part);
  }
  return hash.digest() as Sha512Digest;
}

function assertByteArray(value: unknown): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError("Hash inputs must be Uint8Array values");
  }
}
