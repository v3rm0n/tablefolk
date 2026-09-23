import { ed25519 } from "@noble/curves/ed25519.js";

import { randomBytes, type RandomSource } from "./random";

declare const ed25519ValueBrand: unique symbol;

export type Ed25519SecretKey = Uint8Array & {
  readonly [ed25519ValueBrand]: "ed25519_secret_key";
};
export type Ed25519PublicKey = Uint8Array & {
  readonly [ed25519ValueBrand]: "ed25519_public_key";
};
export type Ed25519Signature = Uint8Array & {
  readonly [ed25519ValueBrand]: "ed25519_signature";
};

export interface Ed25519KeyPair {
  readonly secretKey: Ed25519SecretKey;
  readonly publicKey: Ed25519PublicKey;
}

export const ED25519_SECRET_KEY_LENGTH = 32;
export const ED25519_PUBLIC_KEY_LENGTH = 32;
export const ED25519_SIGNATURE_LENGTH = 64;

export function generateEd25519KeyPair(source?: RandomSource): Ed25519KeyPair {
  const secretKey = importEd25519SecretKey(randomBytes(ED25519_SECRET_KEY_LENGTH, source));
  return {
    secretKey,
    publicKey: deriveEd25519PublicKey(secretKey),
  };
}

export function importEd25519SecretKey(value: Uint8Array): Ed25519SecretKey {
  assertPlainBytes(value, "Ed25519 secret key");
  assertLength(value, ED25519_SECRET_KEY_LENGTH, "Ed25519 secret key");
  return value.slice() as Ed25519SecretKey;
}

export function importEd25519PublicKey(value: Uint8Array): Ed25519PublicKey {
  assertPlainBytes(value, "Ed25519 public key");
  assertLength(value, ED25519_PUBLIC_KEY_LENGTH, "Ed25519 public key");

  if (!isAcceptablePublicKey(value)) {
    throw new TypeError(
      "Ed25519 public key is not a strict, prime-subgroup RFC 8032 point encoding",
    );
  }
  return value.slice() as Ed25519PublicKey;
}

export function deriveEd25519PublicKey(secretKey: Ed25519SecretKey): Ed25519PublicKey {
  assertPlainBytes(secretKey, "Ed25519 secret key");
  assertLength(secretKey, ED25519_SECRET_KEY_LENGTH, "Ed25519 secret key");
  return ed25519.getPublicKey(secretKey) as Ed25519PublicKey;
}

export function signEd25519(
  message: Uint8Array,
  secretKey: Ed25519SecretKey,
): Ed25519Signature {
  assertPlainBytes(message, "Ed25519 message");
  assertPlainBytes(secretKey, "Ed25519 secret key");
  assertLength(secretKey, ED25519_SECRET_KEY_LENGTH, "Ed25519 secret key");
  return ed25519.sign(message, secretKey) as Ed25519Signature;
}

export function verifyEd25519(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (
    !isPlainBytes(signature) ||
    signature.length !== ED25519_SIGNATURE_LENGTH ||
    !isPlainBytes(message) ||
    !isPlainBytes(publicKey) ||
    publicKey.length !== ED25519_PUBLIC_KEY_LENGTH ||
    !isAcceptablePublicKey(publicKey)
  ) {
    return false;
  }

  try {
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

function isAcceptablePublicKey(value: Uint8Array): boolean {
  try {
    const point = ed25519.Point.fromBytes(value, false);
    return point.isTorsionFree() && !point.isSmallOrder();
  } catch {
    return false;
  }
}

function assertPlainBytes(value: unknown, label: string): asserts value is Uint8Array {
  if (!isPlainBytes(value)) {
    throw new TypeError(`${label} must be a plain Uint8Array`);
  }
}

function isPlainBytes(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array && value.constructor === Uint8Array;
}

function assertLength(value: Uint8Array, expected: number, label: string): void {
  if (value.length !== expected) {
    throw new RangeError(`${label} must contain exactly ${expected} bytes; got ${value.length}`);
  }
}
