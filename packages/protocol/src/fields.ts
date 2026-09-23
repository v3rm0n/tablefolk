import { decodeRistrettoScalar, RistrettoPoint } from "@p2pcards/crypto";

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
const typedArrayLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, "length")!.get!;
const typedArrayByteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteLength")!.get!;

declare const protocolFieldBrand: unique symbol;

export type FixedBytes<Size extends number, Name extends string> = Uint8Array & {
  readonly [protocolFieldBrand]: {
    readonly name: Name;
    readonly size: Size;
  };
};

export type GameId = FixedBytes<16, "game_id">;
export type IdentityPublicKey = FixedBytes<32, "identity_public_key">;
export type Hash256 = FixedBytes<32, "sha256_digest">;
export type DtlsFingerprint = FixedBytes<32, "dtls_sha256_fingerprint">;
export type EncodedRistrettoPoint = FixedBytes<32, "ristretto255_point">;
export type EncodedScalar = FixedBytes<32, "ristretto255_scalar">;
export type RandomSecret = FixedBytes<32, "random_secret">;
export type Ed25519Signature = FixedBytes<64, "ed25519_signature">;

export class ProtocolFieldError extends Error {
  readonly field: string;

  constructor(field: string, message: string, options?: ErrorOptions) {
    super(`${field}: ${message}`, options);
    this.name = "ProtocolFieldError";
    this.field = field;
  }
}

export function parseGameId(value: unknown): GameId {
  return parseFixedBytes(value, 16, "game_id");
}

export function parseIdentityPublicKey(value: unknown): IdentityPublicKey {
  return parseFixedBytes(value, 32, "identity_public_key");
}

export function parseHash256(value: unknown): Hash256 {
  return parseFixedBytes(value, 32, "sha256_digest");
}

export function parseDtlsFingerprint(value: unknown): DtlsFingerprint {
  return parseFixedBytes(value, 32, "dtls_sha256_fingerprint");
}

export function parseRistrettoPointEncoding(value: unknown): EncodedRistrettoPoint {
  const encoded = parseFixedBytes(value, 32, "ristretto255_point");
  try {
    RistrettoPoint.fromBytes(encoded);
  } catch (cause) {
    throw new ProtocolFieldError("ristretto255_point", "is not a valid canonical encoding", {
      cause,
    });
  }
  return encoded;
}

export function parseScalarEncoding(value: unknown): EncodedScalar {
  const encoded = parseFixedBytes(value, 32, "ristretto255_scalar");
  try {
    decodeRistrettoScalar(encoded);
  } catch (cause) {
    throw new ProtocolFieldError("ristretto255_scalar", "is not a valid canonical encoding", {
      cause,
    });
  }
  return encoded;
}

export function parseRandomSecret(value: unknown): RandomSecret {
  return parseFixedBytes(value, 32, "random_secret");
}

export function parseEd25519Signature(value: unknown): Ed25519Signature {
  return parseFixedBytes(value, 64, "ed25519_signature");
}

function parseFixedBytes<Size extends number, Name extends string>(
  value: unknown,
  size: Size,
  name: Name,
): FixedBytes<Size, Name> {
  if (!(value instanceof Uint8Array) || value.constructor !== Uint8Array) {
    throw new ProtocolFieldError(name, "must be a Uint8Array");
  }
  let length: number;
  try {
    length = typedArrayLength.call(value) as number;
    if (typedArrayByteLength.call(value) !== length) { throw new TypeError("Expected byte elements"); }
  } catch (cause) { throw new ProtocolFieldError(name, "must be a Uint8Array", { cause }); }
  if (length !== size) {
    throw new ProtocolFieldError(name, `must contain exactly ${size} bytes; got ${length}`);
  }

  // Dependency-owned views can override length or slice; fixed fields always get a bounded, private copy.
  const bytes = new Uint8Array(size);
  bytes.set(value);
  return bytes as FixedBytes<Size, Name>;
}
