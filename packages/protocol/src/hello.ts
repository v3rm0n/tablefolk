import {
  deriveEd25519PublicKey,
  signEd25519,
  verifyEd25519,
  type Ed25519SecretKey,
} from "@p2pcards/crypto";
import {
  decodeCanonical,
  encodeCanonical,
  type CanonicalCbor,
  type CborMap,
  type CborValue,
} from "@p2pcards/encoding";

import {
  parseDtlsFingerprint,
  parseEd25519Signature,
  parseGameId,
  parseIdentityPublicKey,
  type DtlsFingerprint,
  type Ed25519Signature,
  type GameId,
  type IdentityPublicKey,
} from "./fields";
import { channelAuthenticationInput } from "./hash-inputs";
import { expectByteString, expectExactMap } from "./schema";

export const MAX_HELLO_BYTES = 256;

export interface SignedHello {
  readonly pkId: IdentityPublicKey;
  readonly localFingerprint: DtlsFingerprint;
  readonly remoteFingerprint: DtlsFingerprint;
  readonly signature: Ed25519Signature;
}

declare const helloArtifactBrand: unique symbol;

export interface HelloArtifact {
  readonly [helloArtifactBrand]: true;
  readonly hello: SignedHello;
  readonly canonicalBytes: CanonicalCbor;
}

export type HelloValidationErrorCode =
  | "INVALID_SIGNATURE"
  | "MALFORMED_HELLO";

export class HelloValidationError extends Error {
  readonly code: HelloValidationErrorCode;

  constructor(code: HelloValidationErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "HelloValidationError";
    this.code = code;
  }
}

const HELLO_KEYS = ["pk_id", "local_fp", "remote_fp", "sig"] as const;

export function signHello(
  gameId: GameId,
  localFingerprint: DtlsFingerprint,
  remoteFingerprint: DtlsFingerprint,
  secretKey: Ed25519SecretKey,
): HelloArtifact {
  const game = parseGameId(gameId);
  const local = parseDtlsFingerprint(localFingerprint);
  const remote = parseDtlsFingerprint(remoteFingerprint);
  const pkId = parseIdentityPublicKey(deriveEd25519PublicKey(secretKey));
  const signature = parseEd25519Signature(
    signEd25519(channelAuthenticationInput(game, local, remote), secretKey),
  );
  return createArtifact({
    pkId,
    localFingerprint: local,
    remoteFingerprint: remote,
    signature,
  });
}

export function decodeAndVerifyHello(
  encoded: Uint8Array,
  gameId: GameId,
): HelloArtifact {
  let hello: SignedHello;
  try {
    requireEncodedHello(encoded);
    hello = parseHello(decodeCanonical(encoded));
  } catch (cause) {
    if (cause instanceof HelloValidationError) {
      throw cause;
    }
    throw new HelloValidationError("MALFORMED_HELLO", "HELLO decoding failed", {
      cause,
    });
  }

  const game = parseGameId(gameId);
  if (
    !verifyEd25519(
      hello.signature,
      channelAuthenticationInput(
        game,
        hello.localFingerprint,
        hello.remoteFingerprint,
      ),
      hello.pkId,
    )
  ) {
    throw new HelloValidationError("INVALID_SIGNATURE", "HELLO signature is invalid");
  }
  return createArtifact(hello);
}

function parseHello(value: CborValue): SignedHello {
  const hello = expectExactMap(value, HELLO_KEYS, "HELLO");
  return Object.freeze({
    pkId: parseHelloField(
      hello,
      "pk_id",
      "must be a 32-byte identity public key",
      parseIdentityPublicKey,
    ),
    localFingerprint: parseHelloField(
      hello,
      "local_fp",
      "must be a 32-byte SHA-256 fingerprint",
      parseDtlsFingerprint,
    ),
    remoteFingerprint: parseHelloField(
      hello,
      "remote_fp",
      "must be a 32-byte SHA-256 fingerprint",
      parseDtlsFingerprint,
    ),
    signature: parseHelloField(
      hello,
      "sig",
      "must be a 64-byte Ed25519 signature",
      parseEd25519Signature,
    ),
  });
}

function createArtifact(hello: SignedHello): HelloArtifact {
  const snapshot = parseHello(toHelloValue(hello));
  return Object.freeze({
    hello: snapshot,
    canonicalBytes: encodeCanonical(toHelloValue(snapshot)),
  }) as HelloArtifact;
}

function toHelloValue(hello: SignedHello): CborMap {
  return {
    pk_id: hello.pkId,
    local_fp: hello.localFingerprint,
    remote_fp: hello.remoteFingerprint,
    sig: hello.signature,
  };
}

function parseHelloField<T>(
  hello: CborMap,
  field: (typeof HELLO_KEYS)[number],
  message: string,
  parse: (value: Uint8Array) => T,
): T {
  try {
    return parse(expectByteString(hello[field]!, `HELLO.${field}`));
  } catch (cause) {
    throw new HelloValidationError("MALFORMED_HELLO", `HELLO.${field} ${message}`, {
      cause,
    });
  }
}

function requireEncodedHello(value: Uint8Array): void {
  if (!(value instanceof Uint8Array) || value.constructor !== Uint8Array) {
    throw new TypeError("HELLO must be encoded as a Uint8Array");
  }
  if (value.length > MAX_HELLO_BYTES) {
    throw new RangeError(`HELLO must encode to at most ${MAX_HELLO_BYTES} bytes`);
  }
}
