import {
  bytesEqual,
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
  parseEd25519Signature,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  type Ed25519Signature,
  type GameId,
  type Hash256,
  type IdentityPublicKey,
} from "./fields";
import { envelopeSignatureInput, hashEnvelope } from "./hash-inputs";

export const ENVELOPE_VERSION = 1;

export const ENVELOPE_MESSAGE_TYPES = Object.freeze([
  "JOIN",
  "ROSTER",
  "READY",
  "KEY_SHARE",
  "RAND_COMMIT",
  "RAND_REVEAL",
  "SHUFFLE",
  "SHARES",
  "ACTION",
  "AUDIT_DISCLOSE",
  "WITNESS",
  "SYNC_REQ",
  "SYNC_RESP",
  "TIMEOUT_VOTE",
  "VIOLATION",
] as const);

export type EnvelopeMessageType = (typeof ENVELOPE_MESSAGE_TYPES)[number];

export interface UnsignedEnvelope {
  readonly v: typeof ENVELOPE_VERSION;
  readonly game: GameId;
  readonly from: IdentityPublicKey;
  readonly seq: number;
  readonly prev: Hash256;
  readonly round: number;
  readonly phase: string;
  readonly type: EnvelopeMessageType;
  readonly body: CborValue;
}

export interface SignedEnvelope extends UnsignedEnvelope {
  readonly sig: Ed25519Signature;
}

declare const envelopeArtifactBrand: unique symbol;

export interface EnvelopeArtifact {
  readonly [envelopeArtifactBrand]: true;
  readonly envelope: SignedEnvelope;
  readonly canonicalBytes: CanonicalCbor;
  readonly hash: Hash256;
}

export type EnvelopeValidationErrorCode =
  | "INVALID_SIGNATURE"
  | "MALFORMED_ENVELOPE"
  | "SENDER_KEY_MISMATCH"
  | "UNSUPPORTED_VERSION";

export class EnvelopeValidationError extends Error {
  readonly code: EnvelopeValidationErrorCode;

  constructor(code: EnvelopeValidationErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "EnvelopeValidationError";
    this.code = code;
  }
}

const UNSIGNED_KEYS = Object.freeze([
  "v",
  "game",
  "from",
  "seq",
  "prev",
  "round",
  "phase",
  "type",
  "body",
] as const);

const SIGNED_KEYS = Object.freeze([...UNSIGNED_KEYS, "sig"] as const);
const MESSAGE_TYPE_SET: ReadonlySet<string> = new Set(ENVELOPE_MESSAGE_TYPES);

export function encodeUnsignedEnvelope(value: UnsignedEnvelope): CanonicalCbor {
  const envelope = parseUnsignedEnvelope(toUnsignedValue(value));
  return encodeCanonical(toUnsignedValue(envelope));
}

export function signEnvelope(
  value: UnsignedEnvelope,
  secretKey: Ed25519SecretKey,
): EnvelopeArtifact {
  const envelope = parseUnsignedEnvelope(toUnsignedValue(value));
  const signerPublicKey = deriveEd25519PublicKey(secretKey);
  if (!bytesEqual(envelope.from, signerPublicKey)) {
    throw new EnvelopeValidationError(
      "SENDER_KEY_MISMATCH",
      "Envelope sender does not match the signing key",
    );
  }

  const unsignedBytes = encodeCanonical(toUnsignedValue(envelope));
  const signature = parseEd25519Signature(
    signEd25519(envelopeSignatureInput(unsignedBytes), secretKey),
  );
  return createArtifact({ ...envelope, sig: signature });
}

export function decodeAndVerifyEnvelope(bytes: Uint8Array): EnvelopeArtifact {
  let envelope: SignedEnvelope;
  try {
    envelope = parseSignedEnvelope(decodeCanonical(bytes));
  } catch (cause) {
    if (cause instanceof EnvelopeValidationError) {
      throw cause;
    }
    throw new EnvelopeValidationError("MALFORMED_ENVELOPE", "Envelope decoding failed", {
      cause,
    });
  }

  const unsignedBytes = encodeCanonical(toUnsignedValue(envelope));
  if (!verifyEd25519(envelope.sig, envelopeSignatureInput(unsignedBytes), envelope.from)) {
    throw new EnvelopeValidationError("INVALID_SIGNATURE", "Envelope signature is invalid");
  }

  return createArtifact(envelope);
}

function createArtifact(envelope: SignedEnvelope): EnvelopeArtifact {
  const canonicalBytes = encodeCanonical(toSignedValue(envelope));
  return Object.freeze({
    envelope: Object.freeze(envelope),
    canonicalBytes,
    hash: parseHash256(hashEnvelope(canonicalBytes)),
  }) as EnvelopeArtifact;
}

function parseUnsignedEnvelope(value: CborValue): UnsignedEnvelope {
  const record = requireExactMap(value, UNSIGNED_KEYS);
  const version = requireUnsignedInteger(record["v"], "v");
  if (version !== ENVELOPE_VERSION) {
    throw new EnvelopeValidationError(
      "UNSUPPORTED_VERSION",
      `Unsupported envelope version ${version}`,
    );
  }

  return {
    v: ENVELOPE_VERSION,
    game: parseGameId(record["game"]),
    from: parseIdentityPublicKey(record["from"]),
    seq: requireUnsignedInteger(record["seq"], "seq"),
    prev: parseHash256(record["prev"]),
    round: requireUnsignedInteger(record["round"], "round"),
    phase: requireNonEmptyText(record["phase"], "phase"),
    type: requireMessageType(record["type"]),
    body: snapshotCborValue(record["body"]!),
  };
}

function parseSignedEnvelope(value: CborValue): SignedEnvelope {
  const record = requireExactMap(value, SIGNED_KEYS);
  const unsigned = parseUnsignedEnvelope(copyWithoutSignature(record));
  return {
    ...unsigned,
    sig: parseEd25519Signature(record["sig"]),
  };
}

function snapshotCborValue(value: CborValue): CborValue {
  return decodeCanonical(encodeCanonical(value));
}

function toUnsignedValue(envelope: UnsignedEnvelope): CborMap {
  return {
    v: envelope.v,
    game: envelope.game,
    from: envelope.from,
    seq: envelope.seq,
    prev: envelope.prev,
    round: envelope.round,
    phase: envelope.phase,
    type: envelope.type,
    body: envelope.body,
  };
}

function toSignedValue(envelope: SignedEnvelope): CborMap {
  return {
    ...toUnsignedValue(envelope),
    sig: envelope.sig,
  };
}

function copyWithoutSignature(record: CborMap): CborMap {
  const unsigned: Record<string, CborValue> = Object.create(null) as Record<string, CborValue>;
  for (const key of UNSIGNED_KEYS) {
    unsigned[key] = record[key]!;
  }
  return unsigned;
}

function requireExactMap<const Keys extends readonly string[]>(
  value: CborValue,
  expectedKeys: Keys,
): CborMap & Record<Keys[number], CborValue> {
  if (!isCborMap(value)) {
    throw malformed("Envelope must be a CBOR map");
  }

  const actualKeys = Object.keys(value);
  if (
    actualKeys.length !== expectedKeys.length ||
    expectedKeys.some((key) => !Object.hasOwn(value, key))
  ) {
    throw malformed(`Envelope fields must be exactly: ${expectedKeys.join(", ")}`);
  }
  return value as CborMap & Record<Keys[number], CborValue>;
}

function isCborMap(value: CborValue): value is CborMap {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array);
}

function requireUnsignedInteger(value: CborValue, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw malformed(`${field} must be an unsigned safe integer`);
  }
  return value;
}

function requireNonEmptyText(value: CborValue, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw malformed(`${field} must be a non-empty text string`);
  }
  return value;
}

function requireMessageType(value: CborValue): EnvelopeMessageType {
  if (typeof value !== "string" || !MESSAGE_TYPE_SET.has(value)) {
    throw malformed("type is not a version 1 envelope message type");
  }
  return value as EnvelopeMessageType;
}

function malformed(message: string): EnvelopeValidationError {
  return new EnvelopeValidationError("MALFORMED_ENVELOPE", message);
}
