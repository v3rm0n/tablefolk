import type { CborMap, CborValue } from "@p2pcards/encoding";
import { decodeCanonical, encodeCanonical } from "@p2pcards/encoding";

import { decodeAndVerifyEnvelope, type EnvelopeArtifact } from "./envelope";
import { parseIdentityPublicKey, type IdentityPublicKey } from "./fields";
import {
  expectArray,
  expectByteString,
  expectExactMap,
  expectUnsignedInteger,
  ProtocolSchemaError,
} from "./schema";

export interface SyncRequestBody {
  readonly from: IdentityPublicKey;
  readonly fromSeq: number;
  readonly toSeq: number;
}

export interface SyncResponseBody {
  readonly envelopes: readonly EnvelopeArtifact[];
}

const REQUEST_KEYS = ["from", "from_seq", "to_seq"] as const;
const RESPONSE_KEYS = ["envelopes"] as const;

export function encodeSyncRequestBody(body: SyncRequestBody): CborMap {
  const normalized = normalizeRequest(body.from, body.fromSeq, body.toSeq);
  return {
    from: normalized.from,
    from_seq: normalized.fromSeq,
    to_seq: normalized.toSeq,
  };
}

export function decodeSyncRequestBody(value: CborValue): SyncRequestBody {
  const body = expectExactMap(value, REQUEST_KEYS, "SYNC_REQ.body");
  return normalizeRequest(
    decodeIdentity(body["from"], "SYNC_REQ.body.from"),
    expectUnsignedInteger(body["from_seq"], "SYNC_REQ.body.from_seq"),
    expectUnsignedInteger(body["to_seq"], "SYNC_REQ.body.to_seq"),
  );
}

export function encodeSyncResponseBody(body: SyncResponseBody): CborMap {
  if (!Array.isArray(body.envelopes) || body.envelopes.length === 0) {
    throw new ProtocolSchemaError("SYNC_RESP.body.envelopes", "must be a non-empty array");
  }
  return {
    envelopes: body.envelopes.map((candidate, index) => {
      try {
        const artifact = decodeAndVerifyEnvelope(candidate.canonicalBytes);
        return decodeCanonical(artifact.canonicalBytes);
      } catch (cause) {
        throw new ProtocolSchemaError(
          `SYNC_RESP.body.envelopes[${index}]`,
          "must be a valid signed envelope artifact",
          { cause },
        );
      }
    }),
  };
}

export function decodeSyncResponseBody(value: CborValue): SyncResponseBody {
  const body = expectExactMap(value, RESPONSE_KEYS, "SYNC_RESP.body");
  const encoded = expectArray(body["envelopes"], "SYNC_RESP.body.envelopes");
  if (encoded.length === 0) {
    throw new ProtocolSchemaError("SYNC_RESP.body.envelopes", "must be a non-empty array");
  }
  const envelopes = encoded.map((candidate, index) => {
    try {
      return decodeAndVerifyEnvelope(encodeCanonical(candidate));
    } catch (cause) {
      throw new ProtocolSchemaError(
        `SYNC_RESP.body.envelopes[${index}]`,
        "must be a canonical signed envelope",
        { cause },
      );
    }
  });
  return Object.freeze({ envelopes: Object.freeze(envelopes) });
}

function normalizeRequest(
  from: IdentityPublicKey,
  fromSeq: number,
  toSeq: number,
): SyncRequestBody {
  const normalizedFrom = decodeIdentity(from, "SYNC_REQ.body.from");
  const normalizedFromSeq = expectUnsignedInteger(fromSeq, "SYNC_REQ.body.from_seq");
  const normalizedToSeq = expectUnsignedInteger(toSeq, "SYNC_REQ.body.to_seq");
  if (normalizedFromSeq > normalizedToSeq) {
    throw new ProtocolSchemaError(
      "SYNC_REQ.body",
      "from_seq must be less than or equal to to_seq",
    );
  }
  return Object.freeze({
    from: normalizedFrom,
    fromSeq: normalizedFromSeq,
    toSeq: normalizedToSeq,
  });
}

function decodeIdentity(value: CborValue, path: string): IdentityPublicKey {
  try {
    return parseIdentityPublicKey(expectByteString(value, path));
  } catch (cause) {
    if (cause instanceof ProtocolSchemaError) {
      throw cause;
    }
    throw new ProtocolSchemaError(path, "must be a 32-byte identity key", { cause });
  }
}
