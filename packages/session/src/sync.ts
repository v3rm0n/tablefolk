import { bytesEqual } from "@p2pcards/crypto";
import {
  decodeAndVerifyEnvelope,
  parseIdentityPublicKey,
  type EnvelopeArtifact,
  type SyncRequestBody,
  type SyncResponseBody,
} from "@p2pcards/protocol";

import {
  SessionChainRegistry,
  type SessionIngestResult,
} from "./chain-registry";

export const DEFAULT_MAX_SYNC_RANGE_ENVELOPES = 128;
export const DEFAULT_MAX_SYNC_RESPONSE_BYTES = 4 * 1024 * 1024;

export interface SyncResponseLimits {
  readonly maxEnvelopes?: number;
  readonly maxBytes?: number;
}

export type SyncServeResult =
  | {
      readonly status: "complete";
      readonly body: SyncResponseBody;
    }
  | {
      readonly status: "missing";
      readonly firstMissingSeq: number;
    }
  | {
      readonly status: "unknown_sender";
    };

export type SyncResponseRejection =
  | {
      readonly status: "rejected";
      readonly reason: "unknown_sender" | "wrong_count";
      readonly expectedCount?: number;
      readonly actualCount?: number;
    }
  | {
      readonly status: "rejected";
      readonly reason:
        | "wrong_game"
        | "wrong_sender"
        | "wrong_sequence"
        | "invalid_artifact"
        | "broken_prev";
      readonly index: number;
    }
  | {
      readonly status: "rejected";
      readonly reason: "limit_exceeded";
    };

export type SyncResponsePreflightResult =
  | {
      readonly status: "valid";
      readonly request: SyncRequestBody;
      readonly response: SyncResponseBody;
    }
  | SyncResponseRejection;

export type SyncApplyResult =
  | {
      readonly status: "applied";
      readonly results: readonly SessionIngestResult[];
    }
  | SyncResponseRejection;

export function serveSyncRequest(
  registry: SessionChainRegistry,
  request: SyncRequestBody,
): SyncServeResult {
  const normalized = normalizeRequest(request);
  if (normalized.toSeq - normalized.fromSeq >= DEFAULT_MAX_SYNC_RANGE_ENVELOPES) {
    throw new RangeError(
      `SYNC_REQ range must contain at most ${DEFAULT_MAX_SYNC_RANGE_ENVELOPES} envelopes`,
    );
  }
  const range = registry.readRange(normalized.from, normalized.fromSeq, normalized.toSeq);
  if (range.status === "complete") {
    const preflight = preflightSyncResponse(registry, normalized, { envelopes: range.envelopes });
    if (preflight.status === "rejected") {
      if (preflight.reason === "limit_exceeded") {
        throw new RangeError("SYNC_RESP source range exceeds the byte limit");
      }
      throw new Error(`SYNC_RESP source range is invalid: ${preflight.reason}`);
    }
    return Object.freeze({
      status: "complete",
      body: preflight.response,
    });
  }
  return Object.freeze(range);
}

// Pure batch validation, not validation of the first artifact against the local chain head.
export function preflightSyncResponse(
  registry: SessionChainRegistry,
  request: SyncRequestBody,
  response: SyncResponseBody,
  limits: SyncResponseLimits = {},
): SyncResponsePreflightResult {
  const {
    maxEnvelopes = DEFAULT_MAX_SYNC_RANGE_ENVELOPES,
    maxBytes = DEFAULT_MAX_SYNC_RESPONSE_BYTES,
  } = limits;
  if (!Number.isSafeInteger(maxEnvelopes) || maxEnvelopes < 1) {
    throw new RangeError("maxEnvelopes must be a positive safe integer");
  }
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new RangeError("maxBytes must be a positive safe integer");
  }

  const normalized = normalizeRequest(request);
  if (registry.seatOf(normalized.from) === null) {
    return Object.freeze({ status: "rejected", reason: "unknown_sender" });
  }

  // Compare the difference before adding one: [0, MAX_SAFE_INTEGER] has an unsafe count.
  if (normalized.toSeq - normalized.fromSeq >= maxEnvelopes) {
    return Object.freeze({ status: "rejected", reason: "limit_exceeded" });
  }
  const candidates = response.envelopes;
  if (!Array.isArray(candidates)) {
    return Object.freeze({ status: "rejected", reason: "invalid_artifact", index: 0 });
  }
  const actualCount = candidates.length;
  if (actualCount > maxEnvelopes) {
    return Object.freeze({ status: "rejected", reason: "limit_exceeded" });
  }
  const expectedCount = normalized.toSeq - normalized.fromSeq + 1;
  if (actualCount !== expectedCount) {
    return Object.freeze({
      status: "rejected",
      reason: "wrong_count",
      expectedCount,
      actualCount,
    });
  }

  // Capture byte references once and bound the entire batch before decoding or copying it.
  const encoded: Uint8Array[] = [];
  let totalBytes = 0;
  for (let index = 0; index < actualCount; index += 1) {
    let bytes: Uint8Array;
    try {
      bytes = candidates[index]!.canonicalBytes;
      if (!(bytes instanceof Uint8Array) || bytes.constructor !== Uint8Array) {
        return Object.freeze({ status: "rejected", reason: "invalid_artifact", index });
      }
    } catch {
      return Object.freeze({ status: "rejected", reason: "invalid_artifact", index });
    }
    if (bytes.byteLength > maxBytes - totalBytes) {
      return Object.freeze({ status: "rejected", reason: "limit_exceeded" });
    }
    totalBytes += bytes.byteLength;
    encoded.push(bytes);
  }

  const envelopes: EnvelopeArtifact[] = [];
  const gameId = registry.gameId;
  for (const [index, bytes] of encoded.entries()) {
    let artifact: EnvelopeArtifact;
    try {
      artifact = decodeAndVerifyEnvelope(bytes);
    } catch {
      return Object.freeze({ status: "rejected", reason: "invalid_artifact", index });
    }
    if (!bytesEqual(artifact.envelope.game, gameId)) {
      return Object.freeze({ status: "rejected", reason: "wrong_game", index });
    }
    if (!bytesEqual(artifact.envelope.from, normalized.from)) {
      return Object.freeze({ status: "rejected", reason: "wrong_sender", index });
    }
    if (artifact.envelope.seq !== normalized.fromSeq + index) {
      return Object.freeze({ status: "rejected", reason: "wrong_sequence", index });
    }
    if (index > 0 && !bytesEqual(artifact.envelope.prev, envelopes[index - 1]!.hash)) {
      return Object.freeze({ status: "rejected", reason: "broken_prev", index });
    }
    envelopes.push(artifact);
  }

  return Object.freeze({
    status: "valid",
    request: normalized,
    response: Object.freeze({ envelopes: Object.freeze(envelopes) }),
  });
}

// In-memory only: "applied" means ingestion was attempted, and results can contain rejections.
export function applySyncResponse(
  registry: SessionChainRegistry,
  request: SyncRequestBody,
  response: SyncResponseBody,
): SyncApplyResult {
  const preflight = preflightSyncResponse(registry, request, response);
  if (preflight.status === "rejected") {
    return preflight;
  }

  const results = preflight.response.envelopes.map((artifact) => registry.ingest(artifact));
  return Object.freeze({ status: "applied", results: Object.freeze(results) });
}

function normalizeRequest(request: SyncRequestBody): SyncRequestBody {
  const { from, fromSeq, toSeq } = request;
  if (!Number.isSafeInteger(fromSeq) || fromSeq < 0) {
    throw new RangeError("SYNC_REQ fromSeq must be an unsigned safe integer");
  }
  if (!Number.isSafeInteger(toSeq) || toSeq < fromSeq) {
    throw new RangeError("SYNC_REQ toSeq must be an unsigned safe integer at or above fromSeq");
  }
  return Object.freeze({
    from: parseIdentityPublicKey(from),
    fromSeq,
    toSeq,
  });
}
