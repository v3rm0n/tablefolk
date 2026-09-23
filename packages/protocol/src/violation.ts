import { bytesEqual } from "@p2pcards/crypto";
import {
  decodeCanonical,
  encodeCanonical,
  type CborMap,
  type CborValue,
} from "@p2pcards/encoding";

import { decodeAndVerifyEnvelope, type EnvelopeArtifact } from "./envelope";
import {
  expectArray,
  expectExactMap,
  expectNonEmptyText,
  expectUnsignedInteger,
  ProtocolSchemaError,
} from "./schema";

export interface EquivocationViolationBody {
  readonly seat: number;
  readonly reason: "equivocation";
  readonly evidence: readonly [EnvelopeArtifact, EnvelopeArtifact];
}

const BODY_KEYS = ["seat", "reason", "evidence"] as const;

export function encodeEquivocationViolationBody(body: EquivocationViolationBody): CborMap {
  const seat = expectUnsignedInteger(body.seat, "VIOLATION.body.seat", 7);
  if (body.reason !== "equivocation") {
    throw new ProtocolSchemaError(
      "VIOLATION.body.reason",
      'must be exactly "equivocation"',
    );
  }
  const evidence = normalizeEvidence(body.evidence, false);
  return {
    seat,
    reason: "equivocation",
    evidence: evidence.map((artifact) => decodeCanonical(artifact.canonicalBytes)),
  };
}

export function decodeEquivocationViolationBody(value: CborValue): EquivocationViolationBody {
  const body = expectExactMap(value, BODY_KEYS, "VIOLATION.body");
  const seat = expectUnsignedInteger(body["seat"], "VIOLATION.body.seat", 7);
  const reason = expectNonEmptyText(body["reason"], "VIOLATION.body.reason");
  if (reason !== "equivocation") {
    throw new ProtocolSchemaError(
      "VIOLATION.body.reason",
      'must be exactly "equivocation"',
    );
  }
  const encodedEvidence = expectArray(body["evidence"], "VIOLATION.body.evidence");
  if (encodedEvidence.length !== 2) {
    throw new ProtocolSchemaError(
      "VIOLATION.body.evidence",
      "must contain exactly two envelopes",
    );
  }
  const evidence = encodedEvidence.map((candidate, index) => {
    try {
      return decodeAndVerifyEnvelope(encodeCanonical(candidate));
    } catch (cause) {
      throw new ProtocolSchemaError(
        `VIOLATION.body.evidence[${index}]`,
        "must be a valid signed envelope",
        { cause },
      );
    }
  });
  return Object.freeze({
    seat,
    reason,
    evidence: normalizeEvidence(evidence, true),
  });
}

function normalizeEvidence(
  candidates: readonly EnvelopeArtifact[],
  requireCanonicalOrder: boolean,
): readonly [EnvelopeArtifact, EnvelopeArtifact] {
  if (!Array.isArray(candidates) || candidates.length !== 2) {
    throw new ProtocolSchemaError(
      "VIOLATION.body.evidence",
      "must contain exactly two envelopes",
    );
  }
  const evidence = candidates.map((candidate, index) => {
    try {
      return decodeAndVerifyEnvelope(candidate.canonicalBytes);
    } catch (cause) {
      throw new ProtocolSchemaError(
        `VIOLATION.body.evidence[${index}]`,
        "must be a valid signed envelope artifact",
        { cause },
      );
    }
  }) as [EnvelopeArtifact, EnvelopeArtifact];
  const [left, right] = evidence;
  if (
    !bytesEqual(left.envelope.game, right.envelope.game) ||
    !bytesEqual(left.envelope.from, right.envelope.from) ||
    left.envelope.seq !== right.envelope.seq
  ) {
    throw new ProtocolSchemaError(
      "VIOLATION.body.evidence",
      "envelopes must have the same game, sender, and sequence",
    );
  }
  if (bytesEqual(left.hash, right.hash)) {
    throw new ProtocolSchemaError(
      "VIOLATION.body.evidence",
      "envelopes must have different hashes",
    );
  }

  const order = compareBytes(left.hash, right.hash);
  if (requireCanonicalOrder && order > 0) {
    throw new ProtocolSchemaError(
      "VIOLATION.body.evidence",
      "envelopes must be ordered by ascending hash",
    );
  }
  return Object.freeze(order < 0 ? [left, right] : [right, left]);
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < left.length; index += 1) {
    const difference = left[index]! - right[index]!;
    if (difference !== 0) {
      return difference;
    }
  }
  return 0;
}
