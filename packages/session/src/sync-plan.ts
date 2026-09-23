import {
  decodeAndVerifyEnvelope,
  decodeWitnessBody,
  parseIdentityPublicKey,
  type EnvelopeArtifact,
  type SyncRequestBody,
  type WitnessBody,
} from "@p2pcards/protocol";

import { SessionChainRegistry } from "./chain-registry";
import {
  DEFAULT_MAX_SYNC_RANGE_ENVELOPES,
  DEFAULT_MAX_SYNC_RESPONSE_BYTES,
} from "./sync";
import { assessWitness, type WitnessAssessment } from "./witness";

export type WitnessSyncPlanRejection =
  | Extract<WitnessAssessment, { status: "rejected" }>
  | {
      readonly status: "rejected";
      readonly reason:
        | "invalid_artifact"
        | "limit_exceeded"
        | "wrong_type"
        | "witness_not_accepted"
        | "invalid_witness";
    };

export type WitnessSyncPlanResult =
  | {
      readonly status: "planned";
      readonly requests: readonly SyncRequestBody[];
    }
  | WitnessSyncPlanRejection;

export function planWitnessSyncRequests(
  registry: SessionChainRegistry,
  witness: EnvelopeArtifact,
  maxEnvelopesPerRequest = DEFAULT_MAX_SYNC_RANGE_ENVELOPES,
): WitnessSyncPlanResult {
  if (!Number.isSafeInteger(maxEnvelopesPerRequest) || maxEnvelopesPerRequest < 1) {
    throw new RangeError("maxEnvelopesPerRequest must be a positive safe integer");
  }

  let artifact: EnvelopeArtifact;
  try {
    const bytes = witness.canonicalBytes;
    if (!(bytes instanceof Uint8Array) || bytes.constructor !== Uint8Array) {
      return Object.freeze({ status: "rejected", reason: "invalid_artifact" });
    }
    if (bytes.byteLength > DEFAULT_MAX_SYNC_RESPONSE_BYTES) {
      return Object.freeze({ status: "rejected", reason: "limit_exceeded" });
    }
    artifact = decodeAndVerifyEnvelope(bytes);
  } catch {
    return Object.freeze({ status: "rejected", reason: "invalid_artifact" });
  }
  if (artifact.envelope.type !== "WITNESS") {
    return Object.freeze({ status: "rejected", reason: "wrong_type" });
  }
  // Even an immediately acceptable outer must be ingested by the caller before its claims act.
  if (registry.classify(artifact).status !== "duplicate") {
    return Object.freeze({ status: "rejected", reason: "witness_not_accepted" });
  }

  let body: WitnessBody;
  try {
    body = decodeWitnessBody(artifact.envelope.body);
  } catch {
    return Object.freeze({ status: "rejected", reason: "invalid_witness" });
  }
  const assessment = assessWitness(registry, body);
  if (assessment.status === "rejected") {
    return assessment;
  }

  const requests: SyncRequestBody[] = [];
  for (const outcome of assessment.outcomes) {
    if (outcome.status !== "need_sync" && outcome.status !== "conflict") {
      continue;
    }
    const { fromSeq, toSeq } = outcome;
    requests.push(Object.freeze({
      from: parseIdentityPublicKey(outcome.claimed.from),
      fromSeq,
      // Add only the bounded difference so even a MAX_SAFE_INTEGER claim cannot overflow.
      toSeq: fromSeq + Math.min(toSeq - fromSeq, maxEnvelopesPerRequest - 1),
    }));
  }
  return Object.freeze({ status: "planned", requests: Object.freeze(requests) });
}
