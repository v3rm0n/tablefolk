import { bytesEqual } from "@p2pcards/crypto";
import {
  decodeAndVerifyEnvelope,
  decodeEquivocationViolationBody,
  encodeEquivocationViolationBody,
  parseIdentityPublicKey,
  type EnvelopeArtifact,
  type EquivocationViolationBody,
  type IdentityPublicKey,
} from "@p2pcards/protocol";

import { SessionChainRegistry } from "./chain-registry";

export type EquivocationViolationAssessment =
  | {
      readonly status: "valid";
      readonly seat: number;
      readonly sender: IdentityPublicKey;
      readonly body: EquivocationViolationBody;
    }
  | {
      readonly status: "rejected";
      readonly reason:
        | "malformed_evidence"
        | "seat_out_of_roster"
        | "sender_seat_mismatch"
        | "wrong_game";
    };

export class EquivocationEvidenceError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "EquivocationEvidenceError";
  }
}

export function createEquivocationViolation(
  registry: SessionChainRegistry,
  leftCandidate: EnvelopeArtifact,
  rightCandidate: EnvelopeArtifact,
): EquivocationViolationBody {
  let left: EnvelopeArtifact;
  try {
    left = decodeAndVerifyEnvelope(leftCandidate.canonicalBytes);
  } catch (cause) {
    throw new EquivocationEvidenceError("First equivocation artifact is invalid", { cause });
  }
  const seat = registry.seatOf(left.envelope.from);
  if (seat === null) {
    throw new EquivocationEvidenceError("Equivocation sender is outside the finalized roster");
  }

  let body: EquivocationViolationBody;
  try {
    body = decodeEquivocationViolationBody(
      encodeEquivocationViolationBody({
        seat,
        reason: "equivocation",
        evidence: [left, rightCandidate],
      }),
    );
  } catch (cause) {
    throw new EquivocationEvidenceError("Artifacts do not prove equivocation", { cause });
  }
  const assessment = assessEquivocationViolation(registry, body);
  if (assessment.status === "rejected") {
    throw new EquivocationEvidenceError(
      `Equivocation evidence is invalid for this session: ${assessment.reason}`,
    );
  }
  return assessment.body;
}

export function assessEquivocationViolation(
  registry: SessionChainRegistry,
  candidate: EquivocationViolationBody,
): EquivocationViolationAssessment {
  let body: EquivocationViolationBody;
  try {
    body = decodeEquivocationViolationBody(encodeEquivocationViolationBody(candidate));
  } catch {
    return Object.freeze({ status: "rejected", reason: "malformed_evidence" });
  }

  const sender = body.evidence[0].envelope.from;
  if (!bytesEqual(body.evidence[0].envelope.game, registry.gameId)) {
    return Object.freeze({ status: "rejected", reason: "wrong_game" });
  }
  const expected = registry.roster[body.seat];
  if (expected === undefined) {
    return Object.freeze({ status: "rejected", reason: "seat_out_of_roster" });
  }
  if (!bytesEqual(sender, expected)) {
    return Object.freeze({ status: "rejected", reason: "sender_seat_mismatch" });
  }
  return Object.freeze({
    status: "valid",
    seat: body.seat,
    sender: parseIdentityPublicKey(sender),
    body,
  });
}
