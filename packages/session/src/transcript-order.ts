import { bytesEqual, bytesToHex } from "@p2pcards/crypto";
import {
  decodeAndVerifyEnvelope,
  parseGameId,
  type EnvelopeArtifact,
  type GameId,
} from "@p2pcards/protocol";

import { SenderChain } from "./sender-chain";

export class EnvelopeTranscriptOrderError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "EnvelopeTranscriptOrderError";
  }
}

export function orderEnvelopeTranscript(
  gameId: GameId,
  transcript: readonly EnvelopeArtifact[],
): readonly EnvelopeArtifact[] {
  if (!Array.isArray(transcript)) {
    throw new EnvelopeTranscriptOrderError("Envelope transcript must be an array");
  }
  const game = parseGameId(gameId);
  const bySender = new Map<string, EnvelopeArtifact[]>();
  const tuples = new Set<string>();

  for (const [index, candidate] of transcript.entries()) {
    let artifact: EnvelopeArtifact;
    try {
      artifact = decodeAndVerifyEnvelope(candidate.canonicalBytes);
    } catch (cause) {
      throw new EnvelopeTranscriptOrderError(`Transcript envelope ${index} is invalid`, {
        cause,
      });
    }
    if (!bytesEqual(artifact.envelope.game, game)) {
      throw new EnvelopeTranscriptOrderError(
        `Transcript envelope ${index} belongs to another game`,
      );
    }

    const sender = bytesToHex(artifact.envelope.from);
    const tuple = `${sender}:${artifact.envelope.seq}`;
    if (tuples.has(tuple)) {
      throw new EnvelopeTranscriptOrderError(
        `Transcript repeats sender ${sender} sequence ${artifact.envelope.seq}`,
      );
    }
    tuples.add(tuple);
    const artifacts = bySender.get(sender) ?? [];
    artifacts.push(artifact);
    bySender.set(sender, artifacts);
  }

  const ordered: EnvelopeArtifact[] = [];
  for (const sender of [...bySender.keys()].sort()) {
    const artifacts = bySender.get(sender)!;
    artifacts.sort(compareSequence);
    const chain = new SenderChain(artifacts[0]!.envelope.from);
    for (const artifact of artifacts) {
      const result = chain.ingest(artifact);
      if (result.status !== "accepted") {
        const reason = result.status === "rejected" ? result.reason : result.status;
        throw new EnvelopeTranscriptOrderError(
          `Invalid chain for sender ${sender} at sequence ${artifact.envelope.seq}: ${reason}`,
        );
      }
      ordered.push(artifact);
    }
  }
  return Object.freeze(ordered);
}

function compareSequence(left: EnvelopeArtifact, right: EnvelopeArtifact): number {
  if (left.envelope.seq === right.envelope.seq) {
    return 0;
  }
  return left.envelope.seq < right.envelope.seq ? -1 : 1;
}
