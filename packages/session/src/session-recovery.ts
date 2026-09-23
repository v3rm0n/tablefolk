import { bytesEqual, bytesToHex } from "@p2pcards/crypto";
import {
  decodeAndVerifyEnvelope,
  parseGameId,
  parseIdentityPublicKey,
  type EnvelopeArtifact,
  type GameId,
  type IdentityPublicKey,
} from "@p2pcards/protocol";

import { SessionChainRegistry } from "./chain-registry";

export interface SessionChainRecoveryResult {
  readonly registry: SessionChainRegistry;
  readonly envelopeCount: number;
}

export class SessionChainRecoveryError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SessionChainRecoveryError";
  }
}

export function recoverSessionChains(
  gameId: GameId,
  roster: readonly IdentityPublicKey[],
  transcript: readonly EnvelopeArtifact[],
): SessionChainRecoveryResult {
  if (!Array.isArray(transcript)) {
    throw new SessionChainRecoveryError("Session transcript must be an array");
  }
  const game = parseGameId(gameId);
  const registry = new SessionChainRegistry(game, roster);
  const rosterKeys = new Set(registry.roster.map(bytesToHex));
  const bySender = new Map<string, EnvelopeArtifact[]>();
  const tuples = new Set<string>();

  for (const [index, candidate] of transcript.entries()) {
    let artifact: EnvelopeArtifact;
    try {
      artifact = decodeAndVerifyEnvelope(candidate.canonicalBytes);
    } catch (cause) {
      throw new SessionChainRecoveryError(`Transcript envelope ${index} is invalid`, { cause });
    }
    if (!bytesEqual(artifact.envelope.game, game)) {
      throw new SessionChainRecoveryError(`Transcript envelope ${index} belongs to another game`);
    }

    const senderKey = bytesToHex(artifact.envelope.from);
    if (!rosterKeys.has(senderKey)) {
      throw new SessionChainRecoveryError(`Transcript envelope ${index} has a non-roster sender`);
    }
    const tuple = `${senderKey}:${artifact.envelope.seq}`;
    if (tuples.has(tuple)) {
      throw new SessionChainRecoveryError(
        `Transcript repeats sender ${senderKey} sequence ${artifact.envelope.seq}`,
      );
    }
    tuples.add(tuple);
    const senderArtifacts = bySender.get(senderKey) ?? [];
    senderArtifacts.push(artifact);
    bySender.set(senderKey, senderArtifacts);
  }

  for (const sender of registry.roster) {
    const senderKey = bytesToHex(parseIdentityPublicKey(sender));
    const artifacts = bySender.get(senderKey) ?? [];
    artifacts.sort(compareSequence);
    for (const artifact of artifacts) {
      const result = registry.ingest(artifact);
      if (result.status !== "accepted") {
        const reason = result.status === "rejected" ? result.reason : result.status;
        throw new SessionChainRecoveryError(
          `Could not recover sender ${senderKey} sequence ${artifact.envelope.seq}: ${reason}`,
        );
      }
    }
  }

  return Object.freeze({ registry, envelopeCount: transcript.length });
}

function compareSequence(left: EnvelopeArtifact, right: EnvelopeArtifact): number {
  if (left.envelope.seq === right.envelope.seq) {
    return 0;
  }
  return left.envelope.seq < right.envelope.seq ? -1 : 1;
}
