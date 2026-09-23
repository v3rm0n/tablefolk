import { bytesEqual, bytesToHex } from "@p2pcards/crypto";
import {
  decodeAndVerifyEnvelope,
  parseGameId,
  type EnvelopeArtifact,
  type GameId,
  type IdentityPublicKey,
} from "@p2pcards/protocol";

import {
  SetupEnvelopeCoordinator,
  type SetupEnvelopeResult,
} from "./setup-envelope-coordinator";

export interface SetupRecoveryResult {
  readonly coordinator: SetupEnvelopeCoordinator;
  readonly setupEnvelopeCount: number;
}

export class SetupRecoveryError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SetupRecoveryError";
  }
}

interface SetupArtifact {
  readonly artifact: EnvelopeArtifact;
  readonly rank: number;
  readonly seat: number;
}

const SETUP_TYPE_RANK = new Map<string, number>([
  ["KEY_SHARE", 0],
  ["RAND_COMMIT", 1],
  ["RAND_REVEAL", 2],
]);

export function recoverSetup(
  gameId: GameId,
  round: number,
  roster: readonly IdentityPublicKey[],
  transcript: readonly EnvelopeArtifact[],
): SetupRecoveryResult {
  if (!Array.isArray(transcript)) {
    throw new SetupRecoveryError("Setup transcript must be an array");
  }
  const game = parseGameId(gameId);
  const coordinator = new SetupEnvelopeCoordinator(game, round, roster);
  const seats = new Map(coordinator.roster.map((identity, seat) => [bytesToHex(identity), seat]));
  const tuples = new Set<string>();
  const setupArtifacts: SetupArtifact[] = [];
  const firstSequenceBySenderAndRank = new Map<string, number>();

  for (const [index, candidate] of transcript.entries()) {
    let artifact: EnvelopeArtifact;
    try {
      artifact = decodeAndVerifyEnvelope(candidate.canonicalBytes);
    } catch (cause) {
      throw new SetupRecoveryError(`Transcript envelope ${index} is invalid`, { cause });
    }
    if (!bytesEqual(artifact.envelope.game, game)) {
      throw new SetupRecoveryError(`Transcript envelope ${index} belongs to another game`);
    }

    const senderKey = bytesToHex(artifact.envelope.from);
    const tuple = `${senderKey}:${artifact.envelope.seq}`;
    if (tuples.has(tuple)) {
      throw new SetupRecoveryError(
        `Transcript repeats sender ${senderKey} sequence ${artifact.envelope.seq}`,
      );
    }
    tuples.add(tuple);

    const rank = SETUP_TYPE_RANK.get(artifact.envelope.type);
    if (rank === undefined) {
      continue;
    }
    const seat = seats.get(senderKey);
    if (seat === undefined) {
      throw new SetupRecoveryError(
        `Setup envelope ${senderKey}:${artifact.envelope.seq} has a non-roster sender`,
      );
    }
    const firstKey = `${senderKey}:${rank}`;
    const firstSequence = firstSequenceBySenderAndRank.get(firstKey);
    if (firstSequence === undefined || artifact.envelope.seq < firstSequence) {
      firstSequenceBySenderAndRank.set(firstKey, artifact.envelope.seq);
    }
    setupArtifacts.push(Object.freeze({ artifact, rank, seat }));
  }

  requireSenderPhaseOrder(firstSequenceBySenderAndRank);
  setupArtifacts.sort(compareSetupArtifacts);
  for (const { artifact } of setupArtifacts) {
    const result = coordinator.ingest(artifact);
    if (result.status === "rejected") {
      throw transitionError(artifact, result);
    }
  }

  return Object.freeze({
    coordinator,
    setupEnvelopeCount: setupArtifacts.length,
  });
}

function requireSenderPhaseOrder(firstSequences: ReadonlyMap<string, number>): void {
  const senders = new Set<string>();
  for (const key of firstSequences.keys()) {
    senders.add(key.slice(0, key.lastIndexOf(":")));
  }
  for (const sender of senders) {
    const key = firstSequences.get(`${sender}:0`);
    const commit = firstSequences.get(`${sender}:1`);
    const reveal = firstSequences.get(`${sender}:2`);
    if (commit !== undefined && (key === undefined || commit <= key)) {
      throw new SetupRecoveryError(`Sender ${sender} committed before its key share`);
    }
    if (reveal !== undefined && (commit === undefined || reveal <= commit)) {
      throw new SetupRecoveryError(`Sender ${sender} revealed before its commitment`);
    }
  }
}

function compareSetupArtifacts(left: SetupArtifact, right: SetupArtifact): number {
  if (left.rank !== right.rank) {
    return left.rank - right.rank;
  }
  if (left.seat !== right.seat) {
    return left.seat - right.seat;
  }
  return left.artifact.envelope.seq - right.artifact.envelope.seq;
}

function transitionError(
  artifact: EnvelopeArtifact,
  result: Extract<SetupEnvelopeResult, { readonly status: "rejected" }>,
): SetupRecoveryError {
  return new SetupRecoveryError(
    `Could not recover ${artifact.envelope.type} from seat ${result.seat ?? "unknown"} ` +
      `at sequence ${artifact.envelope.seq}: ${result.reason}`,
  );
}
