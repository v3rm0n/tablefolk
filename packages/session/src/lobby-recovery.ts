import { bytesEqual, bytesToHex } from "@p2pcards/crypto";
import {
  decodeAndVerifyEnvelope,
  decodeReadyBody,
  parseGameId,
  type EnvelopeArtifact,
} from "@p2pcards/protocol";

import {
  LobbyChainRegistry,
  type LobbyBootstrapContext,
} from "./lobby-bootstrap";

export interface LobbyRecoveryResult {
  readonly lobby: LobbyChainRegistry;
  readonly envelopeCount: number;
  readonly restoredReadyCount: number;
}

export class LobbyRecoveryError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "LobbyRecoveryError";
  }
}

interface ReadyCandidate {
  readonly artifact: EnvelopeArtifact;
  readonly rosterKey: string;
  readonly senderKey: string;
}

export function recoverLobby(
  context: LobbyBootstrapContext,
  transcript: readonly EnvelopeArtifact[],
  rosterSnapshot?: EnvelopeArtifact | null,
): LobbyRecoveryResult {
  if (!Array.isArray(transcript)) {
    throw new LobbyRecoveryError("Lobby transcript must be an array");
  }

  const expectedGame = parseGameId(context.gameId);
  const hostKey = bytesToHex(context.host);
  const artifactsBySender = new Map<string, EnvelopeArtifact[]>();
  const tuples = new Set<string>();

  for (const [index, candidate] of transcript.entries()) {
    let artifact: EnvelopeArtifact;
    try {
      artifact = decodeAndVerifyEnvelope(candidate.canonicalBytes);
    } catch (cause) {
      throw new LobbyRecoveryError(`Transcript envelope ${index} is invalid`, { cause });
    }
    if (!bytesEqual(artifact.envelope.game, expectedGame)) {
      throw new LobbyRecoveryError(`Transcript envelope ${index} belongs to another game`);
    }

    const senderKey = bytesToHex(artifact.envelope.from);
    const tuple = `${senderKey}:${artifact.envelope.seq}`;
    if (tuples.has(tuple)) {
      throw new LobbyRecoveryError(
        `Transcript repeats sender ${senderKey} sequence ${artifact.envelope.seq}`,
      );
    }
    tuples.add(tuple);
    const senderArtifacts = artifactsBySender.get(senderKey) ?? [];
    senderArtifacts.push(artifact);
    artifactsBySender.set(senderKey, senderArtifacts);
  }

  for (const artifacts of artifactsBySender.values()) {
    artifacts.sort(compareSequence);
  }

  const lobby = new LobbyChainRegistry(context);
  const hostArtifacts = artifactsBySender.get(hostKey) ?? [];
  for (const artifact of hostArtifacts) {
    if (artifact.envelope.type === "JOIN") {
      throw new LobbyRecoveryError("The invitation host cannot have a JOIN envelope");
    }
    const result =
      artifact.envelope.type === "ROSTER"
        ? lobby.ingestRoster(artifact)
        : lobby.ingest(artifact);
    requireAccepted(result, `host sequence ${artifact.envelope.seq}`);
  }

  const senderKeys = [...artifactsBySender.keys()]
    .filter((senderKey) => senderKey !== hostKey)
    .sort();
  for (const senderKey of senderKeys) {
    const artifacts = artifactsBySender.get(senderKey)!;
    const genesis = artifacts[0];
    if (genesis === undefined) {
      throw new LobbyRecoveryError(`Sender ${senderKey} has no chain genesis`);
    }
    const bootstrap = lobby.bootstrapJoin(genesis);
    requireAccepted(bootstrap, `sender ${senderKey} sequence ${genesis.envelope.seq}`);

    for (const artifact of artifacts.slice(1)) {
      if (artifact.envelope.type === "JOIN") {
        throw new LobbyRecoveryError(`Sender ${senderKey} has JOIN after its genesis`);
      }
      if (artifact.envelope.type === "ROSTER") {
        throw new LobbyRecoveryError(`Non-host sender ${senderKey} has a ROSTER envelope`);
      }
      requireAccepted(
        lobby.ingest(artifact),
        `sender ${senderKey} sequence ${artifact.envelope.seq}`,
      );
    }
  }

  verifyRosterSnapshot(lobby, rosterSnapshot);
  const readyCandidates = collectReadyCandidates(artifactsBySender);
  const currentRosterKey = lobby.rosterHash === null ? null : bytesToHex(lobby.rosterHash);
  const currentRoster = lobby.roster;
  const currentSeats = new Map<string, number>();
  for (const [seat, sender] of currentRoster?.seats.entries() ?? []) {
    currentSeats.set(bytesToHex(sender), seat);
  }

  const firstByRosterAndSender = new Map<string, ReadyCandidate>();
  for (const candidate of readyCandidates) {
    const key = `${candidate.rosterKey}:${candidate.senderKey}`;
    const existing = firstByRosterAndSender.get(key);
    if (
      existing === undefined ||
      candidate.artifact.envelope.seq < existing.artifact.envelope.seq
    ) {
      firstByRosterAndSender.set(key, candidate);
    }
  }

  const selected = [...firstByRosterAndSender.values()];
  const historical = selected
    .filter((candidate) => candidate.rosterKey !== currentRosterKey)
    .sort(compareReadyCandidate);
  const current = selected
    .filter((candidate) => candidate.rosterKey === currentRosterKey)
    .sort((left, right) => {
      const leftSeat = currentSeats.get(left.senderKey) ?? -1;
      const rightSeat = currentSeats.get(right.senderKey) ?? -1;
      return leftSeat - rightSeat || compareReadyCandidate(left, right);
    });

  let restoredReadyCount = 0;
  for (const candidate of [...historical, ...current]) {
    const result = lobby.restoreReadyFromHistory(candidate.artifact);
    requireAccepted(result, `READY at ${candidate.senderKey}:${candidate.artifact.envelope.seq}`);
    restoredReadyCount += 1;
  }

  return Object.freeze({
    lobby,
    envelopeCount: transcript.length,
    restoredReadyCount,
  });
}

function collectReadyCandidates(
  artifactsBySender: ReadonlyMap<string, readonly EnvelopeArtifact[]>,
): readonly ReadyCandidate[] {
  const candidates: ReadyCandidate[] = [];
  for (const [senderKey, artifacts] of artifactsBySender) {
    for (const artifact of artifacts) {
      if (artifact.envelope.type !== "READY") {
        continue;
      }
      if (artifact.envelope.phase !== "lobby" || artifact.envelope.round !== 0) {
        throw new LobbyRecoveryError(
          `READY at ${senderKey}:${artifact.envelope.seq} has invalid lobby metadata`,
        );
      }
      try {
        const body = decodeReadyBody(artifact.envelope.body);
        candidates.push(
          Object.freeze({
            artifact,
            rosterKey: bytesToHex(body.rosterHash),
            senderKey,
          }),
        );
      } catch (cause) {
        throw new LobbyRecoveryError(
          `READY at ${senderKey}:${artifact.envelope.seq} has a malformed body`,
          { cause },
        );
      }
    }
  }
  return Object.freeze(candidates);
}

function verifyRosterSnapshot(
  lobby: LobbyChainRegistry,
  expected: EnvelopeArtifact | null | undefined,
): void {
  if (expected === undefined) {
    return;
  }
  const actual = lobby.rosterArtifact;
  if (expected === null) {
    if (actual !== null) {
      throw new LobbyRecoveryError("Transcript has a roster but durable snapshot is missing");
    }
    return;
  }

  let snapshot: EnvelopeArtifact;
  try {
    snapshot = decodeAndVerifyEnvelope(expected.canonicalBytes);
  } catch (cause) {
    throw new LobbyRecoveryError("Durable roster snapshot is invalid", { cause });
  }
  if (actual === null || !bytesEqual(actual.canonicalBytes, snapshot.canonicalBytes)) {
    throw new LobbyRecoveryError("Durable roster snapshot does not match latest host history");
  }
}

function requireAccepted(result: { readonly status: string }, label: string): void {
  if (result.status === "accepted") {
    return;
  }
  const reason = "reason" in result ? String(result.reason) : result.status;
  throw new LobbyRecoveryError(`Could not recover ${label}: ${reason}`);
}

function compareSequence(left: EnvelopeArtifact, right: EnvelopeArtifact): number {
  if (left.envelope.seq === right.envelope.seq) {
    return 0;
  }
  return left.envelope.seq < right.envelope.seq ? -1 : 1;
}

function compareReadyCandidate(left: ReadyCandidate, right: ReadyCandidate): number {
  const rosterOrder = compareText(left.rosterKey, right.rosterKey);
  if (rosterOrder !== 0) {
    return rosterOrder;
  }
  const senderOrder = compareText(left.senderKey, right.senderKey);
  if (senderOrder !== 0) {
    return senderOrder;
  }
  return compareSequence(left.artifact, right.artifact);
}

function compareText(left: string, right: string): number {
  return left === right ? 0 : left < right ? -1 : 1;
}
