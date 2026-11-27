import { bytesEqual } from "@p2pcards/crypto";
import { recoverSetup } from "@p2pcards/engine";
import { decodeCanonical, encodeCanonical } from "@p2pcards/encoding";
import { CandidateSaskuRoundOwner } from "@p2pcards/game-sasku";
import {
  decodeRosterBody, expectArray, expectByteString, expectExactMap, parseHash256,
  type EnvelopeArtifact,
} from "@p2pcards/protocol";
import {
  captureSessionHistory, orderEnvelopeTranscript, PersistentSessionReceiver, recoverLobby,
  type SessionChainRegistry,
} from "@p2pcards/session";

import { CandidateShuffleClient } from "./candidate-shuffle-client";
import { decodeMatchEnvelope, isLobbyEnvelope } from "./match-envelope";
import { liveRoundPolicy, liveRulesHash, MATCH_HISTORY_LIMITS } from "./live-profile";
import {
  INITIAL_SASKU_MATCH, MAX_SASKU_MATCH_ROUNDS, recordSaskuRound, type SaskuMatchState,
} from "./sasku-match";

const VERSION = 1;
const FIELDS = ["version", "rules_hash", "roster", "envelopes"] as const;
export const MAX_TRANSCRIPT_BYTES = MATCH_HISTORY_LIMITS.maxBytes + MATCH_HISTORY_LIMITS.maxEnvelopes * 5 + 128;

export type TranscriptVerification =
  | { readonly status: "verified" | "incomplete"; readonly match: SaskuMatchState }
  | { readonly status: "violation"; readonly message: string; readonly round?: number;
      readonly rule?: string; readonly seat?: number; readonly at?: number };

export function exportTranscript(session: SessionChainRegistry, rosterArtifact: EnvelopeArtifact): Uint8Array {
  const roster = decodeMatchEnvelope(rosterArtifact.canonicalBytes);
  if (roster.envelope.type !== "ROSTER") throw new Error("A signed roster is required");
  const body = decodeRosterBody(roster.envelope.body);
  const history = captureSessionHistory(session, MATCH_HISTORY_LIMITS);
  const ordered = orderEnvelopeTranscript(body.gameId, history.envelopes);
  const envelopes = ordered.filter(artifact => !bytesEqual(artifact.canonicalBytes, roster.canonicalBytes));
  if (envelopes.length !== ordered.length - 1) throw new Error("Signed roster is missing from the table history");
  return encodeCanonical({
    version: VERSION, rules_hash: body.rulesHash, roster: roster.canonicalBytes,
    envelopes: envelopes.map(artifact => artifact.canonicalBytes),
  });
}

export async function verifyTranscript(bytes: Uint8Array): Promise<TranscriptVerification> {
  let round: number | undefined;
  const client = new CandidateShuffleClient();
  try {
    if (bytes.length > MAX_TRANSCRIPT_BYTES) throw new Error("Transcript exceeds the file size limit");
    const container = expectExactMap(decodeCanonical(bytes), FIELDS, "Transcript");
    if (container.version !== VERSION) throw new Error("Unsupported transcript version");
    const rulesHash = parseHash256(expectByteString(container.rules_hash, "rules_hash"));
    if (!bytesEqual(rulesHash, liveRulesHash())) throw new Error("Unknown rules hash");

    const signedRoster = decodeMatchEnvelope(expectByteString(container.roster, "roster"));
    const rosterEnvelope = signedRoster.envelope;
    if (rosterEnvelope.type !== "ROSTER") throw new Error("Transcript roster must be a signed ROSTER");
    const roster = decodeRosterBody(rosterEnvelope.body);
    if (roster.seats.length !== 4 || !bytesEqual(roster.rulesHash, rulesHash)) {
      throw new Error("Signed roster does not match the Sasku profile");
    }

    const entries = expectArray(container.envelopes, "envelopes");
    if (entries.length >= MATCH_HISTORY_LIMITS.maxEnvelopes) throw new Error("Too many transcript envelopes");
    let totalBytes = signedRoster.canonicalBytes.length;
    const envelopes = entries.map((value, index) => {
      try {
        const encoded = expectByteString(value, `envelopes[${index}]`);
        totalBytes += encoded.length;
        if (totalBytes > MATCH_HISTORY_LIMITS.maxBytes) throw new Error("Transcript exceeds the history byte limit");
        return decodeMatchEnvelope(encoded);
      } catch (cause) {
        throw new Error(`Transcript envelope ${index} is invalid`, { cause });
      }
    });
    const ordered = orderEnvelopeTranscript(roster.gameId, [...envelopes, signedRoster]);
    if (ordered.some(({ envelope }) => !roster.seats.some(seat => bytesEqual(seat, envelope.from)))) {
      throw new Error("Transcript has an envelope from outside the signed roster");
    }
    const orderedEntries = ordered.filter(artifact => !bytesEqual(artifact.canonicalBytes, signedRoster.canonicalBytes));
    if (orderedEntries.some((artifact, index) => !bytesEqual(artifact.canonicalBytes, envelopes[index]!.canonicalBytes))) {
      throw new Error("Transcript envelopes are out of canonical sender order");
    }
    const lobby = recoverLobby({
      gameId: roster.gameId, host: rosterEnvelope.from, rulesHash, iceConfigHash: roster.iceConfigHash,
    }, ordered.filter(isLobbyEnvelope), signedRoster).lobby;
    const session = lobby.finalizedRegistry;
    if (!session) throw new Error("Signed roster is missing readiness from all four seats");

    // Setup and round prefixes must follow each sender's confirmed lobby history.
    const setup: EnvelopeArtifact[] = [];
    const rounds = new Map<number, EnvelopeArtifact[]>();
    let priorSender: Uint8Array | undefined;
    let priorRound = 0;
    for (const artifact of ordered) {
      const e = artifact.envelope;
      if (isLobbyEnvelope(artifact)) continue;
      if (!priorSender || !bytesEqual(priorSender, e.from)) {
        priorSender = e.from;
        priorRound = 0;
      }
      if (e.type === "KEY_SHARE" && e.round === 0 && priorRound === 0) {
        setup.push(artifact);
      } else if (["SHUFFLE", "SHARES", "ACTION", "AUDIT_DISCLOSE"].includes(e.type) &&
        e.round >= 1 && e.round <= MAX_SASKU_MATCH_ROUNDS && e.round >= priorRound) {
        const group = rounds.get(e.round) ?? [];
        group.push(artifact);
        rounds.set(e.round, group);
        priorRound = e.round;
      } else {
        throw new Error(`Invalid match traffic at sequence ${e.seq}`);
      }
    }

    restorePrefix(session, setup);
    const setupComplete = recoverSetup(roster.gameId, 0, roster.seats, setup, false).coordinator.state === "complete";
    if (!setupComplete && rounds.size) throw new Error("Round traffic precedes completed setup");
    let match = INITIAL_SASKU_MATCH;
    const receiver = new PersistentSessionReceiver(session, {
      async persistAcceptedEnvelope() { throw new Error("Transcript replay attempted a write"); },
    });

    for (round = 1; rounds.has(round); round += 1) {
      if (match.winner !== null) throw new Error("Transcript continues after the winning round");
      restorePrefix(session, rounds.get(round)!);
      const policy = liveRoundPolicy(round);
      const owner = await CandidateSaskuRoundOwner.open({
        session, sessionReceiver: receiver, roster, self: rosterEnvelope.from, verifier: client, dealBackend: client, ...policy,
      });
      try {
        const snapshot = owner.snapshot;
        const audit = snapshot.phase === "round" ? snapshot.state.audit?.result : null;
        if (audit?.status === "violation") {
          return { ...audit, round, message: `Player ${audit.seat + 1} violated ${audit.rule.replaceAll("_", " ")} on action ${audit.at + 1}` };
        }
        rounds.delete(round);
        if (audit?.status !== "valid") break;
        match = recordSaskuRound(match, policy.dealer, audit.score);
      } finally {
        owner.close();
      }
    }
    if (rounds.size) throw new Error("Transcript advances past a missing or unverified round");
    return { status: match.winner === null ? "incomplete" : "verified", match };
  } catch (error) {
    return { status: "violation", message: errorMessage(error), ...(round === undefined ? {} : { round }) };
  } finally {
    client.close();
  }
}

function restorePrefix(session: SessionChainRegistry, artifacts: readonly EnvelopeArtifact[]): void {
  for (const artifact of artifacts) {
    const result = session.ingest(artifact);
    if (result.status !== "accepted") {
      const reason = result.status === "rejected" ? result.reason : result.status;
      throw new Error(`Cannot restore ${artifact.envelope.type} at sequence ${artifact.envelope.seq}: ${reason}`);
    }
  }
}

function errorMessage(error: unknown): string {
  if (!(error instanceof Error)) return "Transcript verification failed";
  return error.cause instanceof Error ? `${error.message}. ${errorMessage(error.cause)}` : error.message;
}
