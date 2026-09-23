import {
  bytesEqual,
  bytesToHex,
  importEd25519PublicKey,
} from "@p2pcards/crypto";
import {
  decodeJoinBody,
  decodeReadyBody,
  decodeRosterBody,
  hashRosterBody,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  type EnvelopeArtifact,
  type GameId,
  type Hash256,
  type IdentityPublicKey,
  type JoinBody,
  type ReadyBody,
  type RosterBody,
} from "@p2pcards/protocol";

import { MIN_SESSION_SEATS, SessionChainRegistry } from "./chain-registry";
import {
  SenderChain,
  type ChainHead,
  type ChainIngestResult,
  type ChainRejection,
} from "./sender-chain";

export interface LobbyBootstrapContext {
  readonly gameId: GameId;
  readonly host: IdentityPublicKey;
  readonly rulesHash: Hash256;
  readonly iceConfigHash: Hash256;
}

export type LobbyJoinRejectionReason =
  | "wrong_game"
  | "wrong_type"
  | "wrong_phase"
  | "wrong_round"
  | "not_genesis"
  | "malformed_body"
  | "sender_mismatch"
  | "rules_mismatch";

export type LobbyRosterRejectionReason =
  | "wrong_game"
  | "wrong_sender"
  | "wrong_type"
  | "wrong_phase"
  | "wrong_round"
  | "malformed_body"
  | "body_game_mismatch"
  | "rules_mismatch"
  | "invalid_roster_identity"
  | "host_missing";

export type LobbyReadyRejectionReason =
  | "lobby_finalized"
  | "wrong_game"
  | "wrong_type"
  | "wrong_phase"
  | "wrong_round"
  | "no_roster"
  | "roster_not_finalizable"
  | "not_roster_member"
  | "malformed_body"
  | "roster_hash_mismatch"
  | "sender_chain_missing"
  | "unknown_roster_hash"
  | "not_in_history";

export type LobbyState = "forming" | "collecting_ready" | "finalized";

export interface LobbyReadyRejection {
  readonly status: "rejected";
  readonly reason: LobbyReadyRejectionReason;
  readonly received: EnvelopeArtifact;
}

export type LobbyJoinValidationResult =
  | {
      readonly status: "valid";
      readonly body: JoinBody;
    }
  | {
      readonly status: "rejected";
      readonly reason: LobbyJoinRejectionReason;
      readonly received: EnvelopeArtifact;
    };

export type LobbyRosterValidationResult =
  | {
      readonly status: "valid";
      readonly body: RosterBody;
      readonly rosterHash: Hash256;
      readonly iceConfigMatches: boolean;
    }
  | {
      readonly status: "rejected";
      readonly reason: LobbyRosterRejectionReason;
      readonly received: EnvelopeArtifact;
      readonly index?: number;
    };

export type LobbyChainIngestResult =
  | ChainIngestResult
  | {
      readonly status: "rejected";
      readonly reason: "wrong_game";
      readonly expected: GameId;
      readonly actual: GameId;
      readonly received: EnvelopeArtifact;
    }
  | {
      readonly status: "rejected";
      readonly reason: "unknown_sender";
      readonly sender: IdentityPublicKey;
      readonly received: EnvelopeArtifact;
    }
  | {
      readonly status: "rejected";
      readonly reason: "lobby_finalized";
      readonly received: EnvelopeArtifact;
    };

export type LobbyJoinBootstrapResult =
  | (Extract<ChainIngestResult, { status: "accepted" | "duplicate" }> & {
      readonly body: JoinBody;
    })
  | ChainRejection
  | Extract<LobbyJoinValidationResult, { status: "rejected" }>
  | {
      readonly status: "rejected";
      readonly reason: "not_roster_member";
      readonly received: EnvelopeArtifact;
    }
  | {
      readonly status: "rejected";
      readonly reason: "lobby_finalized";
      readonly received: EnvelopeArtifact;
    };

export type LobbyRosterIngestResult =
  | (Extract<ChainIngestResult, { status: "accepted" | "duplicate" }> & {
      readonly body: RosterBody;
      readonly rosterHash: Hash256;
      readonly iceConfigMatches: boolean;
    })
  | ChainRejection
  | Extract<LobbyRosterValidationResult, { status: "rejected" }>
  | {
      readonly status: "rejected";
      readonly reason: "lobby_finalized";
      readonly received: EnvelopeArtifact;
    };

export type LobbyReadyIngestResult =
  | {
      readonly status: "accepted" | "duplicate";
      readonly seat: number;
      readonly state: LobbyState;
      readonly body: ReadyBody;
      readonly received: EnvelopeArtifact;
      readonly chainResult: Extract<ChainIngestResult, { status: "accepted" | "duplicate" }>;
    }
  | ChainRejection
  | LobbyReadyRejection;

export type LobbyReadyRestoreResult =
  | {
      readonly status: "accepted" | "duplicate";
      readonly seat: number;
      readonly state: LobbyState;
      readonly body: ReadyBody;
      readonly received: EnvelopeArtifact;
    }
  | LobbyReadyRejection;

const ZERO_HASH = parseHash256(new Uint8Array(32));

export class LobbyChainRegistry {
  readonly #context: LobbyBootstrapContext;
  readonly #chains = new Map<string, SenderChain>();
  readonly #readyByRoster = new Map<string, Map<string, EnvelopeArtifact>>();
  readonly #knownRosters = new Map<string, RosterBody>();
  #roster: RosterBody | null = null;
  #rosterHash: Hash256 | null = null;
  #rosterArtifact: EnvelopeArtifact | null = null;
  #finalizedRegistry: SessionChainRegistry | null = null;

  constructor(context: LobbyBootstrapContext) {
    this.#context = normalizeContext(context);
    this.#chains.set(bytesToHex(this.#context.host), new SenderChain(this.#context.host));
  }

  get roster(): RosterBody | null {
    return this.#roster === null ? null : copyRoster(this.#roster);
  }

  get host(): IdentityPublicKey {
    return parseIdentityPublicKey(this.#context.host);
  }

  get rosterHash(): Hash256 | null {
    return this.#rosterHash === null ? null : parseHash256(this.#rosterHash);
  }

  get rosterArtifact(): EnvelopeArtifact | null {
    return this.#rosterArtifact;
  }

  get state(): LobbyState {
    if (this.#finalizedRegistry !== null) {
      return "finalized";
    }
    if (this.#roster !== null && this.#roster.seats.length >= MIN_SESSION_SEATS) {
      return "collecting_ready";
    }
    return "forming";
  }

  get readySeats(): readonly number[] {
    if (this.#roster === null) {
      return Object.freeze([]);
    }
    const seats: number[] = [];
    const ready = this.#currentReady();
    for (const [seat, sender] of this.#roster.seats.entries()) {
      if (ready?.has(bytesToHex(sender)) === true) {
        seats.push(seat);
      }
    }
    return Object.freeze(seats);
  }

  get finalizedRegistry(): SessionChainRegistry | null {
    return this.#finalizedRegistry;
  }

  hasSender(sender: IdentityPublicKey): boolean {
    return this.#chains.has(bytesToHex(parseIdentityPublicKey(sender)));
  }

  isRosterMember(sender: IdentityPublicKey): boolean {
    const key = bytesToHex(parseIdentityPublicKey(sender));
    return this.#roster?.seats.some((candidate) => bytesToHex(candidate) === key) ?? false;
  }

  headOf(sender: IdentityPublicKey): ChainHead | null {
    return this.#chains.get(bytesToHex(parseIdentityPublicKey(sender)))?.head ?? null;
  }

  get(sender: IdentityPublicKey, seq: number): EnvelopeArtifact | undefined {
    if (!Number.isSafeInteger(seq) || seq < 0) {
      throw new RangeError("Lobby sequence must be an unsigned safe integer");
    }
    return this.#chains.get(bytesToHex(parseIdentityPublicKey(sender)))?.get(seq);
  }

  classify(received: EnvelopeArtifact): LobbyChainIngestResult {
    if (this.#finalizedRegistry !== null) {
      return Object.freeze({ status: "rejected", reason: "lobby_finalized", received });
    }
    if (!bytesEqual(received.envelope.game, this.#context.gameId)) {
      return Object.freeze({
        status: "rejected",
        reason: "wrong_game",
        expected: parseGameId(this.#context.gameId),
        actual: parseGameId(received.envelope.game),
        received,
      });
    }

    const chain = this.#chains.get(bytesToHex(received.envelope.from));
    if (chain === undefined) {
      return Object.freeze({
        status: "rejected",
        reason: "unknown_sender",
        sender: parseIdentityPublicKey(received.envelope.from),
        received,
      });
    }
    return chain.classify(received);
  }

  ingest(received: EnvelopeArtifact): LobbyChainIngestResult {
    const classification = this.classify(received);
    if (classification.status !== "accepted") {
      return classification;
    }
    const chain = this.#chains.get(bytesToHex(received.envelope.from));
    if (chain === undefined) {
      throw new Error("Lobby sender disappeared between classification and ingestion");
    }
    return chain.ingest(received);
  }

  // Calling this method is the explicit admission decision for an unknown identity.
  classifyBootstrapJoin(received: EnvelopeArtifact): LobbyJoinBootstrapResult {
    if (this.#finalizedRegistry !== null) {
      return Object.freeze({ status: "rejected", reason: "lobby_finalized", received });
    }
    const validation = validateLobbyJoinEnvelope(received, this.#context);
    if (validation.status === "rejected") {
      return validation;
    }

    const key = bytesToHex(received.envelope.from);
    const existing = this.#chains.get(key);
    const chain = existing ?? new SenderChain(received.envelope.from);
    const result = chain.classify(received);
    if (result.status === "accepted" || result.status === "duplicate") {
      return Object.freeze({ ...result, body: validation.body });
    }
    return result;
  }

  // Calling this method is the explicit admission decision for an unknown identity.
  bootstrapJoin(received: EnvelopeArtifact): LobbyJoinBootstrapResult {
    const classification = this.classifyBootstrapJoin(received);
    if (classification.status !== "accepted") {
      return classification;
    }

    const key = bytesToHex(received.envelope.from);
    const existing = this.#chains.get(key);
    const chain = existing ?? new SenderChain(received.envelope.from);
    const result = chain.ingest(received);
    if (result.status !== "accepted") {
      throw new Error(`Lobby JOIN changed between classification and ingestion: ${result.status}`);
    }
    if (existing === undefined) {
      this.#chains.set(key, chain);
    }
    return Object.freeze({ ...result, body: classification.body });
  }

  classifyRosterMemberJoin(received: EnvelopeArtifact): LobbyJoinBootstrapResult {
    if (!this.isRosterMember(received.envelope.from)) {
      return Object.freeze({
        status: "rejected",
        reason: "not_roster_member",
        received,
      });
    }
    return this.classifyBootstrapJoin(received);
  }

  bootstrapRosterMemberJoin(received: EnvelopeArtifact): LobbyJoinBootstrapResult {
    const classification = this.classifyRosterMemberJoin(received);
    if (classification.status === "rejected") {
      return classification;
    }
    return this.bootstrapJoin(received);
  }

  classifyRoster(received: EnvelopeArtifact): LobbyRosterIngestResult {
    if (this.#finalizedRegistry !== null) {
      return Object.freeze({ status: "rejected", reason: "lobby_finalized", received });
    }
    const validation = validateLobbyRosterEnvelope(received, this.#context);
    if (validation.status === "rejected") {
      return validation;
    }

    const hostChain = this.#chains.get(bytesToHex(this.#context.host));
    if (hostChain === undefined) {
      throw new Error("Lobby registry lost its host chain");
    }
    const result = hostChain.classify(received);
    if (result.status === "accepted" || result.status === "duplicate") {
      return Object.freeze({
        ...result,
        body: copyRoster(validation.body),
        rosterHash: parseHash256(validation.rosterHash),
        iceConfigMatches: validation.iceConfigMatches,
      });
    }
    return result;
  }

  ingestRoster(received: EnvelopeArtifact): LobbyRosterIngestResult {
    const classification = this.classifyRoster(received);
    if (classification.status !== "accepted") {
      return classification;
    }
    const hostChain = this.#chains.get(bytesToHex(this.#context.host));
    if (hostChain === undefined) {
      throw new Error("Lobby registry lost its host chain");
    }
    const result = hostChain.ingest(received);
    if (result.status !== "accepted") {
      throw new Error(
        `Lobby roster changed between classification and ingestion: ${result.status}`,
      );
    }
    this.#roster = copyRoster(classification.body);
    this.#rosterHash = parseHash256(classification.rosterHash);
    this.#rosterArtifact = received;
    this.#knownRosters.set(
      bytesToHex(classification.rosterHash),
      copyRoster(classification.body),
    );
    this.#finalizeIfReady();
    return Object.freeze({
      ...classification,
      ...result,
      body: copyRoster(classification.body),
      rosterHash: parseHash256(classification.rosterHash),
    });
  }

  classifyReady(received: EnvelopeArtifact): LobbyReadyIngestResult {
    if (this.#finalizedRegistry !== null) {
      return rejectReady("lobby_finalized", received);
    }

    const envelope = received.envelope;
    if (!bytesEqual(envelope.game, this.#context.gameId)) {
      return rejectReady("wrong_game", received);
    }
    if (envelope.type !== "READY") {
      return rejectReady("wrong_type", received);
    }
    if (envelope.phase !== "lobby") {
      return rejectReady("wrong_phase", received);
    }
    if (envelope.round !== 0) {
      return rejectReady("wrong_round", received);
    }
    if (this.#roster === null || this.#rosterHash === null) {
      return rejectReady("no_roster", received);
    }
    if (this.#roster.seats.length < MIN_SESSION_SEATS) {
      return rejectReady("roster_not_finalizable", received);
    }

    const senderKey = bytesToHex(envelope.from);
    const seat = this.#roster.seats.findIndex(
      (identity) => bytesToHex(identity) === senderKey,
    );
    if (seat < 0) {
      return rejectReady("not_roster_member", received);
    }

    let body: ReadyBody;
    try {
      body = decodeReadyBody(envelope.body);
    } catch {
      return rejectReady("malformed_body", received);
    }
    if (!bytesEqual(body.rosterHash, this.#rosterHash)) {
      return rejectReady("roster_hash_mismatch", received);
    }

    const chain = this.#chains.get(senderKey);
    if (chain === undefined) {
      return rejectReady("sender_chain_missing", received);
    }
    const chainResult = chain.classify(received);
    if (chainResult.status === "rejected") {
      return chainResult;
    }

    const rosterKey = bytesToHex(this.#rosterHash);
    const ready = this.#readyByRoster.get(rosterKey) ?? new Map<string, EnvelopeArtifact>();
    const duplicate = chainResult.status === "duplicate" || ready.has(senderKey);
    const state =
      !duplicate && ready.size + 1 === this.#roster.seats.length
        ? "finalized"
        : this.state;
    return Object.freeze({
      status: duplicate ? "duplicate" : "accepted",
      seat,
      state,
      body,
      received,
      chainResult,
    });
  }

  ingestReady(received: EnvelopeArtifact): LobbyReadyIngestResult {
    const classification = this.classifyReady(received);
    if (classification.status === "rejected") {
      return classification;
    }
    if (classification.chainResult.status === "duplicate") {
      return classification;
    }

    const senderKey = bytesToHex(received.envelope.from);
    const chain = this.#chains.get(senderKey);
    if (chain === undefined) {
      throw new Error("Lobby READY sender disappeared between classification and ingestion");
    }
    const chainResult = chain.ingest(received);
    if (chainResult.status !== "accepted") {
      throw new Error(
        `Lobby READY changed between classification and ingestion: ${chainResult.status}`,
      );
    }

    if (classification.status === "accepted") {
      const rosterKey = bytesToHex(classification.body.rosterHash);
      const ready = this.#readyByRoster.get(rosterKey) ?? new Map<string, EnvelopeArtifact>();
      ready.set(senderKey, received);
      this.#readyByRoster.set(rosterKey, ready);
      this.#finalizeIfReady();
    }
    return Object.freeze({
      ...classification,
      state: this.state,
      chainResult,
    });
  }

  restoreReadyFromHistory(received: EnvelopeArtifact): LobbyReadyRestoreResult {
    if (this.#finalizedRegistry !== null) {
      return rejectReady("lobby_finalized", received);
    }
    const envelope = received.envelope;
    if (!bytesEqual(envelope.game, this.#context.gameId)) {
      return rejectReady("wrong_game", received);
    }
    if (envelope.type !== "READY") {
      return rejectReady("wrong_type", received);
    }
    if (envelope.phase !== "lobby") {
      return rejectReady("wrong_phase", received);
    }
    if (envelope.round !== 0) {
      return rejectReady("wrong_round", received);
    }

    let body: ReadyBody;
    try {
      body = decodeReadyBody(envelope.body);
    } catch {
      return rejectReady("malformed_body", received);
    }
    const rosterKey = bytesToHex(body.rosterHash);
    const roster = this.#knownRosters.get(rosterKey);
    if (roster === undefined) {
      return rejectReady("unknown_roster_hash", received);
    }
    if (roster.seats.length < MIN_SESSION_SEATS) {
      return rejectReady("roster_not_finalizable", received);
    }

    const senderKey = bytesToHex(envelope.from);
    const seat = roster.seats.findIndex((identity) => bytesToHex(identity) === senderKey);
    if (seat < 0) {
      return rejectReady("not_roster_member", received);
    }
    const historical = this.#chains.get(senderKey)?.get(envelope.seq);
    if (
      historical === undefined ||
      !bytesEqual(historical.canonicalBytes, received.canonicalBytes)
    ) {
      return rejectReady("not_in_history", received);
    }

    const ready = this.#readyByRoster.get(rosterKey) ?? new Map<string, EnvelopeArtifact>();
    const duplicate = ready.has(senderKey);
    if (!duplicate) {
      ready.set(senderKey, historical);
      this.#readyByRoster.set(rosterKey, ready);
      if (this.#rosterHash !== null && bytesEqual(body.rosterHash, this.#rosterHash)) {
        this.#finalizeIfReady();
      }
    }
    return Object.freeze({
      status: duplicate ? "duplicate" : "accepted",
      seat,
      state: this.state,
      body,
      received: historical,
    });
  }

  #buildFinalizedRegistry(): SessionChainRegistry {
    if (this.#roster === null) {
      throw new Error("Cannot finalize a lobby without a roster");
    }
    const registry = new SessionChainRegistry(this.#context.gameId, this.#roster.seats);
    for (const sender of this.#roster.seats) {
      const chain = this.#chains.get(bytesToHex(sender));
      if (chain === undefined) {
        throw new Error("Cannot finalize a roster member without a complete sender chain");
      }
      const head = chain.head;
      if (head === null) {
        throw new Error("Cannot finalize a roster member without a complete sender chain");
      }
      for (let seq = 0; seq <= head.seq; seq += 1) {
        const artifact = chain.get(seq);
        if (artifact === undefined) {
          throw new Error("Lobby sender chain is not contiguous");
        }
        const result = registry.ingest(artifact);
        if (result.status !== "accepted") {
          const detail = result.status === "rejected" ? result.reason : result.status;
          throw new Error(`Could not transfer lobby sender chain: ${detail}`);
        }
      }
    }
    return registry;
  }

  #currentReady(): ReadonlyMap<string, EnvelopeArtifact> | null {
    if (this.#rosterHash === null) {
      return null;
    }
    return this.#readyByRoster.get(bytesToHex(this.#rosterHash)) ?? null;
  }

  #finalizeIfReady(): void {
    if (
      this.#finalizedRegistry !== null ||
      this.#roster === null ||
      this.#roster.seats.length < MIN_SESSION_SEATS
    ) {
      return;
    }
    const ready = this.#currentReady();
    if (ready !== null && ready.size === this.#roster.seats.length) {
      this.#finalizedRegistry = this.#buildFinalizedRegistry();
    }
  }
}

export function validateLobbyJoinEnvelope(
  received: EnvelopeArtifact,
  context: LobbyBootstrapContext,
): LobbyJoinValidationResult {
  const expected = normalizeContext(context);
  const envelope = received.envelope;
  if (!bytesEqual(envelope.game, expected.gameId)) {
    return rejectJoin("wrong_game", received);
  }
  if (envelope.type !== "JOIN") {
    return rejectJoin("wrong_type", received);
  }
  if (envelope.phase !== "lobby") {
    return rejectJoin("wrong_phase", received);
  }
  if (envelope.round !== 0) {
    return rejectJoin("wrong_round", received);
  }
  if (envelope.seq !== 0 || !bytesEqual(envelope.prev, ZERO_HASH)) {
    return rejectJoin("not_genesis", received);
  }

  let body: JoinBody;
  try {
    body = decodeJoinBody(envelope.body);
  } catch {
    return rejectJoin("malformed_body", received);
  }
  if (!bytesEqual(body.pkId, envelope.from)) {
    return rejectJoin("sender_mismatch", received);
  }
  if (!bytesEqual(body.rulesHash, expected.rulesHash)) {
    return rejectJoin("rules_mismatch", received);
  }
  return Object.freeze({ status: "valid", body });
}

export function validateLobbyRosterEnvelope(
  received: EnvelopeArtifact,
  context: LobbyBootstrapContext,
): LobbyRosterValidationResult {
  const expected = normalizeContext(context);
  const envelope = received.envelope;
  if (!bytesEqual(envelope.game, expected.gameId)) {
    return rejectRoster("wrong_game", received);
  }
  if (!bytesEqual(envelope.from, expected.host)) {
    return rejectRoster("wrong_sender", received);
  }
  if (envelope.type !== "ROSTER") {
    return rejectRoster("wrong_type", received);
  }
  if (envelope.phase !== "lobby") {
    return rejectRoster("wrong_phase", received);
  }
  if (envelope.round !== 0) {
    return rejectRoster("wrong_round", received);
  }

  let body: RosterBody;
  try {
    body = decodeRosterBody(envelope.body);
  } catch {
    return rejectRoster("malformed_body", received);
  }
  if (!bytesEqual(body.gameId, expected.gameId)) {
    return rejectRoster("body_game_mismatch", received);
  }
  if (!bytesEqual(body.rulesHash, expected.rulesHash)) {
    return rejectRoster("rules_mismatch", received);
  }
  for (const [index, identity] of body.seats.entries()) {
    try {
      importEd25519PublicKey(identity);
    } catch {
      return rejectRoster("invalid_roster_identity", received, index);
    }
  }
  if (!body.seats.some((identity) => bytesEqual(identity, expected.host))) {
    return rejectRoster("host_missing", received);
  }

  return Object.freeze({
    status: "valid",
    body,
    rosterHash: hashRosterBody(body),
    iceConfigMatches: bytesEqual(body.iceConfigHash, expected.iceConfigHash),
  });
}

function normalizeContext(context: LobbyBootstrapContext): LobbyBootstrapContext {
  const host = parseIdentityPublicKey(context.host);
  importEd25519PublicKey(host);
  return Object.freeze({
    gameId: parseGameId(context.gameId),
    host,
    rulesHash: parseHash256(context.rulesHash),
    iceConfigHash: parseHash256(context.iceConfigHash),
  });
}

function copyRoster(body: RosterBody): RosterBody {
  return Object.freeze({
    gameId: parseGameId(body.gameId),
    rulesHash: parseHash256(body.rulesHash),
    iceConfigHash: parseHash256(body.iceConfigHash),
    seats: Object.freeze(body.seats.map(parseIdentityPublicKey)),
  });
}

function rejectJoin(
  reason: LobbyJoinRejectionReason,
  received: EnvelopeArtifact,
): Extract<LobbyJoinValidationResult, { status: "rejected" }> {
  return Object.freeze({ status: "rejected", reason, received });
}

function rejectRoster(
  reason: LobbyRosterRejectionReason,
  received: EnvelopeArtifact,
  index?: number,
): Extract<LobbyRosterValidationResult, { status: "rejected" }> {
  if (index === undefined) {
    return Object.freeze({ status: "rejected", reason, received });
  }
  return Object.freeze({ status: "rejected", reason, received, index });
}

function rejectReady(
  reason: LobbyReadyRejectionReason,
  received: EnvelopeArtifact,
): LobbyReadyRejection {
  return Object.freeze({ status: "rejected", reason, received });
}
