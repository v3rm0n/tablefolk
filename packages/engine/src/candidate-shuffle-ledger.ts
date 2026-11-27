import { bytesEqual, bytesToHex, RistrettoPoint } from "@p2pcards/crypto";
import type { CborMap } from "@p2pcards/encoding";
import { CardPointTable, initialMaskedCard, decodeCandidateShuffleStatement36, encodeCandidateShuffleStatement36,
  decodeCandidateShuffleProof36, type DeckSpec, type MaskedCard } from "@p2pcards/deck";
import { decodeAndVerifyEnvelope, decodeRosterBody, encodeRosterBody, hashRosterBody,
  verifyEnvelopeArtifact, type EnvelopeArtifact, type RosterBody } from "@p2pcards/protocol";
import { SetupEnvelopeCoordinator } from "./setup-envelope-coordinator";

export interface CandidateShuffleCheckpoint {
  readonly hashes: readonly string[];
  readonly deck: readonly (readonly [Uint8Array, Uint8Array])[];
}

export interface CandidateShuffleVerifier {
  verify(statement: Uint8Array, proof: Uint8Array): Promise<boolean>;
}
export interface CandidateShuffleLedgerOptions {
  readonly setup: SetupEnvelopeCoordinator;
  /** Must come from the application's admitted lobby; this ledger does not establish READY. */
  readonly roster: RosterBody;
  readonly round: number;
  readonly deckSpec: DeckSpec;
  readonly verifier: CandidateShuffleVerifier;
}

/** Candidate proof/order ledger. Signature validation does not replace durable sender-chain admission. */
export class CandidateShuffleLedger {
  readonly #options: CandidateShuffleLedgerOptions;
  readonly #roster: RosterBody;
  #deck: readonly MaskedCard[];
  #encodedDeck: CandidateShuffleCheckpoint["deck"] | null = null;
  #seat = 0;
  #prepared: { seat: number; statement: Uint8Array; proof: Uint8Array } | null = null;
  #busy = false;
  #closed = false;
  readonly #accepted: string[] = [];

  constructor(options: CandidateShuffleLedgerOptions) {
    if (!(options.setup instanceof SetupEnvelopeCoordinator) || options.setup.state !== "complete" ||
      options.setup.aggregateKey === null) throw new Error("Shuffle requires completed setup");
    const roster = decodeRosterBody(encodeRosterBody(options.roster));
    if (roster.seats.length !== 4 || options.setup.roster.length !== 4 || !bytesEqual(roster.gameId, options.setup.gameId) ||
      roster.seats.some((id, i) => !bytesEqual(id, options.setup.roster[i]!))) throw new Error("Shuffle roster differs from setup");
    if (!Number.isSafeInteger(options.round) || options.round < options.setup.round || Object.is(options.round, -0)) throw new Error("Invalid shuffle round");
    const table = new CardPointTable(options.deckSpec);
    if (table.size !== 36) throw new Error("Candidate shuffle requires 36 cards");
    this.#options = Object.freeze({ ...options, round: options.round });
    this.#roster = roster;
    this.#deck = Object.freeze(Array.from({ length: 36 }, (_, i) => initialMaskedCard(table.pointAt(i))));
  }

  exportCheckpoint(): CandidateShuffleCheckpoint {
    this.#encodedDeck ??= this.#deck.map(({ A, B }) => [A.toBytes(), B.toBytes()] as const);
    return { hashes: [...this.#accepted], deck: this.#encodedDeck.map(([A, B]) => [A.slice(), B.slice()]) };
  }

  /** Restore public derived state only after the caller matches local transcript heads. */
  restoreTrustedCheckpoint(state: CandidateShuffleCheckpoint, contributions: readonly EnvelopeArtifact[]): void {
    if (this.#seat !== 0 || this.#busy || this.#closed || contributions.length > 4 ||
        state.hashes.length !== contributions.length || state.deck.length !== 36 ||
        contributions.some((artifact, seat) => state.hashes[seat] !== bytesToHex(artifact.hash))) {
      throw new Error("Invalid shuffle checkpoint");
    }
    this.#deck = Object.freeze(state.deck.map(([A, B]) => Object.freeze({
      A: RistrettoPoint.fromBytes(A), B: RistrettoPoint.fromBytes(B),
    })));
    this.#encodedDeck = state.deck.map(([A, B]) => [A.slice(), B.slice()]);
    this.#accepted.push(...state.hashes);
    this.#seat = contributions.length;
  }

  get nextSeat(): number | null { return this.#seat === 4 ? null : this.#seat; }
  get complete(): boolean { return !this.#closed && this.#seat === 4; }
  /** Captured public preparation request; both decks initially equal the preceding verified deck. */
  nextStatement(): Uint8Array {
    if (this.#closed || this.#seat === 4) throw new Error("Shuffle ledger is closed or complete");
    return encodeCandidateShuffleStatement36({ gameId: this.#roster.gameId, round: this.#options.round,
      seat: this.#seat, rosterHash: hashRosterBody(this.#roster), aggregateKey: this.#options.setup.aggregateKey!,
      inputDeck: this.#deck, outputDeck: this.#deck });
  }
  get finalDeck(): readonly MaskedCard[] {
    if (!this.complete) throw new Error("Shuffle chain is incomplete");
    return this.#deck;
  }
  close(): void { this.#closed = true; }

  async verifyPrepared(statement: Uint8Array, proof: Uint8Array): Promise<boolean> {
    const seat = this.#seat;
    const captured = { seat, statement: statement.slice(), proof: proof.slice() };
    const valid = await this.#options.verifier.verify(captured.statement.slice(), captured.proof.slice()) === true;
    if (valid && this.#seat === seat && !this.#closed) this.#prepared = captured;
    return valid;
  }

  /** Optional owner barrier runs after verification, before any state mutation. */
  async accept(candidate: Uint8Array | EnvelopeArtifact, beforeCommit?: () => Promise<void>): Promise<"accepted" | "duplicate"> {
    if (this.#closed) throw new Error("Shuffle ledger is closed");
    if (this.#busy) throw new Error("Shuffle verification is busy");
    const bytes = candidate instanceof Uint8Array ? candidate : candidate.canonicalBytes;
    if (!(bytes instanceof Uint8Array) || bytes.constructor !== Uint8Array || bytes.length > 16 * 1024) throw new Error("Invalid shuffle envelope size");
    const artifact = candidate instanceof Uint8Array ? decodeAndVerifyEnvelope(bytes) : verifyEnvelopeArtifact(candidate, bytes);
    const { envelope } = artifact;
    const hash = bytesToHex(artifact.hash);
    if (this.#accepted.includes(hash)) {
      this.#busy = true;
      try {
        await beforeCommit?.();
        if (this.#closed) throw new Error("Shuffle ledger closed during receipt");
        return "duplicate";
      } finally { this.#busy = false; }
    }
    if (this.#seat === 4) throw new Error("Shuffle chain is complete");
    if (envelope.type !== "SHUFFLE" || !bytesEqual(envelope.game, this.#roster.gameId) ||
      envelope.round !== this.#options.round || envelope.phase !== `round.${this.#options.round}.shuffle.${this.#seat}` ||
      !bytesEqual(envelope.from, this.#roster.seats[this.#seat]!)) throw new Error("Wrong shuffle envelope scope or sender");
    const body = envelope.body;
    if (typeof body !== "object" || body === null || Array.isArray(body) || body instanceof Uint8Array ||
      Object.keys(body).sort().join(",") !== "proof,statement") throw new Error("Invalid candidate shuffle body");
    const statementBytes = (body as CborMap)["statement"], proofBytes = (body as CborMap)["proof"];
    if (!(statementBytes instanceof Uint8Array) || !(proofBytes instanceof Uint8Array)) throw new Error("Invalid candidate shuffle body bytes");
    const statement = decodeCandidateShuffleStatement36(statementBytes);
    decodeCandidateShuffleProof36(proofBytes);
    const expected = decodeCandidateShuffleStatement36(this.nextStatement());
    if (!bytesEqual(encodeCandidateShuffleStatement36({ ...statement, outputDeck: expected.outputDeck }),
      encodeCandidateShuffleStatement36(expected))) throw new Error("Shuffle statement does not extend admitted state");
    this.#busy = true;
    try {
      // Backend gets detached copies, so an adapter cannot alter the admitted deck or artifact.
      const prepared = this.#prepared;
      if (!(prepared?.seat === this.#seat && bytesEqual(prepared.statement, statementBytes) && bytesEqual(prepared.proof, proofBytes)) &&
          await this.#options.verifier.verify(statementBytes.slice(), proofBytes.slice()) !== true) throw new Error("Invalid shuffle proof");
      if (this.#closed) throw new Error("Shuffle ledger closed during verification");
      await beforeCommit?.();
      if (this.#closed) throw new Error("Shuffle ledger closed during receipt");
      this.#deck = statement.outputDeck;
      this.#encodedDeck = null;
      this.#accepted.push(hash);
      this.#prepared = null;
      this.#seat++;
      return "accepted";
    } finally { this.#busy = false; }
  }
}
