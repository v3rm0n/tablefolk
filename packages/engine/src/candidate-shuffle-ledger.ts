import { bytesEqual } from "@p2pcards/crypto";
import type { CborMap } from "@p2pcards/encoding";
import { CardPointTable, initialMaskedCard, decodeCandidateShuffleStatement36, encodeCandidateShuffleStatement36,
  decodeCandidateShuffleProof36, type DeckSpec, type MaskedCard } from "@p2pcards/deck";
import { decodeAndVerifyEnvelope, decodeRosterBody, encodeRosterBody, hashRosterBody,
  type RosterBody } from "@p2pcards/protocol";
import { SetupEnvelopeCoordinator } from "./setup-envelope-coordinator";

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
  #seat = 0;
  #busy = false;
  #closed = false;
  readonly #accepted: Uint8Array[] = [];

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

  /** Optional owner barrier runs after verification, before any state mutation. */
  async accept(bytes: Uint8Array, beforeCommit?: () => Promise<void>): Promise<"accepted" | "duplicate"> {
    if (this.#closed) throw new Error("Shuffle ledger is closed");
    if (this.#busy) throw new Error("Shuffle verification is busy");
    if (!(bytes instanceof Uint8Array) || bytes.constructor !== Uint8Array || bytes.length > 16 * 1024) throw new Error("Invalid shuffle envelope size");
    const captured = bytes.slice();
    // Reverify canonical bytes; do not trust an externally supplied artifact or sender label.
    const { envelope } = decodeAndVerifyEnvelope(captured);
    if (this.#accepted.some(previous => bytesEqual(previous, captured))) {
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
      if (await this.#options.verifier.verify(statementBytes.slice(), proofBytes.slice()) !== true) throw new Error("Invalid shuffle proof");
      if (this.#closed) throw new Error("Shuffle ledger closed during verification");
      await beforeCommit?.();
      if (this.#closed) throw new Error("Shuffle ledger closed during receipt");
      this.#deck = statement.outputDeck;
      this.#accepted.push(captured);
      this.#seat++;
      return "accepted";
    } finally { this.#busy = false; }
  }
}
