import { bytesEqual } from "@p2pcards/crypto";
import type { CborMap } from "@p2pcards/encoding";
import { CardPointTable, initialMaskedCard, encodeCandidateShuffleStatement, unpackShuffleDeck,
  decodeCandidateShuffleProof, shuffleCardCount, type DeckSpec, type MaskedCard } from "@p2pcards/deck";
import { decodeAndVerifyEnvelope, decodeRosterBody, encodeRosterBody, hashRosterBody,
  type RosterBody } from "@p2pcards/protocol";
import { SetupEnvelopeCoordinator } from "./setup-envelope-coordinator";

const DIMENSIONS = Object.freeze({ rows: 4, columns: 9 });
const CARD_COUNT = shuffleCardCount(DIMENSIONS);

export interface CandidateShuffleBody {
  readonly outputDeck: Uint8Array;
  readonly proof: Uint8Array;
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
    if (table.size !== CARD_COUNT) throw new Error("Candidate shuffle requires 36 cards");
    this.#options = Object.freeze({ ...options, round: options.round });
    this.#roster = roster;
    this.#deck = Object.freeze(Array.from({ length: CARD_COUNT }, (_, i) => initialMaskedCard(table.pointAt(i))));
  }

  get nextSeat(): number | null { return this.#seat === 4 ? null : this.#seat; }
  get complete(): boolean { return !this.#closed && this.#seat === 4; }
  /** Captured public preparation request; both decks initially equal the preceding verified deck. */
  nextStatement(): Uint8Array { return this.#statement(this.#deck); }

  #statement(outputDeck: readonly MaskedCard[]): Uint8Array {
    if (this.#closed || this.#seat === 4) throw new Error("Shuffle ledger is closed or complete");
    return encodeCandidateShuffleStatement({ ...DIMENSIONS, gameId: this.#roster.gameId,
      round: this.#options.round, seat: this.#seat, rosterHash: hashRosterBody(this.#roster),
      aggregateKey: this.#options.setup.aggregateKey!, inputDeck: this.#deck, outputDeck });
  }

  #prepare({ outputDeck, proof }: CandidateShuffleBody) {
    decodeCandidateShuffleProof(proof, DIMENSIONS);
    const deck = unpackShuffleDeck(outputDeck, CARD_COUNT);
    return { statement: this.#statement(deck), deck };
  }

  async verifyPrepared(body: CandidateShuffleBody): Promise<boolean> {
    const { statement } = this.#prepare(body);
    return this.#options.verifier.verify(statement, body.proof.slice());
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
      Object.keys(body).sort().join(",") !== "outputDeck,proof") throw new Error("Invalid candidate shuffle body");
    const { outputDeck, proof } = body as CborMap;
    if (!(outputDeck instanceof Uint8Array) || !(proof instanceof Uint8Array)) throw new Error("Invalid candidate shuffle body bytes");
    const { statement, deck } = this.#prepare({ outputDeck, proof });
    this.#busy = true;
    try {
      // Backend gets detached copies, so an adapter cannot alter the admitted deck or artifact.
      if (await this.#options.verifier.verify(statement, proof.slice()) !== true) throw new Error("Invalid shuffle proof");
      if (this.#closed) throw new Error("Shuffle ledger closed during verification");
      await beforeCommit?.();
      if (this.#closed) throw new Error("Shuffle ledger closed during receipt");
      this.#deck = deck;
      this.#accepted.push(captured);
      this.#seat++;
      return "accepted";
    } finally { this.#busy = false; }
  }
}
