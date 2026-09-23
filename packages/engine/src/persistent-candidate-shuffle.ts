import { bytesEqual } from "@p2pcards/crypto";
import { decodeCandidateShuffleStatement36, decodeCandidateShuffleProof36, encodeCandidateShuffleStatement36,
  type DeckSpec, type MaskedCard } from "@p2pcards/deck";
import { decodeAndVerifyEnvelope, decodeRosterBody, encodeRosterBody, parseIdentityPublicKey,
  type EnvelopeArtifact, type IdentityPublicKey, type RosterBody } from "@p2pcards/protocol";
import { captureSessionHistory, PersistentEnvelopeAuthor, PersistentSessionReceiver, SessionChainRegistry,
  type CapturedSessionHistory, type SessionHistoryCaptureLimits } from "@p2pcards/session";
import { CandidateShuffleLedger, type CandidateShuffleVerifier } from "./candidate-shuffle-ledger";
import { recoverSetup } from "./setup-recovery";

export interface PersistentCandidateShuffleOptions {
  readonly session: SessionChainRegistry;
  readonly sessionReceiver: PersistentSessionReceiver;
  readonly roster: RosterBody;
  readonly self: IdentityPublicKey;
  readonly setupRound: number;
  readonly round: number;
  readonly deckSpec: DeckSpec;
  readonly verifier: CandidateShuffleVerifier;
  readonly historyLimits?: SessionHistoryCaptureLimits;
}
export interface CandidateShuffleSnapshot { readonly nextSeat: number | null; readonly complete: boolean }
export type PersistentCandidateShuffleResult =
  | { readonly status: "accepted" | "duplicate"; readonly received: EnvelopeArtifact; readonly snapshot: CandidateShuffleSnapshot }
  | { readonly status: "rejected"; readonly reason: string; readonly received: EnvelopeArtifact };

class ChainRejection extends Error { constructor(readonly reason: string) { super(reason); } }

/** One active operation, no queue. Owns proof admission and durable receipt; never accepts an arbitrary recovered deck. */
export class PersistentCandidateShuffleReceiver {
  readonly #options: PersistentCandidateShuffleOptions;
  readonly #ledger: CandidateShuffleLedger;
  #checkpoint: CapturedSessionHistory;
  #snapshot: CandidateShuffleSnapshot;
  #busy = false;
  #closed = false;
  #failure: Error | null = null;

  private constructor(options: PersistentCandidateShuffleOptions, ledger: CandidateShuffleLedger, history: CapturedSessionHistory) {
    this.#options = options; this.#ledger = ledger; this.#checkpoint = history;
    this.#snapshot = Object.freeze({ nextSeat: ledger.nextSeat, complete: ledger.complete });
  }

  /** Caller restores complete sender prefixes from durable storage before opening. No writes occur during replay. */
  static async open(input: PersistentCandidateShuffleOptions): Promise<PersistentCandidateShuffleReceiver> {
    if (!(input.session instanceof SessionChainRegistry) || !(input.sessionReceiver instanceof PersistentSessionReceiver) ||
      !input.sessionReceiver.isBoundTo(input.session)) throw new Error("Shuffle receiver requires its bound durable session receiver");
    if (!Number.isSafeInteger(input.setupRound) || input.setupRound < 0 || Object.is(input.setupRound, -0)) throw new Error("Invalid setup round");
    const roster = decodeRosterBody(encodeRosterBody(input.roster));
    const self = parseIdentityPublicKey(input.self);
    if (!bytesEqual(roster.gameId, input.session.gameId) || roster.seats.length !== 4 || input.session.roster.length !== 4 ||
      roster.seats.some((id, seat) => !bytesEqual(id, input.session.roster[seat]!)) || !roster.seats.some(id => bytesEqual(id, self))) throw new Error("Shuffle session scope mismatch");
    const options = Object.freeze({ ...input, roster, self, deckSpec: Object.freeze({ id: input.deckSpec.id, cards: Object.freeze([...input.deckSpec.cards]) }),
      ...(input.historyLimits === undefined ? {} : { historyLimits: Object.freeze({ ...input.historyLimits }) }) });
    const history = captureSessionHistory(options.session, options.historyLimits);
    const setup = recoverSetup(roster.gameId, options.setupRound, roster.seats, history.envelopes).coordinator;
    const ledger = new CandidateShuffleLedger({ setup, roster, round: options.round, deckSpec: options.deckSpec, verifier: options.verifier });
    try {
      const contributions = history.envelopes.filter(a => a.envelope.type === "SHUFFLE" && a.envelope.round === options.round);
      if (contributions.length > 4) throw new Error("Too many stored shuffle contributions");
      const seatOf = (a: EnvelopeArtifact) => roster.seats.findIndex(id => bytesEqual(id, a.envelope.from));
      contributions.sort((a, b) => seatOf(a) - seatOf(b));
      for (const artifact of contributions) {
        const ownSetup = history.envelopes.filter(a => bytesEqual(a.envelope.from, artifact.envelope.from) &&
          ["KEY_SHARE", "RAND_COMMIT", "RAND_REVEAL"].includes(a.envelope.type));
        if (ownSetup.some(a => a.envelope.seq >= artifact.envelope.seq)) throw new Error("Stored shuffle precedes sender setup");
        await ledger.accept(artifact.canonicalBytes);
        history.assertUnchanged();
      }
      const later = history.envelopes.filter(a => a.envelope.round === options.round && ["SHARES", "ACTION", "AUDIT_DISCLOSE"].includes(a.envelope.type));
      if (later.length && !ledger.complete) throw new Error("Stored round activity lacks a complete shuffle chain");
      for (const artifact of later) {
        const own = contributions.find(a => bytesEqual(a.envelope.from, artifact.envelope.from));
        if (!own || own.envelope.seq >= artifact.envelope.seq) throw new Error("Stored round activity precedes sender shuffle");
      }
      history.assertUnchanged();
      return new PersistentCandidateShuffleReceiver(options, ledger, history);
    } catch (error) { ledger.close(); throw error; }
  }

  get snapshot(): CandidateShuffleSnapshot { return this.#snapshot; }
  get failure(): Error | null { return this.#failure; }
  get closed(): boolean { return this.#closed; }
  get busy(): boolean { return this.#busy; }
  nextStatement(): Uint8Array { this.#guard(); return this.#ledger.nextStatement(); }
  get finalDeck(): readonly MaskedCard[] { this.#guard(); return this.#ledger.finalDeck; }
  close(): void { this.#closed = true; this.#ledger.close(); }

  async receive(candidate: EnvelopeArtifact): Promise<PersistentCandidateShuffleResult> {
    this.#begin();
    try { return await this.#receiveOne(capture(candidate)); }
    finally { this.#busy = false; }
  }

  /** Prepared proof is public; private shuffle witnesses never enter the author or durable stores. */
  async author(author: PersistentEnvelopeAuthor, prepared: { readonly statement: Uint8Array; readonly proof: Uint8Array },
    expected: CandidateShuffleSnapshot): Promise<PersistentCandidateShuffleResult> {
    this.#begin();
    let signing = false;
    try {
      const seat = this.#ledger.nextSeat;
      if (expected !== this.#snapshot || seat === null) throw new Error("Stale shuffle preparation");
      if (!(author instanceof PersistentEnvelopeAuthor) || !bytesEqual(author.gameId, this.#options.roster.gameId) ||
        !bytesEqual(author.sender, this.#options.self) || !bytesEqual(author.sender, this.#options.roster.seats[seat]!)) throw new Error("Unexpected shuffle author");
      const template = decodeCandidateShuffleStatement36(this.#ledger.nextStatement());
      const statement = decodeCandidateShuffleStatement36(prepared.statement);
      decodeCandidateShuffleProof36(prepared.proof);
      const statementBytes = encodeCandidateShuffleStatement36(statement), proof = prepared.proof.slice();
      if (!bytesEqual(encodeCandidateShuffleStatement36({ ...statement, outputDeck: template.outputDeck }), encodeCandidateShuffleStatement36(template))) throw new Error("Prepared shuffle differs from admitted state");
      const guard = (head?: EnvelopeArtifact | null): undefined => {
        this.#guard();
        if (expected !== this.#snapshot) throw new Error("Stale shuffle preparation");
        if (head !== undefined) this.#requireHead(author.sender, head);
        return undefined;
      };
      guard(await author.readHead());
      if (await this.#options.verifier.verify(statementBytes.slice(), proof.slice()) !== true) throw new Error("Invalid prepared shuffle proof");
      guard();
      signing = true;
      const artifact = await author.author({ type: "SHUFFLE", round: this.#options.round,
        phase: `round.${this.#options.round}.shuffle.${seat}`, body: { statement: statementBytes, proof } }, guard);
      this.#guard();
      const result = await this.#receiveOne(capture(artifact));
      if (result.status === "rejected") throw new Error("Authored shuffle requires durable recovery");
      return result;
    } catch (error) {
      // A signing/append failure may already have committed bytes. Never generate a replacement here.
      if (signing) throw this.#fail(error);
      throw error;
    } finally { this.#busy = false; }
  }

  #begin(): void { this.#guard(); if (this.#busy) throw new Error("Shuffle receiver is busy"); this.#busy = true; }
  #guard(): void {
    if (this.#failure) throw this.#failure;
    if (this.#closed) throw new Error("Shuffle receiver is closed");
    try { this.#checkpoint.assertUnchanged(); } catch (error) { throw this.#fail(error); }
  }
  #fail(cause: unknown): Error {
    this.#failure ??= new Error("Shuffle recovery required", { cause });
    this.#ledger.close(); return this.#failure;
  }
  #requireHead(sender: IdentityPublicKey, head: EnvelopeArtifact | null): void {
    const expected = this.#options.session.heads().find(h => bytesEqual(h.from, sender));
    if (!expected || !head || head.envelope.seq !== expected.seq || !bytesEqual(head.hash, expected.hash)) throw this.#fail(new Error("Authored head differs from admitted sender prefix"));
    const recorded = this.#options.session.readRange(sender, expected.seq, expected.seq);
    if (recorded.status !== "complete" || recorded.envelopes.length !== 1 || !bytesEqual(recorded.envelopes[0]!.canonicalBytes, head.canonicalBytes)) throw this.#fail(new Error("Authored predecessor bytes differ"));
  }
  async #receiveOne(bytes: Uint8Array): Promise<PersistentCandidateShuffleResult> {
    this.#guard();
    const received = decodeAndVerifyEnvelope(bytes);
    // Reject gaps/forks before starting expensive proof work or touching storage.
    const classification = this.#options.session.classify(received);
    if (classification.status === "rejected") return Object.freeze({ status: "rejected", reason: classification.reason, received });
    let durableStarted = false;
    try {
      const status = await this.#ledger.accept(bytes, async () => {
        this.#guard();
        const before = this.#options.session.heads();
        durableStarted = true;
        const receipt = await this.#options.sessionReceiver.receive(decodeAndVerifyEnvelope(bytes));
        if (!bytesEqual(capture(receipt.received), bytes)) throw this.#fail(new Error("Receipt bytes differ"));
        if (receipt.status === "rejected") { this.#guard(); throw new ChainRejection(receipt.reason); }
        if (!["accepted", "duplicate"].includes(receipt.status) || !["stored", "duplicate"].includes(receipt.persistenceStatus)) throw this.#fail(new Error("Invalid durable receipt"));
        const expected = before.map(h => classification.status !== "duplicate" && bytesEqual(h.from, received.envelope.from)
          ? { from: h.from, seq: received.envelope.seq, hash: received.hash } : h);
        const heads = this.#options.session.heads();
        if (heads.length !== expected.length || heads.some((h, i) => h.seq !== expected[i]!.seq ||
          !bytesEqual(h.from, expected[i]!.from) || !bytesEqual(h.hash, expected[i]!.hash)) ||
          this.#options.session.classify(decodeAndVerifyEnvelope(bytes)).status !== "duplicate") throw this.#fail(new Error("Registry changed during shuffle receipt"));
        const range = this.#options.session.readRange(received.envelope.from, received.envelope.seq, received.envelope.seq);
        if (range.status !== "complete" || range.envelopes.length !== 1 || !bytesEqual(capture(range.envelopes[0]!), bytes)) throw this.#fail(new Error("Receipt absent from registry"));
        this.#checkpoint = captureSessionHistory(this.#options.session, this.#options.historyLimits);
        this.#guard();
      });
      this.#guard();
      if (status === "accepted") this.#snapshot = Object.freeze({ nextSeat: this.#ledger.nextSeat, complete: this.#ledger.complete });
      return Object.freeze({ status, received: decodeAndVerifyEnvelope(bytes), snapshot: this.#snapshot });
    } catch (error) {
      if (error instanceof ChainRejection) return Object.freeze({ status: "rejected", reason: error.reason, received: decodeAndVerifyEnvelope(bytes) });
      if (durableStarted) {
        // Storage may have committed even when close or a dependency interrupted acknowledgement.
        try { this.#guard(); } catch { throw this.#fail(error); }
      }
      throw error;
    }
  }
}
function capture(candidate: EnvelopeArtifact): Uint8Array {
  const bytes = candidate?.canonicalBytes;
  if (!(bytes instanceof Uint8Array) || bytes.constructor !== Uint8Array || bytes.length === 0 || bytes.length > 16 * 1024) throw new Error("Invalid shuffle envelope size");
  return decodeAndVerifyEnvelope(bytes.slice()).canonicalBytes;
}
