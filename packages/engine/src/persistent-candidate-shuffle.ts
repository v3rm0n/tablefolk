import { bytesEqual } from "@p2pcards/crypto";
import type { DeckSpec, MaskedCard } from "@p2pcards/deck";
import type { EnvelopeArtifact, IdentityPublicKey, RosterBody } from "@p2pcards/protocol";
import { captureSessionHistory, PersistentEnvelopeAuthor, PersistentSessionReceiver, SessionChainRegistry,
  PersistentSessionReceiverError, type CapturedSessionHistory, type SessionHistoryCaptureLimits } from "@p2pcards/session";
import { CandidateShuffleLedger, type CandidateShuffleBody, type CandidateShuffleVerifier } from "./candidate-shuffle-ledger";
import { recoverSetup } from "./setup-recovery";

export interface PersistentCandidateShuffleOptions {
  readonly serializedByCaller?: boolean;
  readonly session: SessionChainRegistry;
  readonly sessionReceiver: PersistentSessionReceiver;
  readonly roster: RosterBody;
  readonly self: IdentityPublicKey;
  readonly setupRound: number;
  readonly round: number;
  readonly deckSpec: DeckSpec;
  readonly verifier: CandidateShuffleVerifier;
  readonly historyLimits?: SessionHistoryCaptureLimits;
  readonly beaconRequired?: boolean;
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
    const { roster, self } = input;
    if (!bytesEqual(roster.gameId, input.session.gameId) || roster.seats.length !== 4 || input.session.roster.length !== 4 ||
      roster.seats.some((id, seat) => !bytesEqual(id, input.session.roster[seat]!)) || !roster.seats.some(id => bytesEqual(id, self))) throw new Error("Shuffle session scope mismatch");
    const options = Object.freeze({ ...input, roster, self, deckSpec: Object.freeze({ id: input.deckSpec.id, cards: Object.freeze([...input.deckSpec.cards]) }),
      ...(input.historyLimits === undefined ? {} : { historyLimits: Object.freeze({ ...input.historyLimits }) }) });
    const history = captureSessionHistory(options.session, options.historyLimits);
    const setup = recoverSetup(roster.gameId, options.setupRound, roster.seats, history.envelopes, options.beaconRequired).coordinator;
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
        await ledger.acceptVerified(artifact);
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
    try { return await this.#receiveOne(candidate); }
    finally { this.#busy = false; }
  }

  /** Prepared proof is public; private shuffle witnesses never enter the author or durable stores. */
  async author(author: PersistentEnvelopeAuthor, prepared: CandidateShuffleBody,
    expected: CandidateShuffleSnapshot): Promise<PersistentCandidateShuffleResult> {
    this.#begin();
    let signing = false;
    try {
      const seat = this.#ledger.nextSeat;
      if (expected !== this.#snapshot || seat === null) throw new Error("Stale shuffle preparation");
      if (!(author instanceof PersistentEnvelopeAuthor) || !bytesEqual(author.gameId, this.#options.roster.gameId) ||
        !bytesEqual(author.sender, this.#options.self) || !bytesEqual(author.sender, this.#options.roster.seats[seat]!)) throw new Error("Unexpected shuffle author");
      const body = { outputDeck: prepared.outputDeck.slice(), proof: prepared.proof.slice() };
      const guard = (head?: EnvelopeArtifact | null): undefined => {
        this.#guard();
        if (expected !== this.#snapshot) throw new Error("Stale shuffle preparation");
        if (head !== undefined) this.#requireHead(author.sender, head);
        return undefined;
      };
      guard(await author.readHead());
      if (await this.#ledger.verifyPrepared(body) !== true) throw new Error("Invalid prepared shuffle proof");
      guard();
      signing = true;
      const artifact = await author.author({ type: "SHUFFLE", round: this.#options.round,
        phase: `round.${this.#options.round}.shuffle.${seat}`, body }, guard);
      this.#guard();
      const result = await this.#receiveOne(artifact);
      if (result.status === "rejected") throw new Error("Authored shuffle requires durable recovery");
      return result;
    } catch (error) {
      // A signing/append failure may already have committed bytes. Never generate a replacement here.
      if (signing) throw this.#fail(error);
      throw error;
    } finally { this.#busy = false; }
  }

  #begin(): void {
    this.#guard();
    if (this.#options.serializedByCaller) return;
    if (this.#busy) throw new Error("Shuffle receiver is busy");
    this.#busy = true;
  }
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
  async #receiveOne(received: EnvelopeArtifact): Promise<PersistentCandidateShuffleResult> {
    this.#guard();
    // Reject gaps/forks before starting expensive proof work or touching storage.
    const classification = this.#options.session.classify(received);
    if (classification.status === "rejected") return { status: "rejected", reason: classification.reason, received };
    let persisted = false;
    try {
      const status = await this.#ledger.acceptVerified(received, async () => {
        this.#guard();
        const receipt = await this.#options.sessionReceiver.receiveVerified(received);
        if (receipt.status === "rejected") throw new ChainRejection(receipt.reason);
        persisted = true;
        this.#checkpoint = captureSessionHistory(this.#options.session, this.#options.historyLimits);
      });
      this.#guard();
      if (status === "accepted") this.#snapshot = Object.freeze({ nextSeat: this.#ledger.nextSeat, complete: this.#ledger.complete });
      return Object.freeze({ status, received, snapshot: this.#snapshot });
    } catch (error) {
      if (error instanceof ChainRejection) return { status: "rejected", reason: error.reason, received };
      if (persisted || error instanceof PersistentSessionReceiverError) throw this.#fail(error);
      throw error;
    }
  }
}
