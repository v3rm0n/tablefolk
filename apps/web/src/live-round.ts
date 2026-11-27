import { bytesEqual, bytesToHex, RistrettoPoint, type RistrettoScalar } from "@p2pcards/crypto";
import { PersistentSetupReceiver } from "@p2pcards/engine";
import { CandidateSaskuRoundOwner, type SaskuActionIntent, type SaskuRoundSnapshot } from "@p2pcards/game-sasku";
import {
  decodeEquivocationViolationBody, encodeEquivocationViolationBody, MAX_GAME_ENVELOPE_BYTES, MAX_HISTORY_ENVELOPE_BYTES,
  type EnvelopeArtifact, type EquivocationViolationBody, type IdentityPublicKey, type RosterBody,
} from "@p2pcards/protocol";
import { assessEquivocationViolation, captureSessionHistory, createEquivocationViolation, PersistentEnvelopeAuthor, PersistentSessionReceiver, type SessionChainRegistry } from "@p2pcards/session";
import { IndexedDbGameSecretStore, type IndexedDbStoreOptions, type IndexedDbSessionStore } from "@p2pcards/storage";
import { legalSaskuCards, saskuBidStrength, type SaskuCardId } from "@p2pcards/rules-sasku";
import { CandidateShuffleClient } from "./candidate-shuffle-client";
import { FIRST_DEAL, FIRST_ROUND } from "./live-profile";
import { dealerForSaskuRound, INITIAL_SASKU_MATCH, MAX_SASKU_MATCH_ROUNDS, recordSaskuRound, type SaskuMatchState } from "./sasku-match";

const MATCH_HISTORY_LIMITS = Object.freeze({ maxEnvelopes: 4096, maxBytes: 64 * 1024 * 1024 });

export interface LiveRoundView {
  readonly phase: "setup" | "shuffle" | "dealing" | "bidding" | "choosing_trump" | "playing" | "audit" | "complete" | "match_complete";
  readonly match: SaskuMatchState;
  readonly message: string;
  readonly seat: number;
  readonly connected: boolean;
  readonly busy: boolean;
  readonly hand: readonly { position: number; card: SaskuCardId; playable: boolean }[];
  readonly strength: number | null;
  readonly state: SaskuRoundSnapshot | null;
  readonly error: string | null;
}
interface Options {
  session: SessionChainRegistry; roster: RosterBody; self: IdentityPublicKey;
  author: PersistentEnvelopeAuthor; stored: IndexedDbSessionStore; storage?: IndexedDbStoreOptions;
  restoredViolations: readonly EnvelopeArtifact[];
  changed: () => void; published: (artifact: EnvelopeArtifact) => void;
}
/** A full Sasku match driver. Only public envelopes leave the browser; secret stores stay local. */
export class LiveRound {
  readonly #options: Options;
  readonly #setup: PersistentSetupReceiver;
  readonly #keys: IndexedDbGameSecretStore;
  readonly #client = new CandidateShuffleClient();
  readonly #durable: PersistentSessionReceiver;
  readonly #pending = new Map<string, EnvelopeArtifact>();
  #bytes = 0;
  #owner: CandidateSaskuRoundOwner | null = null;
  #match: SaskuMatchState = INITIAL_SASKU_MATCH;
  #roundReady = 0;
  #secret: RistrettoScalar | null = null;
  #connected = false;
  #running: Promise<void> | null = null;
  #again = false;
  #closed = false;
  #error: string | null = null;
  #violation: EquivocationViolationBody | null = null;
  #violationStored = false;
  #unpublishedViolation: EquivocationViolationBody | null = null;
  #action: { intent: SaskuActionIntent; expected: SaskuRoundSnapshot; resolve: () => void; reject: (e: unknown) => void } | null = null;
  #view: LiveRoundView;
  constructor(options: Options) {
    this.#options = options;
    this.#keys = new IndexedDbGameSecretStore(options.storage);
    this.#durable = new PersistentSessionReceiver(options.session, options.stored);
    this.#setup = new PersistentSetupReceiver({ round: 0, self: options.self, session: options.session, sessionReceiver: this.#durable,
      beaconRequired: false });
    this.#view = { phase: "setup", match: this.#match, message: "Synchronizing signed histories", seat: options.session.seatOf(options.self)!, connected: false, busy: true, hand: [], strength: null, state: null, error: null };
    for (const artifact of options.restoredViolations) {
      this.#violation = this.#validateViolation(artifact);
      this.#violationStored = true;
    }
    this.#kick();
  }
  get view(): LiveRoundView { return this.#view; }
  get(remote: IdentityPublicKey, seq: number): EnvelopeArtifact | undefined {
    const r = this.#options.session.readRange(remote, seq, seq); return r.status === "complete" ? r.envelopes[0] : undefined;
  }
  connected(value: boolean): void { if (this.#connected !== value) { this.#connected = value; this.#update(); this.#kick(); } }
  roundReady(round: number): void {
    if (this.#closed) return;
    const value = round === this.#match.round ? round : 0;
    if (this.#roundReady !== value) { this.#roundReady = value; this.#kick(); }
  }
  receiveHistory(artifact: EnvelopeArtifact): void {
    if (this.#closed || this.#error) throw new Error(this.#error ?? "Round is closed");
    const e = artifact.envelope;
    if (artifact.canonicalBytes.length > (e.type === "VIOLATION" ? MAX_HISTORY_ENVELOPE_BYTES : MAX_GAME_ENVELOPE_BYTES) ||
        !bytesEqual(e.game, this.#options.roster.gameId) || this.#options.session.seatOf(e.from) === null) {
      throw new Error("Wrong round history scope");
    }
    if (this.#violationStored && e.type !== "VIOLATION") return;
    const chain = this.#options.session.classify(artifact);
    if (chain.status === "duplicate") return;
    if (chain.status === "rejected" && chain.reason === "equivocation") {
      this.reportEquivocation(chain.existing, artifact);
      return;
    }
    if (e.type === "VIOLATION") {
      const evidence = this.#validateViolation(artifact);
      this.#violation ??= evidence;
      if (chain.status === "rejected") {
        // The evidence verifies independently. Record it on our own chain when the reporter's chain is unavailable.
        if (!this.#violationStored) this.#unpublishedViolation ??= evidence;
        this.#kick();
        return;
      }
    } else if (chain.status === "rejected" && chain.reason !== "gap") {
      throw new Error(`Round chain rejected: ${chain.reason}`);
    }
    if (e.type !== "VIOLATION") {
      const setup = e.type === "KEY_SHARE";
      if ((setup ? e.round !== 0 : e.round < FIRST_ROUND || e.round > MAX_SASKU_MATCH_ROUNDS) ||
          !["KEY_SHARE", "SHUFFLE", "SHARES", "ACTION", "AUDIT_DISCLOSE"].includes(e.type)) throw new Error("Unsupported match traffic");
      if (!setup && (this.#match.winner !== null || e.round < this.#match.round)) throw new Error("Match traffic arrived after its round ended");
    }
    const key = `${bytesToHex(e.from)}:${e.seq}`, prior = this.#pending.get(key);
    if (prior) {
      if (!bytesEqual(prior.hash, artifact.hash)) this.reportEquivocation(prior, artifact);
      return;
    }
    if (this.#pending.size >= 256 || this.#bytes + artifact.canonicalBytes.length > 4 * 1024 * 1024) {
      throw new Error("Round receive budget exceeded");
    }
    this.#pending.set(key, artifact);
    this.#bytes += artifact.canonicalBytes.length;
    this.#kick();
  }

  reportEquivocation(left: EnvelopeArtifact, right: EnvelopeArtifact): void {
    if (this.#violation) return;
    const evidence = createEquivocationViolation(this.#options.session, left, right);
    this.#violation = evidence;
    this.#unpublishedViolation = evidence;
    this.#kick();
  }

  #validateViolation(artifact: EnvelopeArtifact): EquivocationViolationBody {
    const { phase, round, body } = artifact.envelope;
    if (phase !== "control.equivocation" || round !== 0) throw new Error("Invalid equivocation certificate scope");
    const checked = assessEquivocationViolation(this.#options.session, decodeEquivocationViolationBody(body));
    if (checked.status !== "valid") throw new Error(`Invalid equivocation certificate: ${checked.reason}`);
    return checked.body;
  }

  async #publishViolation(evidence: EquivocationViolationBody): Promise<void> {
    const artifact = await this.#options.author.author(
      { type: "VIOLATION", round: 0, phase: "control.equivocation", body: encodeEquivocationViolationBody(evidence) },
      head => {
        const local = this.#options.session.heads().find(item => bytesEqual(item.from, this.#options.self));
        if (!head || !local || local.seq !== head.envelope.seq || !bytesEqual(local.hash, head.hash)) {
          throw new Error("Local history changed while reporting equivocation");
        }
      },
    );
    accepted(await this.#durable.receive(artifact));
    this.#options.published(artifact);
  }
  act(intent: SaskuActionIntent): Promise<void> {
    const state = this.#view.state;
    if (!state || this.#match.winner !== null || !this.#connected || this.#violation || this.#action || this.#error || this.#closed || state.hand.turn !== this.#view.seat) return Promise.reject(new Error("Wait for your turn and all four connections"));
    const result = new Promise<void>((resolve, reject) => { this.#action = { intent: { ...intent }, expected: state, resolve, reject }; });
    this.#kick(); return result;
  }
  #kick(): void {
    if (this.#closed || this.#error) return;
    if (this.#running) { this.#again = true; return; }
    this.#running = Promise.resolve().then(() => this.#drain()).catch((e: unknown) => {
      if (!this.#closed) this.#error = e instanceof Error ? e.message : "Round failed";
      this.#action?.reject(e); this.#action = null;
    }).finally(() => { this.#running = null; this.#update(); if (this.#again) { this.#again = false; this.#kick(); } });
  }
  async #drain(): Promise<void> {
    while (!this.#closed && !this.#error) {
      this.#update();
      if (this.#violation) {
        this.#action?.reject(new Error("The table ended because a player signed conflicting history"));
        this.#action = null;
      }
      if (this.#unpublishedViolation) {
        await this.#publishViolation(this.#unpublishedViolation);
        this.#unpublishedViolation = null;
        this.#violationStored = true;
        break;
      }
      const next = [...this.#pending.entries()].find(([, a]) =>
        (!this.#violationStored || a.envelope.type === "VIOLATION") && this.#eligible(a));
      if (next) {
        const [key, a] = next;
        if (this.#options.session.classify(a).status !== "duplicate") {
          const result = a.envelope.type === "VIOLATION" ? await this.#durable.receive(a)
            : this.#owner ? await this.#owner.receiveHistory(a) : await this.#setup.receive(a);
          if (result.status !== "accepted" && result.status !== "duplicate") throw new Error(`Round receipt failed: ${result.status}`);
        }
        this.#pending.delete(key);
        this.#bytes -= a.canonicalBytes.length;
        if (a.envelope.type === "VIOLATION") {
          this.#violationStored = true;
          break;
        }
        continue;
      }
      if (this.#violationStored) break;
      if (!this.#owner && this.#setup.snapshot.state === "complete") {
        await this.#setup.whenIdle();
        this.#secret = await this.#keys.loadGameSecret(this.#options.roster.gameId);
        if (this.#secret === null) throw new Error("The saved private game key is missing; it will not be regenerated");
        if (!RistrettoPoint.base().multiply(this.#secret).equals(this.#setup.getCompletedSetup().publicKeyAt(this.#view.seat)!)) throw new Error("The saved private game key does not match the signed setup");
        this.#owner = await this.#openRound();
        this.#validateMatchHistory();
        this.#setup.close(); continue;
      }
      if (this.#owner?.snapshot.phase === "round") {
        const audit = this.#owner.snapshot.state.audit?.result;
        if (audit?.status === "violation") throw new Error(`Round ${this.#match.round} audit found a ${audit.rule} violation`);
        if (audit?.status === "valid" && this.#match.completed.length < this.#match.round) {
          if (this.#roundReady !== this.#match.round) break;
          this.#match = recordSaskuRound(this.#match, dealerForSaskuRound(this.#match.round), audit.score);
          this.#roundReady = 0;
          if (this.#match.winner !== null) { this.#validateMatchHistory(); break; }
          this.#owner.close();
          this.#owner = await this.#openRound();
          this.#validateMatchHistory();
          continue;
        }
      }
      if (this.#match.winner !== null || this.#violation) break;
      if (!this.#connected) break;
      const seat = this.#view.seat;
      if (!this.#owner) {
        const s = this.#setup.snapshot;
        if (!s.pendingSenders.includes(seat)) break;
        const result = s.state === "keys" ? await this.#setup.authorKeyShare(this.#options.author, this.#keys, s)
          : null;
        if (!result || result.status !== "accepted") throw new Error("Local setup contribution failed");
        this.#options.published(result.received); continue;
      }
      const snapshot = this.#owner.snapshot;
      if (snapshot.phase === "shuffle") {
        if (snapshot.state.nextSeat !== seat) break;
        const prepared = await this.#client.prove(this.#owner.nextShuffleStatement());
        if (this.#closed || !this.#connected || this.#violation) break;
        const result = await this.#owner.authorShuffle(this.#options.author, prepared, snapshot.state);
        if (result.status !== "accepted") throw new Error("Local shuffle failed");
        this.#options.published(result.received); continue;
      }
      const state = snapshot.state;
      if (state.ledger.deal?.pendingSenders.includes(seat)) {
        this.#options.published(accepted(await this.#owner.authorDealShares(this.#options.author, this.#secret!, state))); continue;
      }
      if (this.#action) {
        const action = this.#action; this.#action = null;
        try { this.#options.published(accepted(await this.#owner.authorAction(this.#options.author, this.#secret!, action.expected, action.intent))); action.resolve(); }
        catch (e) { action.reject(e); if (this.#owner.failure) throw e; }
        continue;
      }
      if (state.hand.phase === "complete" && state.audit?.pendingSenders.some(sender => sender === seat)) {
        this.#options.published(accepted(await this.#owner.authorAuditDisclose(this.#options.author, state))); continue;
      }
      break;
    }
  }
  #openRound(): Promise<CandidateSaskuRoundOwner> {
    return CandidateSaskuRoundOwner.open({ session: this.#options.session, sessionReceiver: this.#durable,
      roster: this.#options.roster, self: this.#options.self, setupRound: 0, round: this.#match.round,
      dealer: dealerForSaskuRound(this.#match.round), schedule: FIRST_DEAL, verifier: this.#client,
      beaconRequired: false, batchDeal: true,
      historyLimits: MATCH_HISTORY_LIMITS, roundHistoryLimits: { ...MATCH_HISTORY_LIMITS, allowOtherRounds: true } });
  }
  #validateMatchHistory(): void {
    const history = captureSessionHistory(this.#options.session, MATCH_HISTORY_LIMITS);
    let highest = 0;
    for (const chain of history.bySeat) {
      let prior = 0;
      for (const { envelope } of chain) {
        if (!["SHUFFLE", "SHARES", "ACTION", "AUDIT_DISCLOSE"].includes(envelope.type)) continue;
        if (envelope.round < 1 || envelope.round > MAX_SASKU_MATCH_ROUNDS || envelope.round < prior) {
          throw new Error("Saved match contains out-of-order or unsupported rounds");
        }
        prior = envelope.round;
        highest = Math.max(highest, prior);
      }
    }
    const current = this.#owner?.snapshot;
    const complete = current?.phase === "round" && current.state.audit?.result?.status === "valid";
    if (highest > this.#match.round && (this.#match.winner !== null || !complete)) {
      throw new Error("Saved match advances before the current round is verified");
    }
    history.assertUnchanged();
  }
  #eligible(a: EnvelopeArtifact): boolean {
    const c = this.#options.session.classify(a);
    if (c.status === "rejected") return c.reason !== "gap";
    if (c.status === "duplicate") return true;
    const e = a.envelope;
    if (e.type === "VIOLATION") return true;
    if (e.round !== (e.type === "KEY_SHARE" || e.type === "RAND_COMMIT" || e.type === "RAND_REVEAL" ? 0 : this.#match.round)) return false;
    if (!this.#owner) {
      const type = { keys: "KEY_SHARE", rand_commit: "RAND_COMMIT", rand_reveal: "RAND_REVEAL", complete: "", failed: "" }[this.#setup.snapshot.state];
      return e.type === type;
    }
    const s = this.#owner.snapshot;
    if (s.phase === "shuffle") return e.type === "SHUFFLE" && e.phase === `round.${this.#match.round}.shuffle.${s.state.nextSeat}`;
    if (e.type === "SHARES") return e.phase === `round.${this.#match.round}.deal.${s.state.ledger.dealIndex}`;
    if (e.type === "ACTION") return s.state.ledger.deal === null && e.phase === `round.${this.#match.round}.play.${s.state.ledger.actionIndex}`;
    return e.type === "AUDIT_DISCLOSE" && s.state.hand.phase === "complete";
  }
  #update(): void {
    if (this.#closed) return;
    const s = this.#owner?.snapshot;
    const state = s?.phase === "round" ? s.state : null;
    const phase = this.#match.winner !== null ? "match_complete" : !s ? "setup" : s.phase === "shuffle" ? "shuffle" : state!.ledger.deal ? "dealing"
      : state!.hand.phase === "complete" ? state!.audit?.result ? "complete" : "audit" : state!.hand.phase;
    let hand: LiveRoundView["hand"] = this.#view.hand, strength: number | null = this.#view.strength;
    if (!this.#error && !this.#violation && !this.#owner?.failure && state && !state.ledger.deal && this.#secret !== null && this.#owner!.pendingEnvelopes === 0) {
      const privateHand = this.#owner!.readPrivateHand(this.#secret);
      if (!privateHand) throw new Error("Private hand is unavailable");
      const cards = Object.values(privateHand.remaining);
      const trump = state.hand.contract?.kind === "pass_round" ? "diamonds" : state.hand.contract?.suit;
      const legal = state.hand.phase === "playing" && state.hand.turn === this.#view.seat ? legalSaskuCards(cards, state.hand.trick, trump!) : [];
      hand = Object.entries(privateHand.remaining).map(([position, card]) => ({ position: Number(position), card, playable: legal.includes(card) }));
      strength = saskuBidStrength(Object.values(privateHand.dealt));
    }
    this.#view = Object.freeze({ ...this.#view, phase, match: this.#match, state, hand, strength, connected: this.#connected && !this.#violation, busy: this.#running !== null,
      error: this.#error ?? (this.#violation ? `Player ${this.#violation.seat + 1} signed conflicting history. The table ended.` : null), message: !this.#connected ? "Waiting for all four signed histories and connections" : phase === "setup" ? `Preparing ${this.#setup.snapshot.state.replaceAll("_", " ")}`
        : phase === "shuffle" ? `Player ${(s!.phase === "shuffle" ? s!.state.nextSeat ?? 0 : 0) + 1} is shuffling` : phase === "dealing" ? "Dealing your private hand" : phase === "audit" ? "Checking the completed round" : "" });
    this.#options.changed();
  }
  async close(): Promise<void> {
    this.#closed = true; this.#client.close();
    await this.#running; this.#setup.close(); this.#owner?.close();
    this.#action?.reject(new Error("Round closed")); this.#action = null;
    await this.#keys.close();
  }
}

function accepted(receipt: { readonly status: string; readonly received: EnvelopeArtifact }): EnvelopeArtifact {
  if (receipt.status !== "accepted") throw new Error(`Local round contribution failed: ${receipt.status}`);
  return receipt.received;
}
