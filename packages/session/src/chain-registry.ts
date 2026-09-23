import {
  bytesEqual,
  bytesToHex,
  importEd25519PublicKey,
} from "@p2pcards/crypto";
import {
  parseGameId,
  parseIdentityPublicKey,
  type EnvelopeArtifact,
  type GameId,
  type IdentityPublicKey,
} from "@p2pcards/protocol";

import { SenderChain, type ChainHead, type ChainIngestResult } from "./sender-chain";

export const MIN_SESSION_SEATS = 3;
export const MAX_SESSION_SEATS = 8;

export type SessionIngestResult =
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
    };

export type SyncRangeResult =
  | {
      readonly status: "complete";
      readonly envelopes: readonly EnvelopeArtifact[];
    }
  | {
      readonly status: "missing";
      readonly firstMissingSeq: number;
    }
  | {
      readonly status: "unknown_sender";
    };

interface RosterEntry {
  readonly seat: number;
  readonly sender: IdentityPublicKey;
  readonly chain: SenderChain;
}

export class SessionRosterError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SessionRosterError";
  }
}

export class SessionChainRegistry {
  readonly #gameId: GameId;
  readonly #entries: readonly RosterEntry[];
  readonly #bySender: ReadonlyMap<string, RosterEntry>;

  constructor(gameId: GameId, roster: readonly IdentityPublicKey[]) {
    this.#gameId = parseGameId(gameId);
    if (roster.length < MIN_SESSION_SEATS || roster.length > MAX_SESSION_SEATS) {
      throw new SessionRosterError(
        `Roster must contain ${MIN_SESSION_SEATS} to ${MAX_SESSION_SEATS} seats; got ${roster.length}`,
      );
    }

    const bySender = new Map<string, RosterEntry>();
    const entries = roster.map((candidate, seat): RosterEntry => {
      const sender = parseIdentityPublicKey(candidate);
      try {
        importEd25519PublicKey(sender);
      } catch (cause) {
        throw new SessionRosterError(`Seat ${seat} has an invalid Ed25519 public key`, { cause });
      }

      const key = bytesToHex(sender);
      if (bySender.has(key)) {
        throw new SessionRosterError(`Roster contains duplicate identity at seat ${seat}`);
      }

      const entry: RosterEntry = Object.freeze({
        seat,
        sender,
        chain: new SenderChain(sender),
      });
      bySender.set(key, entry);
      return entry;
    });

    this.#entries = Object.freeze(entries);
    this.#bySender = bySender;
  }

  get gameId(): GameId {
    return parseGameId(this.#gameId);
  }

  get roster(): readonly IdentityPublicKey[] {
    return Object.freeze(this.#entries.map(({ sender }) => parseIdentityPublicKey(sender)));
  }

  seatOf(sender: IdentityPublicKey): number | null {
    return this.#bySender.get(bytesToHex(sender))?.seat ?? null;
  }

  classify(received: EnvelopeArtifact): SessionIngestResult {
    if (!bytesEqual(received.envelope.game, this.#gameId)) {
      return {
        status: "rejected",
        reason: "wrong_game",
        expected: parseGameId(this.#gameId),
        actual: received.envelope.game,
        received,
      };
    }

    const entry = this.#bySender.get(bytesToHex(received.envelope.from));
    if (entry === undefined) {
      return {
        status: "rejected",
        reason: "unknown_sender",
        sender: received.envelope.from,
        received,
      };
    }
    return entry.chain.classify(received);
  }

  ingest(received: EnvelopeArtifact): SessionIngestResult {
    const result = this.classify(received);
    if (result.status !== "accepted") {
      return result;
    }

    const entry = this.#bySender.get(bytesToHex(received.envelope.from));
    if (entry === undefined) {
      throw new Error("Session sender disappeared between classification and ingestion");
    }
    return entry.chain.ingest(received);
  }

  heads(): readonly ChainHead[] {
    const heads: ChainHead[] = [];
    for (const { chain } of this.#entries) {
      const head = chain.head;
      if (head !== null) {
        heads.push(head);
      }
    }
    return Object.freeze(heads);
  }

  readRange(
    sender: IdentityPublicKey,
    fromSeq: number,
    toSeq: number,
  ): SyncRangeResult {
    assertSequence(fromSeq, "fromSeq");
    assertSequence(toSeq, "toSeq");
    if (fromSeq > toSeq) {
      throw new RangeError("fromSeq must not exceed toSeq");
    }

    const entry = this.#bySender.get(bytesToHex(sender));
    if (entry === undefined) {
      return { status: "unknown_sender" };
    }

    const head = entry.chain.head;
    if (head === null || fromSeq > head.seq) {
      return { status: "missing", firstMissingSeq: fromSeq };
    }
    if (toSeq > head.seq) {
      return { status: "missing", firstMissingSeq: head.seq + 1 };
    }

    const envelopes: EnvelopeArtifact[] = [];
    for (let seq = fromSeq; seq <= toSeq; seq += 1) {
      const artifact = entry.chain.get(seq);
      if (artifact === undefined) {
        return { status: "missing", firstMissingSeq: seq };
      }
      envelopes.push(artifact);
    }
    return { status: "complete", envelopes: Object.freeze(envelopes) };
  }
}

function assertSequence(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${label} must be an unsigned safe integer`);
  }
}
