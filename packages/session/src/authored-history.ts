import { bytesEqual, importEd25519PublicKey } from "@p2pcards/crypto";
import {
  decodeAndVerifyEnvelope,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  type EnvelopeArtifact,
  type GameId,
  type Hash256,
  type IdentityPublicKey,
} from "@p2pcards/protocol";

import type { SyncCancellationSignal } from "./persistent-sync-receiver";
import type { ChainHead } from "./sender-chain";

export const MAX_AUTHORED_HISTORY_PAGE_ENVELOPES = 128;
export const MAX_AUTHORED_HISTORY_PAGE_BYTES = 8 * 1024 * 1024;
export const DEFAULT_MAX_AUTHORED_REPLAY_ENVELOPES = 4096;
export const DEFAULT_MAX_AUTHORED_REPLAY_BYTES = 64 * 1024 * 1024;

export interface AuthoredHistoryStore {
  readAuthoredHead(gameId: GameId, sender: IdentityPublicKey): Promise<EnvelopeArtifact | null>;
  /** Return a nonempty, byte-bounded prefix of this inclusive range, or reject missing/corrupt history. */
  readAuthoredPage(
    gameId: GameId,
    sender: IdentityPublicKey,
    fromSeq: number,
    toSeq: number,
  ): Promise<readonly EnvelopeArtifact[]>;
}

export interface AuthoredHistoryReplayOptions {
  readonly signal?: SyncCancellationSignal;
  readonly maxEnvelopes?: number;
  readonly maxBytes?: number;
}

export type AuthoredHistoryReplayResult = {
  readonly checkpoint: ChainHead | null;
  readonly submittedCount: number;
  readonly submittedBytes: number;
} & (
  | { readonly status: "replayed" | "cancelled" }
  | { readonly status: "failed"; readonly stage: "head" | "verify" | "send"; readonly error: Error }
);

interface VerifiedPage {
  readonly fromSeq: number;
  readonly toSeq: number;
  readonly prev: Hash256;
  readonly hash: Hash256;
}

export async function replayAuthoredHistory(
  store: AuthoredHistoryStore,
  gameId: GameId,
  sender: IdentityPublicKey,
  send: (payload: Uint8Array) => Promise<void>,
  options: AuthoredHistoryReplayOptions = {},
): Promise<AuthoredHistoryReplayResult> {
  if (typeof store !== "object" || store === null || typeof store.readAuthoredHead !== "function" ||
      typeof store.readAuthoredPage !== "function" || typeof send !== "function") {
    throw new TypeError("Authored replay requires a history store and send callback");
  }
  const game = parseGameId(gameId);
  const author = parseIdentityPublicKey(sender);
  importEd25519PublicKey(author);
  const maxEnvelopes = positiveInteger(options.maxEnvelopes ?? DEFAULT_MAX_AUTHORED_REPLAY_ENVELOPES);
  const maxBytes = positiveInteger(options.maxBytes ?? DEFAULT_MAX_AUTHORED_REPLAY_BYTES);
  const signal = options.signal;
  let checkpoint: ChainHead | null = null;
  let submittedCount = 0;
  let submittedBytes = 0;
  let stage: "head" | "verify" | "send" = "head";
  const progress = () => ({
    checkpoint: checkpoint === null ? null : Object.freeze({
      from: parseIdentityPublicKey(checkpoint.from), seq: checkpoint.seq, hash: parseHash256(checkpoint.hash),
    }),
    submittedCount,
    submittedBytes,
  });
  const cancelled = (): AuthoredHistoryReplayResult => Object.freeze({ status: "cancelled", ...progress() });

  try {
    if (signal?.aborted) {
      return cancelled();
    }
    const candidate = await store.readAuthoredHead(parseGameId(game), parseIdentityPublicKey(author));
    if (signal?.aborted) {
      return cancelled();
    }
    if (candidate === null) {
      return Object.freeze({ status: "replayed", ...progress() });
    }
    const headBytes = candidate.canonicalBytes;
    requireBytes(headBytes, Math.min(MAX_AUTHORED_HISTORY_PAGE_BYTES, maxBytes));
    const head = decodeAndVerifyEnvelope(headBytes);
    requireScope(head, game, author);
    if (head.envelope.seq >= maxEnvelopes) {
      throw new RangeError("Authored replay exceeds the envelope limit");
    }
    checkpoint = Object.freeze({ from: author, seq: head.envelope.seq, hash: parseHash256(head.hash) });

    // Verify the entire prefix before sending. Keep page hashes, not the whole decoded transcript.
    stage = "verify";
    const pages: VerifiedPage[] = [];
    let fromSeq = 0;
    let prev = parseHash256(new Uint8Array(32));
    let verifiedBytes = 0;
    while (fromSeq <= checkpoint.seq) {
      if (signal?.aborted) {
        return cancelled();
      }
      const toSeq = fromSeq + Math.min(checkpoint.seq - fromSeq, MAX_AUTHORED_HISTORY_PAGE_ENVELOPES - 1);
      const candidates = await store.readAuthoredPage(parseGameId(game), parseIdentityPublicKey(author), fromSeq, toSeq);
      if (signal?.aborted) {
        return cancelled();
      }
      const page = verifyPage(candidates, game, author, fromSeq, toSeq, prev, maxBytes - verifiedBytes);
      const last = page.at(-1)!;
      verifiedBytes += page.reduce((total, artifact) => total + artifact.canonicalBytes.length, 0);
      pages.push({ fromSeq, toSeq: last.envelope.seq, prev, hash: parseHash256(last.hash) });
      prev = parseHash256(last.hash);
      fromSeq = last.envelope.seq + 1;
    }
    if (!bytesEqual(prev, checkpoint.hash)) {
      throw new Error("Authored history does not reach the captured checkpoint");
    }

    stage = "send";
    for (const expected of pages) {
      const page: EnvelopeArtifact[] = [];
      let from = expected.fromSeq;
      let predecessor = expected.prev;
      let remainingBytes = Math.min(MAX_AUTHORED_HISTORY_PAGE_BYTES, maxBytes - submittedBytes);
      while (from <= expected.toSeq) {
        if (signal?.aborted) {
          return cancelled();
        }
        const candidates = await store.readAuthoredPage(
          parseGameId(game), parseIdentityPublicKey(author), from, expected.toSeq,
        );
        if (signal?.aborted) {
          return cancelled();
        }
        const fragment = verifyPage(candidates, game, author, from, expected.toSeq, predecessor, remainingBytes);
        const last = fragment.at(-1)!;
        remainingBytes -= fragment.reduce((total, artifact) => total + artifact.canonicalBytes.length, 0);
        page.push(...fragment);
        from = last.envelope.seq + 1;
        predecessor = parseHash256(last.hash);
      }
      if (!bytesEqual(predecessor, expected.hash)) {
        throw new Error("Authored replay page changed after verification");
      }
      for (const artifact of page) {
        if (signal?.aborted) {
          return cancelled();
        }
        const sending = send(artifact.canonicalBytes.slice());
        if (sending === undefined || sending === null || typeof sending.then !== "function") {
          throw new TypeError("Authored replay send callback must return a promise");
        }
        await sending;
        submittedCount += 1;
        submittedBytes += artifact.canonicalBytes.length;
      }
    }
    return signal?.aborted ? cancelled() : Object.freeze({ status: "replayed", ...progress() });
  } catch (cause) {
    return Object.freeze({
      status: "failed", stage, ...progress(),
      error: cause instanceof Error ? cause : new Error("Authored replay failed", { cause }),
    });
  }
}

function verifyPage(
  candidates: readonly EnvelopeArtifact[],
  game: GameId,
  author: IdentityPublicKey,
  fromSeq: number,
  toSeq: number,
  prev: Hash256,
  remainingBytes: number,
): readonly EnvelopeArtifact[] {
  if (!Array.isArray(candidates) || candidates.length === 0 || candidates.length > toSeq - fromSeq + 1) {
    throw new Error("Authored history page has an invalid envelope count");
  }
  let bytes = 0;
  const encoded: Uint8Array[] = [];
  for (const candidate of candidates) {
    const value = candidate.canonicalBytes;
    requireBytes(value, Math.min(MAX_AUTHORED_HISTORY_PAGE_BYTES, remainingBytes) - bytes);
    bytes += value.length;
    encoded.push(value);
  }
  return Object.freeze(encoded.map((value, index) => {
    const artifact = decodeAndVerifyEnvelope(value);
    requireScope(artifact, game, author);
    if (artifact.envelope.seq !== fromSeq + index || !bytesEqual(artifact.envelope.prev, prev)) {
      throw new Error("Authored history page has a gap or broken predecessor");
    }
    prev = parseHash256(artifact.hash);
    return artifact;
  }));
}

function requireScope(artifact: EnvelopeArtifact, game: GameId, author: IdentityPublicKey): void {
  if (!bytesEqual(artifact.envelope.game, game) || !bytesEqual(artifact.envelope.from, author)) {
    throw new Error("Authored history belongs to another game or sender");
  }
}

function requireBytes(value: Uint8Array, limit: number): void {
  if (!(value instanceof Uint8Array) || value.constructor !== Uint8Array) {
    throw new TypeError("Authored history must contain canonical envelope bytes");
  }
  if (value.length > limit) {
    throw new RangeError("Authored history exceeds the byte limit");
  }
}

function positiveInteger(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError("Authored replay limits must be positive safe integers");
  }
  return value;
}
