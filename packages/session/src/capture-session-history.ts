import { bytesEqual, importEd25519PublicKey } from "@p2pcards/crypto";
import {
  decodeAndVerifyEnvelope,
  verifiedEnvelopeByteLength,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  type EnvelopeArtifact,
} from "@p2pcards/protocol";

import { MAX_SESSION_SEATS, MIN_SESSION_SEATS, type SessionChainRegistry } from "./chain-registry";
import type { ChainHead } from "./sender-chain";

export const DEFAULT_MAX_SESSION_HISTORY_ENVELOPES = 1024;
export const DEFAULT_MAX_SESSION_HISTORY_BYTES = 16 * 1024 * 1024;

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
const typedArrayLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, "length")!.get!;
const typedArrayByteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteLength")!.get!;

export interface SessionHistoryCaptureLimits {
  readonly maxEnvelopes?: number;
  readonly maxBytes?: number;
}

export interface CapturedSessionHistory {
  readonly bySeat: readonly (readonly EnvelopeArtifact[])[];
  readonly envelopes: readonly EnvelopeArtifact[];
  readonly assertUnchanged: () => void;
}

export class SessionHistoryCaptureError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SessionHistoryCaptureError";
  }
}

/** Authenticated sender prefixes only; empty seats and all envelope semantics belong to the caller. */
export function captureSessionHistory(
  session: SessionChainRegistry,
  limits: SessionHistoryCaptureLimits = {},
): CapturedSessionHistory {
  if (typeof limits !== "object" || limits === null) { throw new TypeError("Session history limits must be an object"); }
  const { maxEnvelopes = DEFAULT_MAX_SESSION_HISTORY_ENVELOPES, maxBytes = DEFAULT_MAX_SESSION_HISTORY_BYTES } = limits;
  if (!Number.isSafeInteger(maxEnvelopes) || maxEnvelopes < 1 || !Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new RangeError("Session history limits must be positive safe integers");
  }

  try {
    const sourceGame = session.gameId;
    const game = parseGameId(sourceGame);
    const sourceRoster = session.roster;
    const seatCount = Array.isArray(sourceRoster) ? sourceRoster.length : 0;
    if (!Number.isSafeInteger(seatCount) || seatCount < MIN_SESSION_SEATS || seatCount > MAX_SESSION_SEATS) {
      throw new SessionHistoryCaptureError("Invalid session history roster");
    }
    const roster = Array.from({ length: seatCount }, (_, seat) => parseIdentityPublicKey(sourceRoster[seat]));
    for (let seat = 0; seat < roster.length; seat += 1) {
      importEd25519PublicKey(roster[seat]!);
      if (roster.slice(0, seat).some((sender) => bytesEqual(sender, roster[seat]!))) {
        throw new SessionHistoryCaptureError("Duplicate session history roster identity");
      }
    }
    const sourceHeads = session.heads();
    const headCount = Array.isArray(sourceHeads) ? sourceHeads.length : -1;
    if (!Number.isSafeInteger(headCount) || headCount < 0 || headCount > roster.length) {
      throw new SessionHistoryCaptureError("Invalid session history heads");
    }
    const heads: (ChainHead & { readonly seat: number })[] = [];
    let envelopeCount = 0;
    let previousSeat = -1;
    for (let index = 0; index < headCount; index += 1) {
      const source = sourceHeads[index]!;
      const head = { from: parseIdentityPublicKey(source.from), seq: source.seq, hash: parseHash256(source.hash) };
      const seat = roster.findIndex((sender) => bytesEqual(sender, head.from));
      if (seat <= previousSeat || !Number.isSafeInteger(head.seq) || head.seq < 0 || Object.is(head.seq, -0)) {
        throw new SessionHistoryCaptureError("Invalid session history heads or seat order");
      }
      // Bound every prefix before readRange allocates, without overflowing seq + 1.
      if (head.seq >= maxEnvelopes - envelopeCount) {
        throw new SessionHistoryCaptureError("Session history envelope limit exceeded");
      }
      envelopeCount += head.seq + 1;
      heads.push({ ...head, seat });
      previousSeat = seat;
    }

    const capturedBySeat = roster.map((): (EnvelopeArtifact | Uint8Array)[] => []);
    let byteCount = 0;
    for (const head of heads) {
      const range = session.readRange(parseIdentityPublicKey(head.from), 0, head.seq);
      const candidates = range.status === "complete" ? range.envelopes : null;
      const count = head.seq + 1;
      if (!Array.isArray(candidates) || candidates.length !== count) {
        throw new SessionHistoryCaptureError("Session history requires complete sender prefixes");
      }
      for (let seq = 0; seq < count; seq += 1) {
        const artifact = candidates[seq];
        if (artifact !== undefined) {
          const verifiedSize = verifiedEnvelopeByteLength(artifact);
          if (verifiedSize !== undefined) {
            if (verifiedSize > maxBytes - byteCount) throw new SessionHistoryCaptureError("Session history byte limit exceeded");
            byteCount += verifiedSize;
            capturedBySeat[head.seat]!.push(artifact);
            continue;
          }
        }
        const source = artifact?.canonicalBytes;
        if (!(source instanceof Uint8Array) || source.constructor !== Uint8Array) {
          throw new SessionHistoryCaptureError("Invalid session history envelope bytes");
        }
        const size = typedArrayLength.call(source) as number;
        if (typedArrayByteLength.call(source) !== size || source.length !== size ||
            !Number.isSafeInteger(size) || size < 1 || size > maxBytes - byteCount) {
          throw new SessionHistoryCaptureError("Invalid or over-budget session history envelope bytes");
        }
        byteCount += size;
        capturedBySeat[head.seat]!.push(new Uint8Array(source));
      }
    }

    // Bound every source before checking any unsigned artifact representation.
    const bySeat = roster.map((): EnvelopeArtifact[] => []);
    for (const head of heads) {
      const captured = capturedBySeat[head.seat]!;
      let previous = new Uint8Array(32);
      for (let seq = 0; seq < captured.length; seq += 1) {
        const candidate = captured[seq]!;
        const artifact = candidate instanceof Uint8Array ? decodeAndVerifyEnvelope(candidate) : candidate;
        const envelope = artifact.envelope;
        if (!bytesEqual(envelope.game, game) || !bytesEqual(envelope.from, head.from) || envelope.seq !== seq ||
            !bytesEqual(envelope.prev, previous)) {
          throw new SessionHistoryCaptureError("Invalid session history sender chain");
        }
        previous = new Uint8Array(artifact.hash);
        bySeat[head.seat]!.push(artifact);
      }
      if (!bytesEqual(previous, head.hash)) { throw new SessionHistoryCaptureError("Session history does not reach its captured head"); }
    }

    const assertUnchanged = (): void => {
      try {
        for (const current of [sourceHeads, session.heads()]) {
          if (!Array.isArray(current) || current.length !== heads.length) { throw new SessionHistoryCaptureError("Session history heads changed"); }
          for (let index = 0; index < heads.length; index += 1) {
            const expected = heads[index]!;
            const actual = current[index]!;
            if (!Object.is(actual.seq, expected.seq) || !bytesEqual(parseIdentityPublicKey(actual.from), expected.from) ||
                !bytesEqual(parseHash256(actual.hash), expected.hash)) {
              throw new SessionHistoryCaptureError("Session history heads changed");
            }
          }
        }
        for (const current of [sourceGame, session.gameId]) {
          if (!bytesEqual(parseGameId(current), game)) { throw new SessionHistoryCaptureError("Session history game changed"); }
        }
        for (const current of [sourceRoster, session.roster]) {
          if (!Array.isArray(current) || current.length !== roster.length ||
              roster.some((sender, seat) => !bytesEqual(parseIdentityPublicKey(current[seat]), sender))) {
            throw new SessionHistoryCaptureError("Session history roster changed");
          }
        }
      } catch (cause) {
        if (cause instanceof SessionHistoryCaptureError) throw cause;
        throw new SessionHistoryCaptureError("Could not check session history stability", { cause });
      }
    };
    assertUnchanged();
    return Object.freeze({
      bySeat: Object.freeze(bySeat.map((artifacts) => Object.freeze(artifacts))),
      envelopes: Object.freeze(bySeat.flat()),
      assertUnchanged,
    });
  } catch (cause) {
    if (cause instanceof SessionHistoryCaptureError) throw cause;
    throw new SessionHistoryCaptureError("Could not capture session history", { cause });
  }
}
