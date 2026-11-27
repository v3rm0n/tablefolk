import { bytesEqual } from "@p2pcards/crypto";
import type { EnvelopeArtifact } from "@p2pcards/protocol";
import type { SessionChainRegistry } from "./chain-registry";

export const DEFAULT_MAX_SESSION_HISTORY_ENVELOPES = 1024;
export const DEFAULT_MAX_SESSION_HISTORY_BYTES = 16 * 1024 * 1024;

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

/** Reads bounded prefixes from the authenticated, append-only session registry. */
export function captureSessionHistory(
  session: SessionChainRegistry,
  limits: SessionHistoryCaptureLimits = {},
): CapturedSessionHistory {
  const { maxEnvelopes = DEFAULT_MAX_SESSION_HISTORY_ENVELOPES, maxBytes = DEFAULT_MAX_SESSION_HISTORY_BYTES } = limits;
  if (!Number.isSafeInteger(maxEnvelopes) || maxEnvelopes < 1 || !Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new RangeError("Session history limits must be positive safe integers");
  }

  const heads = session.heads();
  let envelopeCount = 0;
  for (const { seq } of heads) {
    // Bound every prefix before readRange allocates, without overflowing seq + 1.
    if (seq >= maxEnvelopes - envelopeCount) {
      throw new SessionHistoryCaptureError("Session history envelope limit exceeded");
    }
    envelopeCount += seq + 1;
  }

  const bySeat: (readonly EnvelopeArtifact[])[] = session.roster.map(() => Object.freeze([]));
  let byteCount = 0;
  for (const { from, seq } of heads) {
    const range = session.readRange(from, 0, seq);
    if (range.status !== "complete") {
      throw new SessionHistoryCaptureError("Session history requires complete sender prefixes");
    }
    for (const artifact of range.envelopes) {
      byteCount += artifact.canonicalBytes.length;
      if (byteCount > maxBytes) throw new SessionHistoryCaptureError("Session history byte limit exceeded");
    }
    bySeat[session.seatOf(from)!] = range.envelopes;
  }

  const assertUnchanged = (): void => {
    const current = session.heads();
    if (current.length !== heads.length || heads.some((head, index) => {
      const other = current[index]!;
      return head.seq !== other.seq || !bytesEqual(head.from, other.from) || !bytesEqual(head.hash, other.hash);
    })) {
      throw new SessionHistoryCaptureError("Session history heads changed");
    }
  };

  return Object.freeze({
    bySeat: Object.freeze(bySeat),
    envelopes: Object.freeze(bySeat.flat()),
    assertUnchanged,
  });
}
