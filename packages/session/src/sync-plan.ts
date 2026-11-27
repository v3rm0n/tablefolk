import { bytesEqual } from "@p2pcards/crypto";
import type { AdvertisedHead, EnvelopeArtifact, SyncRequestBody } from "@p2pcards/protocol";

import type { ChainHead } from "./sender-chain";

export type HeadSyncPlan =
  | { readonly status: "known" }
  | { readonly status: "missing" | "conflict"; readonly request: SyncRequestBody };

/** Plan the next bounded request using the accepted history of a single authorized author. */
export function planHeadSyncRequest(
  claimed: AdvertisedHead,
  localHead: ChainHead | null,
  get: (seq: number) => EnvelopeArtifact | undefined,
  maxEnvelopes = 1,
): HeadSyncPlan {
  if (!Number.isSafeInteger(maxEnvelopes) || maxEnvelopes < 1) {
    throw new RangeError("Sync request limit must be a positive safe integer");
  }
  const known = get(claimed.seq);
  if (known) {
    return bytesEqual(known.hash, claimed.hash) ? { status: "known" }
      : { status: "conflict", request: { from: claimed.from, fromSeq: claimed.seq, toSeq: claimed.seq } };
  }
  const fromSeq = (localHead?.seq ?? -1) + 1;
  return { status: "missing", request: {
    from: claimed.from, fromSeq, toSeq: fromSeq + Math.min(claimed.seq - fromSeq, maxEnvelopes - 1),
  } };
}
