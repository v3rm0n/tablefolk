import { bytesEqual } from "@p2pcards/crypto";
import {
  parseHash256,
  parseIdentityPublicKey,
  type EnvelopeArtifact,
  type EnvelopeMessageType,
  type Hash256,
  type WitnessBody,
  type WitnessHead,
} from "@p2pcards/protocol";

import { SessionChainRegistry } from "./chain-registry";
import type { ChainHead } from "./sender-chain";

export const HOUSEKEEPING_ENVELOPE_TYPES = Object.freeze([
  "WITNESS",
  "SYNC_REQ",
  "SYNC_RESP",
  "TIMEOUT_VOTE",
  "VIOLATION",
] as const satisfies readonly EnvelopeMessageType[]);

const HOUSEKEEPING_TYPE_SET: ReadonlySet<EnvelopeMessageType> = new Set(
  HOUSEKEEPING_ENVELOPE_TYPES,
);

export type WitnessHeadOutcome =
  | {
      readonly status: "matching";
      readonly seat: number;
      readonly claimed: WitnessHead;
      readonly localHead: ChainHead;
    }
  | {
      readonly status: "stale";
      readonly seat: number;
      readonly claimed: WitnessHead;
      readonly localHead: ChainHead;
    }
  | {
      readonly status: "need_sync";
      readonly seat: number;
      readonly claimed: WitnessHead;
      readonly fromSeq: number;
      readonly toSeq: number;
    }
  | {
      readonly status: "conflict";
      readonly seat: number;
      readonly claimed: WitnessHead;
      readonly local: EnvelopeArtifact;
      readonly fromSeq: number;
      readonly toSeq: number;
    };

export type WitnessAssessment =
  | {
      readonly status: "assessed";
      readonly outcomes: readonly WitnessHeadOutcome[];
    }
  | {
      readonly status: "rejected";
      readonly reason: "duplicate_sender" | "non_roster_order" | "unknown_sender";
      readonly index: number;
    };

export function shouldEmitImmediateWitness(type: EnvelopeMessageType): boolean {
  return !HOUSEKEEPING_TYPE_SET.has(type);
}

export function currentWitnessBody(
  registry: SessionChainRegistry,
  stateHash?: Hash256,
): WitnessBody {
  const heads = registry.heads().map(
    (head): WitnessHead =>
      Object.freeze({
        from: parseIdentityPublicKey(head.from),
        seq: head.seq,
        hash: parseHash256(head.hash),
      }),
  );
  const frozenHeads = Object.freeze(heads);
  if (stateHash !== undefined) {
    return Object.freeze({ heads: frozenHeads, stateHash: parseHash256(stateHash) });
  }
  return Object.freeze({ heads: frozenHeads });
}

export function assessWitness(
  registry: SessionChainRegistry,
  body: WitnessBody,
): WitnessAssessment {
  const localHeads = new Map<number, ChainHead>();
  for (const head of registry.heads()) {
    const seat = registry.seatOf(head.from);
    if (seat === null) {
      throw new Error("Session registry returned a head outside its own roster");
    }
    localHeads.set(seat, head);
  }

  const outcomes: WitnessHeadOutcome[] = [];
  const seenSeats = new Set<number>();
  let previousSeat = -1;
  for (const [index, candidate] of body.heads.entries()) {
    const claimed = copyWitnessHead(candidate);
    const seat = registry.seatOf(claimed.from);
    if (seat === null) {
      return Object.freeze({ status: "rejected", reason: "unknown_sender", index });
    }
    if (seenSeats.has(seat)) {
      return Object.freeze({ status: "rejected", reason: "duplicate_sender", index });
    }
    if (seat < previousSeat) {
      return Object.freeze({ status: "rejected", reason: "non_roster_order", index });
    }
    seenSeats.add(seat);
    previousSeat = seat;

    const localHead = localHeads.get(seat);
    if (localHead === undefined || claimed.seq > localHead.seq) {
      outcomes.push(
        Object.freeze({
          status: "need_sync",
          seat,
          claimed,
          fromSeq: localHead === undefined ? 0 : localHead.seq + 1,
          toSeq: claimed.seq,
        }),
      );
      continue;
    }

    const range = registry.readRange(claimed.from, claimed.seq, claimed.seq);
    if (range.status !== "complete") {
      throw new Error("Session registry could not read a sequence at or below its head");
    }
    const local = range.envelopes[0]!;
    if (!bytesEqual(local.hash, claimed.hash)) {
      outcomes.push(
        Object.freeze({
          status: "conflict",
          seat,
          claimed,
          local,
          fromSeq: claimed.seq,
          toSeq: claimed.seq,
        }),
      );
      continue;
    }

    outcomes.push(
      Object.freeze({
        status: claimed.seq === localHead.seq ? "matching" : "stale",
        seat,
        claimed,
        localHead,
      }),
    );
  }

  return Object.freeze({ status: "assessed", outcomes: Object.freeze(outcomes) });
}

function copyWitnessHead(head: WitnessHead): WitnessHead {
  if (!Number.isSafeInteger(head.seq) || head.seq < 0) {
    throw new RangeError("Witness sequence must be an unsigned safe integer");
  }
  return Object.freeze({
    from: parseIdentityPublicKey(head.from),
    seq: head.seq,
    hash: parseHash256(head.hash),
  });
}
