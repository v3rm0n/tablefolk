import { bytesEqual } from "@p2pcards/crypto";
import {
  parseHash256,
  parseIdentityPublicKey,
  type EnvelopeArtifact,
  type Hash256,
  type IdentityPublicKey,
} from "@p2pcards/protocol";

export interface ChainHead {
  readonly from: IdentityPublicKey;
  readonly seq: number;
  readonly hash: Hash256;
}

export type ChainRejection =
  | {
      readonly status: "rejected";
      readonly reason: "wrong_sender";
      readonly expected: IdentityPublicKey;
      readonly actual: IdentityPublicKey;
      readonly received: EnvelopeArtifact;
    }
  | {
      readonly status: "rejected";
      readonly reason: "gap";
      readonly expectedSeq: number;
      readonly actualSeq: number;
      readonly received: EnvelopeArtifact;
    }
  | {
      readonly status: "rejected";
      readonly reason: "broken_prev";
      readonly expectedPrev: Hash256;
      readonly actualPrev: Hash256;
      readonly received: EnvelopeArtifact;
    }
  | {
      readonly status: "rejected";
      readonly reason: "equivocation";
      readonly existing: EnvelopeArtifact;
      readonly received: EnvelopeArtifact;
    };

export type ChainIngestResult =
  | {
      readonly status: "accepted";
      readonly head: ChainHead;
      readonly received: EnvelopeArtifact;
    }
  | {
      readonly status: "duplicate";
      readonly existing: EnvelopeArtifact;
      readonly received: EnvelopeArtifact;
    }
  | ChainRejection;

const ZERO_HASH = parseHash256(new Uint8Array(32));

export class SenderChain {
  readonly #sender: IdentityPublicKey;
  readonly #accepted = new Map<
    number,
    { readonly artifact: EnvelopeArtifact; readonly hash: Hash256 }
  >();
  #head: ChainHead | null = null;

  constructor(sender: IdentityPublicKey) {
    this.#sender = parseIdentityPublicKey(sender);
  }

  get sender(): IdentityPublicKey {
    return parseIdentityPublicKey(this.#sender);
  }

  get size(): number {
    return this.#accepted.size;
  }

  get head(): ChainHead | null {
    if (this.#head === null) {
      return null;
    }
    return copyHead(this.#head);
  }

  get(seq: number): EnvelopeArtifact | undefined {
    return this.#accepted.get(seq)?.artifact;
  }

  classify(received: EnvelopeArtifact): ChainIngestResult {
    const envelope = received.envelope;

    if (!bytesEqual(envelope.from, this.#sender)) {
      return {
        status: "rejected",
        reason: "wrong_sender",
        expected: parseIdentityPublicKey(this.#sender),
        actual: envelope.from,
        received,
      };
    }

    const existing = this.#accepted.get(envelope.seq);
    if (existing !== undefined) {
      if (bytesEqual(existing.hash, received.hash)) {
        return { status: "duplicate", existing: existing.artifact, received };
      }
      return {
        status: "rejected",
        reason: "equivocation",
        existing: existing.artifact,
        received,
      };
    }

    const expectedSeq = this.#head === null ? 0 : this.#head.seq + 1;
    if (envelope.seq !== expectedSeq) {
      return {
        status: "rejected",
        reason: "gap",
        expectedSeq,
        actualSeq: envelope.seq,
        received,
      };
    }

    const expectedPrev = this.#head?.hash ?? ZERO_HASH;
    if (!bytesEqual(envelope.prev, expectedPrev)) {
      return {
        status: "rejected",
        reason: "broken_prev",
        expectedPrev: parseHash256(expectedPrev),
        actualPrev: envelope.prev,
        received,
      };
    }

    const head: ChainHead = Object.freeze({
      from: parseIdentityPublicKey(this.#sender),
      seq: envelope.seq,
      hash: parseHash256(received.hash),
    });
    return { status: "accepted", head: copyHead(head), received };
  }

  ingest(received: EnvelopeArtifact): ChainIngestResult {
    const result = this.classify(received);
    if (result.status !== "accepted") {
      return result;
    }

    const head = result.head;
    this.#accepted.set(received.envelope.seq, {
      artifact: received,
      hash: parseHash256(received.hash),
    });
    this.#head = head;

    return { status: "accepted", head: copyHead(head), received };
  }
}

function copyHead(head: ChainHead): ChainHead {
  return Object.freeze({
    from: parseIdentityPublicKey(head.from),
    seq: head.seq,
    hash: parseHash256(head.hash),
  });
}
