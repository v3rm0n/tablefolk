import { bytesEqual } from "@p2pcards/crypto";
import {
  decodeAndVerifyEnvelope,
  type EnvelopeArtifact,
} from "@p2pcards/protocol";

import {
  SessionChainRegistry,
  type SessionIngestResult,
} from "./chain-registry";

export interface DurableEnvelopeRecord {
  readonly artifact: EnvelopeArtifact;
}

export type AcceptedEnvelopePersistenceOutcome =
  | {
      readonly status: "stored" | "duplicate";
      readonly record: DurableEnvelopeRecord;
    }
  | {
      readonly status: "conflict";
      readonly existing: DurableEnvelopeRecord;
      readonly received: EnvelopeArtifact;
    };

export interface AcceptedEnvelopeStore {
  persistAcceptedEnvelope(
    received: EnvelopeArtifact,
  ): Promise<AcceptedEnvelopePersistenceOutcome>;
}

export type PersistentSessionReceiveResult =
  | {
      readonly status: "accepted" | "duplicate";
      readonly persistenceStatus: "stored" | "duplicate";
      readonly chainResult: Extract<SessionIngestResult, { status: "accepted" | "duplicate" }>;
      readonly received: EnvelopeArtifact;
    }
  | Exclude<SessionIngestResult, { status: "accepted" | "duplicate" }>
  | {
      readonly status: "rejected";
      readonly reason: "durable_conflict";
      readonly existing: EnvelopeArtifact;
      readonly received: EnvelopeArtifact;
    };

export class PersistentSessionReceiverError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "PersistentSessionReceiverError";
  }
}

export class PersistentSessionReceiver {
  readonly #registry: SessionChainRegistry;
  readonly #store: AcceptedEnvelopeStore;
  #pending: Promise<void> = Promise.resolve();

  constructor(registry: SessionChainRegistry, store: AcceptedEnvelopeStore) {
    if (!(registry instanceof SessionChainRegistry)) {
      throw new TypeError("Persistent receiver requires a session chain registry");
    }
    if (
      typeof store !== "object" ||
      store === null ||
      typeof store.persistAcceptedEnvelope !== "function"
    ) {
      throw new TypeError("Accepted envelope store must implement persistAcceptedEnvelope");
    }
    this.#registry = registry;
    this.#store = store;
  }

  isBoundTo(registry: SessionChainRegistry): boolean {
    return this.#registry === registry;
  }

  receive(candidate: EnvelopeArtifact): Promise<PersistentSessionReceiveResult> {
    let received: EnvelopeArtifact;
    try {
      received = decodeAndVerifyEnvelope(candidate.canonicalBytes);
    } catch (cause) {
      return Promise.reject(
        new PersistentSessionReceiverError("Received envelope artifact is invalid", { cause }),
      );
    }

    const operation = this.#pending.then(() => this.#persistThenIngest(received));
    this.#pending = operation.then(
      () => undefined,
      () => undefined,
    );
    return operation;
  }

  async #persistThenIngest(
    received: EnvelopeArtifact,
  ): Promise<PersistentSessionReceiveResult> {
    const classification = this.#registry.classify(received);
    if (classification.status === "rejected") {
      return classification;
    }

    const persistence = await this.#store.persistAcceptedEnvelope(received);
    if (persistence.status === "conflict") {
      const persistedReceived = snapshotArtifact(
        persistence.received,
        "Accepted envelope store returned an invalid conflict candidate",
      );
      if (!bytesEqual(persistedReceived.canonicalBytes, received.canonicalBytes)) {
        throw new PersistentSessionReceiverError(
          "Accepted envelope store reported a conflict for a different candidate",
        );
      }
      return Object.freeze({
        status: "rejected",
        reason: "durable_conflict",
        existing: snapshotStoredArtifact(persistence.existing),
        received,
      });
    }

    const durable = snapshotStoredArtifact(persistence.record);
    if (!bytesEqual(durable.canonicalBytes, received.canonicalBytes)) {
      throw new PersistentSessionReceiverError(
        "Accepted envelope store committed a different artifact",
      );
    }

    if (classification.status === "duplicate") {
      return Object.freeze({
        status: "duplicate",
        persistenceStatus: persistence.status,
        chainResult: classification,
        received,
      });
    }

    const chainResult = this.#registry.ingest(received);
    if (chainResult.status === "rejected") {
      throw new PersistentSessionReceiverError(
        `Session chain changed during durable commit: ${chainResult.reason}`,
      );
    }
    return Object.freeze({
      status: chainResult.status,
      persistenceStatus: persistence.status,
      chainResult,
      received,
    });
  }
}

function snapshotStoredArtifact(record: DurableEnvelopeRecord): EnvelopeArtifact {
  return snapshotArtifact(record.artifact, "Accepted envelope store returned an invalid artifact");
}

function snapshotArtifact(candidate: EnvelopeArtifact, message: string): EnvelopeArtifact {
  try {
    return decodeAndVerifyEnvelope(candidate.canonicalBytes);
  } catch (cause) {
    throw new PersistentSessionReceiverError(message, { cause });
  }
}
