import { bytesEqual } from "@p2pcards/crypto";
import {
  decodeAndVerifyEnvelope,
  type EnvelopeArtifact,
  type IdentityPublicKey,
} from "@p2pcards/protocol";

import {
  LobbyChainRegistry,
  type LobbyChainIngestResult,
  type LobbyJoinBootstrapResult,
  type LobbyReadyIngestResult,
  type LobbyRosterIngestResult,
} from "./lobby-bootstrap";
import {
  type AcceptedEnvelopePersistenceOutcome,
  type AcceptedEnvelopeStore,
  type DurableEnvelopeRecord,
} from "./persistent-receiver";

export interface DurableLobbyRosterRecord {
  readonly artifact: EnvelopeArtifact;
}

export type AcceptedLobbyRosterPersistenceOutcome =
  | {
      readonly status: "stored" | "duplicate" | "stale";
      readonly transcriptStatus: "stored" | "duplicate";
      readonly snapshot: DurableLobbyRosterRecord;
    }
  | {
      readonly status: "conflict";
      readonly existing: DurableEnvelopeRecord;
      readonly received: EnvelopeArtifact;
    };

export interface AcceptedLobbyEnvelopeStore extends AcceptedEnvelopeStore {
  persistAcceptedRoster(
    expectedHost: IdentityPublicKey,
    received: EnvelopeArtifact,
  ): Promise<AcceptedLobbyRosterPersistenceOutcome>;
}

type LobbyTransitionResult =
  | LobbyChainIngestResult
  | LobbyJoinBootstrapResult
  | LobbyRosterIngestResult
  | LobbyReadyIngestResult;

type AcceptedLobbyTransition = Extract<
  LobbyTransitionResult,
  { readonly status: "accepted" | "duplicate" }
>;

type RejectedLobbyTransition = Extract<
  LobbyTransitionResult,
  { readonly status: "rejected" }
>;

export type PersistentLobbyReceiveResult =
  | {
      readonly status: "accepted" | "duplicate";
      readonly persistenceStatus: "stored" | "duplicate";
      readonly rosterSnapshotStatus: "stored" | "duplicate" | "stale" | null;
      readonly transition: AcceptedLobbyTransition;
      readonly received: EnvelopeArtifact;
    }
  | RejectedLobbyTransition
  | {
      readonly status: "rejected";
      readonly reason: "durable_conflict";
      readonly existing: EnvelopeArtifact;
      readonly received: EnvelopeArtifact;
    };

export class PersistentLobbyReceiverError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "PersistentLobbyReceiverError";
  }
}

export class PersistentLobbyReceiver {
  readonly #lobby: LobbyChainRegistry;
  readonly #store: AcceptedLobbyEnvelopeStore;
  #pending: Promise<void> = Promise.resolve();

  constructor(lobby: LobbyChainRegistry, store: AcceptedLobbyEnvelopeStore) {
    if (!(lobby instanceof LobbyChainRegistry)) {
      throw new TypeError("Persistent lobby receiver requires a lobby chain registry");
    }
    if (
      typeof store !== "object" ||
      store === null ||
      typeof store.persistAcceptedEnvelope !== "function" ||
      typeof store.persistAcceptedRoster !== "function"
    ) {
      throw new TypeError(
        "Accepted lobby store must implement envelope and roster persistence",
      );
    }
    this.#lobby = lobby;
    this.#store = store;
  }

  receiveKnown(candidate: EnvelopeArtifact): Promise<PersistentLobbyReceiveResult> {
    return this.#enqueue(candidate, (received) =>
      isLobbyControlType(received.envelope.type)
        ? Promise.reject(
            new PersistentLobbyReceiverError(
              `${received.envelope.type} must use its dedicated lobby receive method`,
            ),
          )
        : this.#persistEnvelopeTransition(
            received,
            () => this.#lobby.classify(received),
            () => this.#lobby.ingest(received),
          ),
    );
  }

  receiveAdmittedJoin(candidate: EnvelopeArtifact): Promise<PersistentLobbyReceiveResult> {
    return this.#enqueue(candidate, (received) =>
      this.#persistEnvelopeTransition(
        received,
        () => this.#lobby.classifyBootstrapJoin(received),
        () => this.#lobby.bootstrapJoin(received),
      ),
    );
  }

  receiveRosterMemberJoin(
    candidate: EnvelopeArtifact,
  ): Promise<PersistentLobbyReceiveResult> {
    return this.#enqueue(candidate, (received) =>
      this.#persistEnvelopeTransition(
        received,
        () => this.#lobby.classifyRosterMemberJoin(received),
        () => this.#lobby.bootstrapRosterMemberJoin(received),
      ),
    );
  }

  receiveRoster(candidate: EnvelopeArtifact): Promise<PersistentLobbyReceiveResult> {
    return this.#enqueue(candidate, (received) => this.#persistRosterTransition(received));
  }

  receiveReady(candidate: EnvelopeArtifact): Promise<PersistentLobbyReceiveResult> {
    return this.#enqueue(candidate, (received) =>
      this.#persistEnvelopeTransition(
        received,
        () => this.#lobby.classifyReady(received),
        () => this.#lobby.ingestReady(received),
      ),
    );
  }

  #enqueue(
    candidate: EnvelopeArtifact,
    operation: (received: EnvelopeArtifact) => Promise<PersistentLobbyReceiveResult>,
  ): Promise<PersistentLobbyReceiveResult> {
    let received: EnvelopeArtifact;
    try {
      received = snapshotCandidate(candidate);
    } catch (cause) {
      return Promise.reject(cause);
    }
    const result = this.#pending.then(() => operation(received));
    this.#pending = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  async #persistEnvelopeTransition(
    received: EnvelopeArtifact,
    classify: () => LobbyTransitionResult,
    commit: () => LobbyTransitionResult,
  ): Promise<PersistentLobbyReceiveResult> {
    const classification = classify();
    if (classification.status === "rejected") {
      return classification;
    }

    const persistence = await this.#store.persistAcceptedEnvelope(received);
    if (persistence.status === "conflict") {
      return durableConflict(persistence, received);
    }
    requireExactDurableArtifact(persistence.record, received);
    return commitTransition(
      classification,
      commit,
      persistence.status,
      null,
      received,
    );
  }

  async #persistRosterTransition(
    received: EnvelopeArtifact,
  ): Promise<PersistentLobbyReceiveResult> {
    const classification = this.#lobby.classifyRoster(received);
    if (classification.status === "rejected") {
      return classification;
    }

    const persistence = await this.#store.persistAcceptedRoster(this.#lobby.host, received);
    if (persistence.status === "conflict") {
      return durableConflict(persistence, received);
    }
    const snapshot = snapshotRecord(
      persistence.snapshot,
      "Accepted lobby store returned an invalid roster snapshot",
    );
    if (persistence.status === "stale") {
      if (
        !bytesEqual(snapshot.envelope.game, received.envelope.game) ||
        !bytesEqual(snapshot.envelope.from, this.#lobby.host) ||
        snapshot.envelope.type !== "ROSTER" ||
        snapshot.envelope.seq <= received.envelope.seq
      ) {
        throw new PersistentLobbyReceiverError(
          "Accepted lobby store returned an invalid newer roster snapshot",
        );
      }
      if (classification.status === "accepted") {
        throw new PersistentLobbyReceiverError(
          "Durable roster is ahead of the live lobby; recovery is required",
        );
      }
    } else if (!bytesEqual(snapshot.canonicalBytes, received.canonicalBytes)) {
      throw new PersistentLobbyReceiverError(
        "Accepted lobby store committed a different roster artifact",
      );
    }

    return commitTransition(
      classification,
      () => this.#lobby.ingestRoster(received),
      persistence.transcriptStatus,
      persistence.status,
      received,
    );
  }
}

function commitTransition(
  classification: AcceptedLobbyTransition,
  commit: () => LobbyTransitionResult,
  persistenceStatus: "stored" | "duplicate",
  rosterSnapshotStatus: "stored" | "duplicate" | "stale" | null,
  received: EnvelopeArtifact,
): PersistentLobbyReceiveResult {
  const transition = commit();
  if (transition.status === "rejected" || transition.status !== classification.status) {
    const outcome =
      transition.status === "rejected" ? transition.reason : transition.status;
    throw new PersistentLobbyReceiverError(
      `Lobby state changed during durable commit: ${outcome}`,
    );
  }
  return Object.freeze({
    status: transition.status,
    persistenceStatus,
    rosterSnapshotStatus,
    transition,
    received,
  });
}

function durableConflict(
  persistence: Extract<AcceptedEnvelopePersistenceOutcome, { readonly status: "conflict" }>,
  received: EnvelopeArtifact,
): PersistentLobbyReceiveResult {
  const persistedReceived = snapshotArtifact(
    persistence.received,
    "Accepted lobby store returned an invalid conflict candidate",
  );
  if (!bytesEqual(persistedReceived.canonicalBytes, received.canonicalBytes)) {
    throw new PersistentLobbyReceiverError(
      "Accepted lobby store reported a conflict for a different candidate",
    );
  }
  return Object.freeze({
    status: "rejected",
    reason: "durable_conflict",
    existing: snapshotRecord(
      persistence.existing,
      "Accepted lobby store returned invalid conflict evidence",
    ),
    received,
  });
}

function requireExactDurableArtifact(
  record: DurableEnvelopeRecord,
  received: EnvelopeArtifact,
): void {
  const durable = snapshotRecord(
    record,
    "Accepted lobby store returned an invalid envelope artifact",
  );
  if (!bytesEqual(durable.canonicalBytes, received.canonicalBytes)) {
    throw new PersistentLobbyReceiverError(
      "Accepted lobby store committed a different envelope artifact",
    );
  }
}

function snapshotCandidate(candidate: EnvelopeArtifact): EnvelopeArtifact {
  return snapshotArtifact(candidate, "Received lobby envelope artifact is invalid");
}

function snapshotRecord(record: DurableEnvelopeRecord, message: string): EnvelopeArtifact {
  return snapshotArtifact(record.artifact, message);
}

function snapshotArtifact(candidate: EnvelopeArtifact, message: string): EnvelopeArtifact {
  try {
    return decodeAndVerifyEnvelope(candidate.canonicalBytes);
  } catch (cause) {
    throw new PersistentLobbyReceiverError(message, { cause });
  }
}

function isLobbyControlType(type: string): boolean {
  return type === "JOIN" || type === "ROSTER" || type === "READY";
}
