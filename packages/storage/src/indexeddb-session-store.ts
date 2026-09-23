import {
  bytesEqual,
  bytesToHex,
  importEd25519PublicKey,
} from "@p2pcards/crypto";
import {
  decodeAndVerifyEnvelope,
  decodeRosterBody,
  hashRosterBody,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  type EnvelopeArtifact,
  type GameId,
  type Hash256,
  type IdentityPublicKey,
  type RosterBody,
} from "@p2pcards/protocol";
import { orderEnvelopeTranscript } from "@p2pcards/session";

import {
  GAMES_STORE,
  openP2pCardsDatabase,
  TRANSCRIPT_GAME_INDEX,
  TRANSCRIPT_SENDER_SEQUENCE_INDEX,
  TRANSCRIPTS_STORE,
  type IndexedDbStoreOptions,
} from "./database";

const LOBBY_ROSTER_FIELD = "lobbyRoster";

interface StoredTranscriptEnvelope {
  readonly arrival?: number;
  readonly game: string;
  readonly sender: string;
  readonly seq: number;
  readonly bytes: Uint8Array;
  readonly authored: boolean;
}

interface StoredLobbyRoster {
  readonly host: string;
  readonly seq: number;
  readonly bytes: Uint8Array;
}

export interface PersistedTranscriptEnvelope {
  readonly arrival: number;
  readonly artifact: EnvelopeArtifact;
  readonly authored: boolean;
}

export interface PersistedLobbyRoster {
  readonly artifact: EnvelopeArtifact;
  readonly body: RosterBody;
  readonly rosterHash: Hash256;
}

export type AcceptedEnvelopePersistenceResult =
  | {
      readonly status: "stored" | "duplicate";
      readonly record: PersistedTranscriptEnvelope;
    }
  | {
      readonly status: "conflict";
      readonly existing: PersistedTranscriptEnvelope;
      readonly received: EnvelopeArtifact;
    };

export type LobbyRosterPersistenceResult =
  | {
      readonly status: "stored" | "duplicate" | "stale";
      readonly transcriptStatus: "stored" | "duplicate";
      readonly snapshot: PersistedLobbyRoster;
    }
  | {
      readonly status: "conflict";
      readonly existing: PersistedTranscriptEnvelope;
      readonly received: EnvelopeArtifact;
    };

export class SessionStoreError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SessionStoreError";
  }
}

export class IndexedDbSessionStore {
  readonly #database: Promise<IDBDatabase>;

  constructor(options: IndexedDbStoreOptions = {}) {
    this.#database = openP2pCardsDatabase(options);
  }

  async persistAcceptedEnvelope(
    candidate: EnvelopeArtifact,
  ): Promise<AcceptedEnvelopePersistenceResult> {
    const received = snapshotArtifact(candidate, "Accepted envelope is invalid");
    const game = bytesToHex(received.envelope.game);
    const sender = bytesToHex(received.envelope.from);
    const database = await this.#database;
    let result: AcceptedEnvelopePersistenceResult | null = null;

    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(TRANSCRIPTS_STORE, "readwrite");
      const transcripts = transaction.objectStore(TRANSCRIPTS_STORE);
      const request = transcripts
        .index(TRANSCRIPT_SENDER_SEQUENCE_INDEX)
        .get([game, sender, received.envelope.seq]);
      let operationError: unknown;

      request.onsuccess = () => {
        try {
          if (request.result !== undefined) {
            const existing = decodeStoredTranscript(request.result);
            result = sameArtifact(existing.artifact, received)
              ? Object.freeze({ status: "duplicate", record: existing })
              : Object.freeze({ status: "conflict", existing, received });
            return;
          }

          const addRequest = transcripts.add({
            game,
            sender,
            seq: received.envelope.seq,
            bytes: received.canonicalBytes.slice(),
            authored: false,
          } satisfies StoredTranscriptEnvelope);
          addRequest.onsuccess = () => {
            try {
              const arrival = parseArrivalKey(addRequest.result);
              result = Object.freeze({
                status: "stored",
                record: transcriptRecord(arrival, received, false),
              });
            } catch (cause) {
              operationError = cause;
              transaction.abort();
            }
          };
        } catch (cause) {
          operationError = cause;
          transaction.abort();
        }
      };

      transaction.oncomplete = () => resolve();
      transaction.onabort = () => {
        reject(
          operationError ??
            transaction.error ??
            new SessionStoreError("Accepted-envelope transaction aborted"),
        );
      };
      transaction.onerror = () => {
        operationError ??= transaction.error;
      };
    });

    if (result === null) {
      throw new SessionStoreError("Accepted-envelope transaction completed without a result");
    }
    return result;
  }

  async persistAcceptedRoster(
    expectedHost: IdentityPublicKey,
    candidate: EnvelopeArtifact,
  ): Promise<LobbyRosterPersistenceResult> {
    const host = parseIdentityPublicKey(expectedHost);
    importEd25519PublicKey(host);
    const received = snapshotArtifact(candidate, "Accepted roster envelope is invalid");
    const incomingSnapshot = decodeRosterArtifact(received, host);
    const game = bytesToHex(received.envelope.game);
    const sender = bytesToHex(host);
    const database = await this.#database;
    let result: LobbyRosterPersistenceResult | null = null;

    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(
        [TRANSCRIPTS_STORE, GAMES_STORE],
        "readwrite",
      );
      const transcripts = transaction.objectStore(TRANSCRIPTS_STORE);
      const games = transaction.objectStore(GAMES_STORE);
      const transcriptRequest = transcripts
        .index(TRANSCRIPT_SENDER_SEQUENCE_INDEX)
        .get([game, sender, received.envelope.seq]);
      const gameRequest = games.get(game);
      let transcriptLoaded = false;
      let gameLoaded = false;
      let processed = false;
      let operationError: unknown;

      const process = () => {
        if (processed || !transcriptLoaded || !gameLoaded) {
          return;
        }
        processed = true;
        try {
          let transcriptStatus: "stored" | "duplicate";
          let storedTranscript: PersistedTranscriptEnvelope | null = null;
          if (transcriptRequest.result === undefined) {
            transcriptStatus = "stored";
            transcripts.add({
              game,
              sender,
              seq: received.envelope.seq,
              bytes: received.canonicalBytes.slice(),
              authored: false,
            } satisfies StoredTranscriptEnvelope);
          } else {
            storedTranscript = decodeStoredTranscript(transcriptRequest.result);
            if (!sameArtifact(storedTranscript.artifact, received)) {
              result = Object.freeze({
                status: "conflict",
                existing: storedTranscript,
                received,
              });
              return;
            }
            transcriptStatus = "duplicate";
          }

          const gameRecord = readGameRecord(gameRequest.result, game);
          const existingSnapshot = Object.hasOwn(gameRecord, LOBBY_ROSTER_FIELD)
            ? decodeStoredRoster(gameRecord[LOBBY_ROSTER_FIELD], received.envelope.game, host)
            : null;
          let status: "stored" | "duplicate" | "stale";
          let selected: PersistedLobbyRoster;
          if (existingSnapshot === null || received.envelope.seq > existingSnapshot.artifact.envelope.seq) {
            status = "stored";
            selected = incomingSnapshot;
            games.put({
              ...gameRecord,
              game,
              [LOBBY_ROSTER_FIELD]: {
                host: sender,
                seq: received.envelope.seq,
                bytes: received.canonicalBytes.slice(),
              } satisfies StoredLobbyRoster,
            });
          } else if (received.envelope.seq < existingSnapshot.artifact.envelope.seq) {
            status = "stale";
            selected = existingSnapshot;
          } else if (sameArtifact(existingSnapshot.artifact, received)) {
            status = "duplicate";
            selected = existingSnapshot;
          } else {
            throw new SessionStoreError("Roster snapshot conflicts with its transcript row");
          }

          result = Object.freeze({ status, transcriptStatus, snapshot: selected });
        } catch (cause) {
          operationError = cause;
          transaction.abort();
        }
      };

      transcriptRequest.onsuccess = () => {
        transcriptLoaded = true;
        process();
      };
      gameRequest.onsuccess = () => {
        gameLoaded = true;
        process();
      };
      transaction.oncomplete = () => resolve();
      transaction.onabort = () => {
        reject(
          operationError ??
            transaction.error ??
            new SessionStoreError("Roster persistence transaction aborted"),
        );
      };
      transaction.onerror = () => {
        operationError ??= transaction.error;
      };
    });

    if (result === null) {
      throw new SessionStoreError("Roster persistence transaction completed without a result");
    }
    return result;
  }

  async loadTranscript(gameId: GameId): Promise<readonly PersistedTranscriptEnvelope[]> {
    const game = bytesToHex(parseGameId(gameId));
    const database = await this.#database;
    const transaction = database.transaction(TRANSCRIPTS_STORE, "readonly");
    const request = transaction
      .objectStore(TRANSCRIPTS_STORE)
      .index(TRANSCRIPT_GAME_INDEX)
      .getAll(game);
    const values = await requestResult<unknown[]>(request);
    await transactionComplete(transaction);
    const records = values.map((value) => {
      const record = decodeStoredTranscript(value);
      if (!bytesEqual(record.artifact.envelope.game, gameId)) {
        throw new SessionStoreError("Transcript index returned an envelope for another game");
      }
      return record;
    });
    return Object.freeze(records);
  }

  async loadCanonicalEnvelopeTranscript(
    gameId: GameId,
  ): Promise<readonly PersistedTranscriptEnvelope[]> {
    const records = await this.loadTranscript(gameId);
    let artifacts: readonly EnvelopeArtifact[];
    try {
      artifacts = orderEnvelopeTranscript(
        gameId,
        records.map(({ artifact }) => artifact),
      );
    } catch (cause) {
      throw new SessionStoreError("Stored transcript cannot be canonically ordered", {
        cause,
      });
    }
    const byTuple = new Map(
      records.map((record) => [transcriptTuple(record.artifact), record] as const),
    );
    return Object.freeze(
      artifacts.map((artifact) => {
        const record = byTuple.get(transcriptTuple(artifact));
        if (record === undefined) {
          throw new SessionStoreError("Canonical transcript lost a persisted envelope");
        }
        return transcriptRecord(record.arrival, artifact, record.authored);
      }),
    );
  }

  async loadLobbyRoster(
    gameId: GameId,
    expectedHost: IdentityPublicKey,
  ): Promise<PersistedLobbyRoster | null> {
    const gameValue = parseGameId(gameId);
    const host = parseIdentityPublicKey(expectedHost);
    importEd25519PublicKey(host);
    const game = bytesToHex(gameValue);
    const database = await this.#database;
    const transaction = database.transaction(GAMES_STORE, "readonly");
    const value = await requestResult<unknown>(
      transaction.objectStore(GAMES_STORE).get(game),
    );
    await transactionComplete(transaction);
    if (value === undefined) {
      return null;
    }
    const record = readGameRecord(value, game);
    return Object.hasOwn(record, LOBBY_ROSTER_FIELD)
      ? decodeStoredRoster(record[LOBBY_ROSTER_FIELD], gameValue, host)
      : null;
  }

  async close(): Promise<void> {
    const database = await this.#database;
    database.close();
  }
}

function snapshotArtifact(candidate: EnvelopeArtifact, message: string): EnvelopeArtifact {
  try {
    return decodeAndVerifyEnvelope(candidate.canonicalBytes);
  } catch (cause) {
    throw new SessionStoreError(message, { cause });
  }
}

function decodeRosterArtifact(
  artifact: EnvelopeArtifact,
  expectedHost: IdentityPublicKey,
): PersistedLobbyRoster {
  const envelope = artifact.envelope;
  if (!bytesEqual(envelope.from, expectedHost)) {
    throw new SessionStoreError("Roster envelope was not signed by the expected host");
  }
  if (envelope.type !== "ROSTER" || envelope.phase !== "lobby" || envelope.round !== 0) {
    throw new SessionStoreError("Roster envelope has invalid lobby metadata");
  }

  let body: RosterBody;
  try {
    body = decodeRosterBody(envelope.body);
  } catch (cause) {
    throw new SessionStoreError("Roster envelope body is malformed", { cause });
  }
  if (!bytesEqual(body.gameId, envelope.game)) {
    throw new SessionStoreError("Roster body has the wrong game identifier");
  }
  let includesHost = false;
  for (const identity of body.seats) {
    try {
      importEd25519PublicKey(identity);
    } catch (cause) {
      throw new SessionStoreError("Roster contains an invalid identity public key", { cause });
    }
    includesHost ||= bytesEqual(identity, expectedHost);
  }
  if (!includesHost) {
    throw new SessionStoreError("Roster does not contain the expected host");
  }

  return Object.freeze({
    artifact,
    body: copyRosterBody(body),
    rosterHash: hashRosterBody(body),
  });
}

function decodeStoredTranscript(value: unknown): PersistedTranscriptEnvelope {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new SessionStoreError("IndexedDB contains a malformed transcript record");
  }
  const record = value as Record<string, unknown>;
  const arrival = record["arrival"];
  const game = record["game"];
  const sender = record["sender"];
  const seq = record["seq"];
  const bytes = record["bytes"];
  const authored = record["authored"];
  if (
    typeof game !== "string" ||
    typeof sender !== "string" ||
    typeof seq !== "number" ||
    !Number.isSafeInteger(seq) ||
    seq < 0 ||
    !(bytes instanceof Uint8Array) ||
    bytes.constructor !== Uint8Array ||
    typeof authored !== "boolean"
  ) {
    throw new SessionStoreError("IndexedDB transcript record fields are malformed");
  }
  const artifact = snapshotArtifact(
    { canonicalBytes: bytes } as EnvelopeArtifact,
    "IndexedDB transcript contains an invalid envelope",
  );
  if (
    bytesToHex(artifact.envelope.game) !== game ||
    bytesToHex(artifact.envelope.from) !== sender ||
    artifact.envelope.seq !== seq
  ) {
    throw new SessionStoreError("IndexedDB transcript metadata does not match its envelope");
  }
  return transcriptRecord(parseArrivalKey(arrival), artifact, authored);
}

function decodeStoredRoster(
  value: unknown,
  expectedGame: GameId,
  expectedHost: IdentityPublicKey,
): PersistedLobbyRoster {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new SessionStoreError("IndexedDB contains a malformed lobby roster snapshot");
  }
  const record = value as Record<string, unknown>;
  const host = record["host"];
  const seq = record["seq"];
  const bytes = record["bytes"];
  if (
    host !== bytesToHex(expectedHost) ||
    typeof seq !== "number" ||
    !Number.isSafeInteger(seq) ||
    seq < 0 ||
    !(bytes instanceof Uint8Array) ||
    bytes.constructor !== Uint8Array
  ) {
    throw new SessionStoreError("IndexedDB lobby roster snapshot fields are malformed");
  }
  const artifact = snapshotArtifact(
    { canonicalBytes: bytes } as EnvelopeArtifact,
    "IndexedDB lobby roster snapshot contains an invalid envelope",
  );
  if (!bytesEqual(artifact.envelope.game, expectedGame) || artifact.envelope.seq !== seq) {
    throw new SessionStoreError("IndexedDB lobby roster metadata does not match its envelope");
  }
  return decodeRosterArtifact(artifact, expectedHost);
}

function transcriptRecord(
  arrival: number,
  artifact: EnvelopeArtifact,
  authored: boolean,
): PersistedTranscriptEnvelope {
  return Object.freeze({ arrival, artifact, authored });
}

function copyRosterBody(body: RosterBody): RosterBody {
  return Object.freeze({
    gameId: parseGameId(body.gameId),
    rulesHash: parseHash256(body.rulesHash),
    iceConfigHash: parseHash256(body.iceConfigHash),
    seats: Object.freeze(body.seats.map(parseIdentityPublicKey)),
  });
}

function sameArtifact(left: EnvelopeArtifact, right: EnvelopeArtifact): boolean {
  return bytesEqual(left.canonicalBytes, right.canonicalBytes);
}

function transcriptTuple(artifact: EnvelopeArtifact): string {
  return `${bytesToHex(artifact.envelope.from)}:${artifact.envelope.seq}`;
}

function parseArrivalKey(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw new SessionStoreError("IndexedDB transcript arrival key is malformed");
  }
  return value;
}

function readGameRecord(value: unknown, expectedGame: string): Record<string, unknown> {
  if (value === undefined) {
    return { game: expectedGame };
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new SessionStoreError("IndexedDB contains a malformed game record");
  }
  const record = value as Record<string, unknown>;
  if (record["game"] !== expectedGame) {
    throw new SessionStoreError("IndexedDB game record has the wrong key");
  }
  return record;
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new SessionStoreError("IndexedDB request failed"));
  });
}

function transactionComplete(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error ?? new SessionStoreError("IndexedDB transaction aborted"));
    transaction.onerror = () => reject(transaction.error ?? new SessionStoreError("IndexedDB transaction failed"));
  });
}
