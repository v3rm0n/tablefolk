import { bytesEqual, bytesToHex } from "@p2pcards/crypto";
import {
  decodeAndVerifyEnvelope,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  type EnvelopeArtifact,
  type GameId,
  type IdentityPublicKey,
} from "@p2pcards/protocol";
import {
  AuthoredEnvelopeStoreError,
  MAX_AUTHORED_HISTORY_PAGE_BYTES,
  MAX_AUTHORED_HISTORY_PAGE_ENVELOPES,
  type AuthoredEnvelopeStore,
  type AuthoredHistoryStore,
} from "@p2pcards/session";

import {
  AUTHORED_HEADS_STORE,
  openP2pCardsDatabase,
  TRANSCRIPTS_STORE,
  TRANSCRIPT_SENDER_SEQUENCE_INDEX,
  type IndexedDbStoreOptions,
} from "./database";
const ZERO_HASH = parseHash256(new Uint8Array(32));

export interface IndexedDbAuthoredEnvelopeStoreOptions extends IndexedDbStoreOptions {
  readonly keyRange?: Pick<typeof IDBKeyRange, "bound">;
}

interface StoredAuthoredHead {
  readonly game: string;
  readonly sender: string;
  readonly bytes: Uint8Array;
}

interface StoredTranscriptEnvelope {
  readonly arrival?: number;
  readonly game: string;
  readonly sender: string;
  readonly seq: number;
  readonly bytes: Uint8Array;
  readonly authored: true;
}

export class IndexedDbAuthoredEnvelopeStore implements AuthoredEnvelopeStore, AuthoredHistoryStore {
  readonly #database: Promise<IDBDatabase>;
  readonly #keyRange: Pick<typeof IDBKeyRange, "bound"> | undefined;

  constructor(options: IndexedDbAuthoredEnvelopeStoreOptions = {}) {
    this.#keyRange = options.keyRange ?? globalThis.IDBKeyRange;
    this.#database = openP2pCardsDatabase(options);
  }

  async appendNext(
    gameId: GameId,
    sender: IdentityPublicKey,
    create: (head: EnvelopeArtifact | null) => EnvelopeArtifact,
  ): Promise<void> {
    if (typeof create !== "function") {
      throw new TypeError("appendNext create callback must be a function");
    }

    const game = parseGameId(gameId);
    const author = parseIdentityPublicKey(sender);
    await this.#withCheckpoint<void>(game, author, "readwrite", (transaction, head, finish) => {
      const candidate = create(head === null ? null : decodeAndVerifyEnvelope(head.canonicalBytes));
      const artifact = validateNextArtifact(candidate, game, author, head);
      const record: StoredTranscriptEnvelope = {
        game: bytesToHex(game), sender: bytesToHex(author), seq: artifact.envelope.seq,
        bytes: artifact.canonicalBytes.slice(), authored: true,
      };
      const storedHead: StoredAuthoredHead = {
        game: record.game, sender: record.sender, bytes: artifact.canonicalBytes.slice(),
      };
      transaction.objectStore(TRANSCRIPTS_STORE).add(record);
      transaction.objectStore(AUTHORED_HEADS_STORE).put(storedHead);
      finish(undefined);
    });
  }

  async readAuthoredHead(gameId: GameId, sender: IdentityPublicKey): Promise<EnvelopeArtifact | null> {
    return this.#withCheckpoint(gameId, sender, "readonly", (_transaction, head, finish) => finish(head));
  }

  async readAuthoredPage(
    gameId: GameId,
    sender: IdentityPublicKey,
    fromSeq: number,
    toSeq: number,
  ): Promise<readonly EnvelopeArtifact[]> {
    if (!Number.isSafeInteger(fromSeq) || fromSeq < 0 || !Number.isSafeInteger(toSeq) || toSeq < fromSeq ||
        toSeq - fromSeq >= MAX_AUTHORED_HISTORY_PAGE_ENVELOPES) {
      throw new RangeError("Authored page must be an inclusive range of at most 128 safe sequences");
    }
    const game = parseGameId(gameId);
    const author = parseIdentityPublicKey(sender);
    return this.#withCheckpoint(game, author, "readonly", (transaction, head, finish, fail) => {
      if (head === null || toSeq > head.envelope.seq) {
        throw new AuthoredEnvelopeStoreError("Requested history exceeds the durable authored checkpoint");
      }
      const query = this.#keyRange!.bound(
        [bytesToHex(game), bytesToHex(author), fromSeq],
        [bytesToHex(game), bytesToHex(author), toSeq],
      );
      const request = transaction.objectStore(TRANSCRIPTS_STORE).index(TRANSCRIPT_SENDER_SEQUENCE_INDEX).openCursor(query);
      const artifacts: EnvelopeArtifact[] = [];
      let bytes = 0;
      request.onsuccess = () => {
        try {
          const cursor = request.result;
          if (cursor === null) {
            throw new AuthoredEnvelopeStoreError("Authored history page is missing an envelope");
          }
          const record = decodeRecordMetadata(cursor.value, game, author);
          if (record.seq !== fromSeq + artifacts.length) {
            throw new AuthoredEnvelopeStoreError("Authored history page contains a sequence gap");
          }
          if (record.bytes.length > MAX_AUTHORED_HISTORY_PAGE_BYTES - bytes) {
            if (artifacts.length === 0) {
              throw new AuthoredEnvelopeStoreError("Authored envelope exceeds the page byte limit");
            }
            finish(Object.freeze(artifacts));
            return;
          }
          const artifact = decodeAndVerifyEnvelope(record.bytes);
          if (!bytesEqual(artifact.envelope.game, game) || !bytesEqual(artifact.envelope.from, author) ||
              artifact.envelope.seq !== record.seq) {
            throw new AuthoredEnvelopeStoreError("Authored history record has mismatched signed metadata");
          }
          const previous = artifacts.at(-1);
          if ((previous !== undefined && !bytesEqual(artifact.envelope.prev, previous.hash)) ||
              (record.seq === 0 && !bytesEqual(artifact.envelope.prev, ZERO_HASH))) {
            throw new AuthoredEnvelopeStoreError("Authored history page has a broken predecessor");
          }
          artifacts.push(artifact);
          bytes += artifact.canonicalBytes.length;
          if (record.seq === toSeq) {
            finish(Object.freeze(artifacts));
          } else {
            cursor.continue();
          }
        } catch (cause) {
          fail(cause);
        }
      };
    });
  }

  async #withCheckpoint<T>(
    gameId: GameId,
    sender: IdentityPublicKey,
    mode: IDBTransactionMode,
    run: (transaction: IDBTransaction, head: EnvelopeArtifact | null, finish: (value: T) => void, fail: (cause: unknown) => void) => void,
  ): Promise<T> {
    const game = parseGameId(gameId);
    const author = parseIdentityPublicKey(sender);
    if (this.#keyRange === undefined || typeof this.#keyRange.bound !== "function") {
      throw new AuthoredEnvelopeStoreError("IDBKeyRange is unavailable; provide it with an injected factory");
    }
    const database = await this.#database;
    return new Promise<T>((resolve, reject) => {
      const transaction = database.transaction([AUTHORED_HEADS_STORE, TRANSCRIPTS_STORE], mode);
      const index = transaction.objectStore(TRANSCRIPTS_STORE).index(TRANSCRIPT_SENDER_SEQUENCE_INDEX);
      const gameKey = bytesToHex(game);
      const authorKey = bytesToHex(author);
      // A prefix bound includes all sequence keys for this exact game/sender, not another identity.
      const query = this.#keyRange!.bound([gameKey, authorKey], [gameKey, `${authorKey}\u0000`], false, true);
      const headRequest = transaction.objectStore(AUTHORED_HEADS_STORE).get([gameKey, authorKey]);
      const lastRequest = index.openCursor(query, "prev");
      const countRequest = index.count(query);
      let pending = 3;
      let completed = false;
      let value: T;
      let operationError: unknown;
      const fail = (cause: unknown): void => {
        operationError = cause;
        transaction.abort();
      };
      const ready = (): void => {
        pending -= 1;
        if (pending !== 0) {
          return;
        }
        try {
          const head = decodeStoredHead(headRequest.result, game, author);
          const last = lastRequest.result?.value as unknown;
          validateCheckpoint(head, last, countRequest.result, game, author);
          run(transaction, head, (result) => { value = result; completed = true; }, fail);
        } catch (cause) {
          fail(cause);
        }
      };
      headRequest.onsuccess = ready;
      lastRequest.onsuccess = ready;
      countRequest.onsuccess = ready;
      transaction.oncomplete = () => {
        if (completed) {
          resolve(value!);
        } else {
          reject(new AuthoredEnvelopeStoreError("Authored history transaction completed without a result"));
        }
      };
      transaction.onabort = () => {
        reject(
          operationError ??
            transaction.error ??
            new AuthoredEnvelopeStoreError("IndexedDB authored history transaction aborted"),
        );
      };
      transaction.onerror = () => {
        operationError ??= transaction.error;
      };
    });
  }

  async close(): Promise<void> {
    const database = await this.#database;
    database.close();
  }
}

function decodeStoredHead(
  value: unknown,
  gameId: GameId,
  sender: IdentityPublicKey,
): EnvelopeArtifact | null {
  if (value === undefined) {
    return null;
  }
  if (typeof value !== "object" || value === null || !("bytes" in value)) {
    throw new AuthoredEnvelopeStoreError("IndexedDB contains a malformed authored head");
  }
  const bytes = (value as { readonly bytes: unknown }).bytes;
  if (!(bytes instanceof Uint8Array) || bytes.constructor !== Uint8Array) {
    throw new AuthoredEnvelopeStoreError("IndexedDB authored head bytes are malformed");
  }
  if (bytes.length > MAX_AUTHORED_HISTORY_PAGE_BYTES) {
    throw new AuthoredEnvelopeStoreError("IndexedDB authored head exceeds the byte limit");
  }

  let artifact: EnvelopeArtifact;
  try {
    artifact = decodeAndVerifyEnvelope(bytes);
  } catch (cause) {
    throw new AuthoredEnvelopeStoreError("IndexedDB contains an invalid authored head", {
      cause,
    });
  }
  if (!bytesEqual(artifact.envelope.game, gameId)) {
    throw new AuthoredEnvelopeStoreError("IndexedDB authored head belongs to another game");
  }
  if (!bytesEqual(artifact.envelope.from, sender)) {
    throw new AuthoredEnvelopeStoreError("IndexedDB authored head belongs to another sender");
  }
  return artifact;
}

function decodeRecordMetadata(value: unknown, game: GameId, sender: IdentityPublicKey): StoredTranscriptEnvelope {
  if (typeof value !== "object" || value === null) {
    throw new AuthoredEnvelopeStoreError("IndexedDB is missing an authored transcript record");
  }
  const record = value as StoredTranscriptEnvelope;
  if (record.game !== bytesToHex(game) || record.sender !== bytesToHex(sender) ||
      !Number.isSafeInteger(record.seq) || record.seq < 0 || record.authored !== true ||
      !(record.bytes instanceof Uint8Array) || record.bytes.constructor !== Uint8Array) {
    throw new AuthoredEnvelopeStoreError("IndexedDB authored transcript metadata is invalid; recovery is required");
  }
  return record;
}

function validateCheckpoint(head: EnvelopeArtifact | null, last: unknown, count: number, game: GameId, sender: IdentityPublicKey): void {
  if (head === null) {
    if (last !== undefined || count !== 0) {
      throw new AuthoredEnvelopeStoreError("Authored checkpoint is missing but history exists; recovery is required");
    }
    return;
  }
  const record = decodeRecordMetadata(last, game, sender);
  if (!Number.isSafeInteger(count) || head.envelope.seq >= Number.MAX_SAFE_INTEGER ||
      count !== head.envelope.seq + 1 || record.seq !== head.envelope.seq ||
      !bytesEqual(record.bytes, head.canonicalBytes) ||
      (head.envelope.seq === 0 && !bytesEqual(head.envelope.prev, ZERO_HASH))) {
    throw new AuthoredEnvelopeStoreError("Authored checkpoint and transcript disagree; recovery is required");
  }
}

function validateNextArtifact(
  candidate: EnvelopeArtifact,
  gameId: GameId,
  sender: IdentityPublicKey,
  head: EnvelopeArtifact | null,
): EnvelopeArtifact {
  let artifact: EnvelopeArtifact;
  try {
    const bytes = candidate.canonicalBytes;
    if (!(bytes instanceof Uint8Array) || bytes.constructor !== Uint8Array) {
      throw new AuthoredEnvelopeStoreError("Authored envelope bytes are malformed");
    }
    if (bytes.length > MAX_AUTHORED_HISTORY_PAGE_BYTES) {
      throw new AuthoredEnvelopeStoreError("Authored envelope exceeds the byte limit");
    }
    artifact = decodeAndVerifyEnvelope(bytes);
  } catch (cause) {
    throw new AuthoredEnvelopeStoreError("Author callback returned an invalid envelope", { cause });
  }

  if (head !== null && head.envelope.seq >= Number.MAX_SAFE_INTEGER) {
    throw new AuthoredEnvelopeStoreError("Authored sequence cannot be advanced safely");
  }
  const expectedSeq = head === null ? 0 : head.envelope.seq + 1;
  const expectedPrev = head?.hash ?? ZERO_HASH;
  if (!bytesEqual(artifact.envelope.game, gameId)) {
    throw new AuthoredEnvelopeStoreError("Authored envelope has the wrong game");
  }
  if (!bytesEqual(artifact.envelope.from, sender)) {
    throw new AuthoredEnvelopeStoreError("Authored envelope has the wrong sender");
  }
  if (artifact.envelope.seq !== expectedSeq) {
    throw new AuthoredEnvelopeStoreError(
      `Authored envelope sequence must be ${expectedSeq}; got ${artifact.envelope.seq}`,
    );
  }
  if (!bytesEqual(artifact.envelope.prev, expectedPrev)) {
    throw new AuthoredEnvelopeStoreError("Authored envelope has the wrong predecessor hash");
  }
  return artifact;
}
