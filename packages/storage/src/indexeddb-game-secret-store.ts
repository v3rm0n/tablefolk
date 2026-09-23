import {
  bytesToHex,
  decodeRistrettoScalar,
  encodeRistrettoScalar,
  RISTRETTO_SCALAR_ZERO,
  type RistrettoScalar,
} from "@p2pcards/crypto";
import { parseGameId, type GameId } from "@p2pcards/protocol";

import {
  GAMES_STORE,
  openP2pCardsDatabase,
  type IndexedDbStoreOptions,
} from "./database";

const GAME_SECRET_FIELD = "gameSecret";

export class GameSecretStoreError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "GameSecretStoreError";
  }
}

export class IndexedDbGameSecretStore {
  readonly #database: Promise<IDBDatabase>;

  constructor(options: IndexedDbStoreOptions = {}) {
    this.#database = openP2pCardsDatabase(options);
  }

  async getOrCreateGameSecret(
    gameId: GameId,
    create: () => RistrettoScalar,
  ): Promise<RistrettoScalar> {
    if (typeof create !== "function") {
      throw new TypeError("Game-secret create callback must be a function");
    }
    const game = bytesToHex(parseGameId(gameId));
    const database = await this.#database;
    let selected: RistrettoScalar | null = null;

    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(GAMES_STORE, "readwrite");
      const games = transaction.objectStore(GAMES_STORE);
      const request = games.get(game);
      let operationError: unknown;

      request.onsuccess = () => {
        try {
          const record = readGameRecord(request.result, game);
          if (Object.hasOwn(record, GAME_SECRET_FIELD)) {
            selected = decodeStoredSecret(record[GAME_SECRET_FIELD]);
            return;
          }

          const secret = create();
          const encoded = encodeRistrettoScalar(secret);
          if (secret === RISTRETTO_SCALAR_ZERO) {
            throw new GameSecretStoreError("Game secret must be non-zero");
          }
          selected = secret;
          games.put({ ...record, game, [GAME_SECRET_FIELD]: encoded });
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
            new GameSecretStoreError("IndexedDB game-secret transaction aborted"),
        );
      };
      transaction.onerror = () => {
        operationError ??= transaction.error;
      };
    });

    if (selected === null) {
      throw new GameSecretStoreError("Game-secret transaction completed without a value");
    }
    return selected;
  }

  async loadGameSecret(gameId: GameId): Promise<RistrettoScalar | null> {
    const game = bytesToHex(parseGameId(gameId));
    const database = await this.#database;
    const transaction = database.transaction(GAMES_STORE, "readonly");
    const result = await requestResult(transaction.objectStore(GAMES_STORE).get(game));
    await transactionComplete(transaction);
    if (result === undefined) {
      return null;
    }
    const record = readGameRecord(result, game);
    return Object.hasOwn(record, GAME_SECRET_FIELD)
      ? decodeStoredSecret(record[GAME_SECRET_FIELD])
      : null;
  }

  async deleteGameSecret(gameId: GameId): Promise<void> {
    const game = bytesToHex(parseGameId(gameId));
    const database = await this.#database;

    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(GAMES_STORE, "readwrite");
      const games = transaction.objectStore(GAMES_STORE);
      const request = games.get(game);
      let operationError: unknown;

      request.onsuccess = () => {
        try {
          if (request.result === undefined) {
            return;
          }
          const record = { ...readGameRecord(request.result, game) };
          delete record[GAME_SECRET_FIELD];
          if (Object.keys(record).length === 1) {
            games.delete(game);
          } else {
            games.put(record);
          }
        } catch (cause) {
          operationError = cause;
          transaction.abort();
        }
      };
      transaction.oncomplete = () => resolve();
      transaction.onabort = () => {
        reject(operationError ?? transaction.error ?? new GameSecretStoreError("Delete aborted"));
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

function readGameRecord(value: unknown, expectedGame: string): Record<string, unknown> {
  if (value === undefined) {
    return { game: expectedGame };
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new GameSecretStoreError("IndexedDB contains a malformed game record");
  }
  const record = value as Record<string, unknown>;
  if (record["game"] !== expectedGame) {
    throw new GameSecretStoreError("IndexedDB game record has the wrong key");
  }
  return record;
}

function decodeStoredSecret(value: unknown): RistrettoScalar {
  if (!(value instanceof Uint8Array) || value.constructor !== Uint8Array) {
    throw new GameSecretStoreError("IndexedDB game secret is not a byte array");
  }
  try {
    const secret = decodeRistrettoScalar(value);
    if (secret === RISTRETTO_SCALAR_ZERO) {
      throw new GameSecretStoreError("IndexedDB game secret must be non-zero");
    }
    return secret;
  } catch (cause) {
    if (cause instanceof GameSecretStoreError) {
      throw cause;
    }
    throw new GameSecretStoreError("IndexedDB game secret is not canonical", { cause });
  }
}

function requestResult(request: IDBRequest): Promise<unknown> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function transactionComplete(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error);
    transaction.onerror = () => reject(transaction.error);
  });
}
