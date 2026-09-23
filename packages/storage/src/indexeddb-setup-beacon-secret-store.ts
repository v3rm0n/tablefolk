import { bytesEqual, bytesToHex } from "@p2pcards/crypto";
import {
  parseGameId,
  parseRandomSecret,
  snapshotSetupBeaconScope,
  type GameId,
  type RandomSecret,
  type SetupBeaconScope,
} from "@p2pcards/protocol";

import {
  GAMES_STORE,
  openP2pCardsDatabase,
  type IndexedDbStoreOptions,
} from "./database";

const SETUP_BEACON_SECRET_FIELD = "setupBeaconSecret";

export class SetupBeaconSecretStoreError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SetupBeaconSecretStoreError";
  }
}

export class IndexedDbSetupBeaconSecretStore {
  readonly #database: Promise<IDBDatabase>;

  constructor(options: IndexedDbStoreOptions = {}) {
    this.#database = openP2pCardsDatabase(options);
  }

  async getOrCreateSetupBeaconSecret(
    scope: SetupBeaconScope,
    create: () => RandomSecret,
  ): Promise<RandomSecret> {
    const requested = snapshotSetupBeaconScope(scope);
    if (typeof create !== "function") {
      throw new TypeError("Setup beacon secret create callback must be a function");
    }
    const game = bytesToHex(requested.gameId);
    const selected = await this.#withGameRecord(game, "readwrite", (record, games) => {
      if (Object.hasOwn(record, SETUP_BEACON_SECRET_FIELD)) {
        return decodeStoredSecret(record[SETUP_BEACON_SECRET_FIELD], requested);
      }

      const candidate = create();
      let secret: RandomSecret;
      try {
        secret = parseRandomSecret(candidate);
      } catch {
        // Observe accidental async failures without awaiting inside the transaction.
        void Promise.resolve(candidate).catch(() => {});
        throw new SetupBeaconSecretStoreError(
          "Setup beacon secret must be a synchronous 32-byte Uint8Array",
        );
      }
      games.put({
        ...record,
        [SETUP_BEACON_SECRET_FIELD]: {
          version: 1,
          round: requested.round,
          sender: requested.sender.slice(),
          roster: requested.roster.map((identity) => identity.slice()),
          secret: parseRandomSecret(secret),
        },
      });
      return secret;
    });
    return parseRandomSecret(selected);
  }

  async loadSetupBeaconSecret(scope: SetupBeaconScope): Promise<RandomSecret | null> {
    const requested = snapshotSetupBeaconScope(scope);
    const game = bytesToHex(requested.gameId);
    const selected = await this.#withGameRecord(game, "readonly", (record) =>
      Object.hasOwn(record, SETUP_BEACON_SECRET_FIELD)
        ? decodeStoredSecret(record[SETUP_BEACON_SECRET_FIELD], requested)
        : null,
    );
    return selected === null ? null : parseRandomSecret(selected);
  }

  async deleteSetupBeaconSecret(gameId: GameId): Promise<void> {
    const game = bytesToHex(parseGameId(gameId));
    await this.#withGameRecord(game, "readwrite", (record, games) => {
      delete record[SETUP_BEACON_SECRET_FIELD];
      if (Object.keys(record).length === 1) {
        games.delete(game);
      } else {
        games.put(record);
      }
    });
  }

  async close(): Promise<void> {
    const database = await this.#database;
    database.close();
  }

  async #withGameRecord<T>(
    game: string,
    mode: "readonly" | "readwrite",
    operation: (record: Record<string, unknown>, games: IDBObjectStore) => T,
  ): Promise<T> {
    const database = await this.#database;
    return new Promise<T>((resolve, reject) => {
      const transaction = database.transaction(GAMES_STORE, mode);
      const games = transaction.objectStore(GAMES_STORE);
      const request = games.get(game);
      let result: { value: T } | undefined;
      let failed = false;
      let failure: unknown;

      request.onsuccess = () => {
        try {
          result = { value: operation(readGameRecord(request.result, game), games) };
        } catch (cause) {
          failed = true;
          failure = cause;
          try {
            transaction.abort();
          } catch {
            // A callback may already have aborted the transaction.
          }
        }
      };
      transaction.oncomplete = () => {
        if (failed) {
          reject(failure);
        } else if (result === undefined) {
          reject(new SetupBeaconSecretStoreError("Setup beacon secret transaction has no result"));
        } else {
          resolve(result.value);
        }
      };
      transaction.onabort = () => {
        reject(
          failed
            ? failure
            : transaction.error ??
                new SetupBeaconSecretStoreError("IndexedDB setup beacon secret transaction aborted"),
        );
      };
      transaction.onerror = () => {
        if (!failed) {
          failed = true;
          failure = transaction.error ??
            new SetupBeaconSecretStoreError("IndexedDB setup beacon secret transaction failed");
        }
      };
    });
  }
}

function readGameRecord(value: unknown, expectedGame: string): Record<string, unknown> {
  if (value === undefined) {
    return { game: expectedGame };
  }
  if (
    typeof value !== "object" || value === null ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    throw new SetupBeaconSecretStoreError("IndexedDB contains a malformed game record");
  }
  const game = Object.getOwnPropertyDescriptor(value, "game");
  if (game === undefined || !game.enumerable || !("value" in game) || game.value !== expectedGame) {
    throw new SetupBeaconSecretStoreError("IndexedDB game record has the wrong key");
  }
  return value as Record<string, unknown>;
}

function decodeStoredSecret(value: unknown, requested: SetupBeaconScope): RandomSecret {
  let stored: SetupBeaconScope;
  let secret: RandomSecret;
  try {
    if (
      typeof value !== "object" || value === null ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
    ) {
      throw new TypeError("Invalid setup beacon secret record");
    }
    const fields = Object.getOwnPropertyDescriptors(value);
    if (
      Reflect.ownKeys(fields).length !== 5 ||
      !["version", "round", "sender", "roster", "secret"].every((key) => {
        const field = fields[key];
        return field !== undefined && field.enumerable && "value" in field;
      }) || fields["version"]!.value !== 1
    ) {
      throw new TypeError("Invalid setup beacon secret fields");
    }
    stored = snapshotSetupBeaconScope({
      gameId: requested.gameId,
      round: fields["round"]!.value,
      sender: fields["sender"]!.value,
      roster: fields["roster"]!.value,
    });
    secret = parseRandomSecret(fields["secret"]!.value);
  } catch {
    throw new SetupBeaconSecretStoreError("IndexedDB contains a malformed setup beacon secret");
  }
  if (
    stored.round !== requested.round || !bytesEqual(stored.sender, requested.sender) ||
    stored.roster.length !== requested.roster.length ||
    !stored.roster.every((identity, seat) => bytesEqual(identity, requested.roster[seat]!))
  ) {
    throw new SetupBeaconSecretStoreError("Stored setup beacon secret has a different scope");
  }
  return secret;
}
