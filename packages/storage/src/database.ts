export const P2PCARDS_DATABASE_NAME = "p2pcards";
export const P2PCARDS_DATABASE_VERSION = 1;
export const IDENTITY_STORE = "identity";
export const GAMES_STORE = "games";
export const TRANSCRIPTS_STORE = "transcripts";
export const AUTHORED_HEADS_STORE = "authored_heads";

export const TRANSCRIPT_SENDER_SEQUENCE_INDEX = "by_game_sender_sequence";
export const TRANSCRIPT_GAME_INDEX = "by_game";

export interface IndexedDbStoreOptions {
  readonly databaseName?: string;
  readonly factory?: IDBFactory;
}

export function openP2pCardsDatabase(
  options: IndexedDbStoreOptions = {},
): Promise<IDBDatabase> {
  const factory =
    options.factory ??
    (globalThis as typeof globalThis & { readonly indexedDB?: IDBFactory }).indexedDB;
  if (factory === undefined || typeof factory.open !== "function") {
    throw new Error("IndexedDB is unavailable");
  }
  const databaseName = options.databaseName ?? P2PCARDS_DATABASE_NAME;
  if (databaseName.length === 0) {
    throw new TypeError("IndexedDB database name must not be empty");
  }

  return new Promise((resolve, reject) => {
    const request = factory.open(databaseName, P2PCARDS_DATABASE_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(IDENTITY_STORE)) {
        database.createObjectStore(IDENTITY_STORE);
      }
      if (!database.objectStoreNames.contains(GAMES_STORE)) {
        database.createObjectStore(GAMES_STORE, { keyPath: "game" });
      }
      if (!database.objectStoreNames.contains(TRANSCRIPTS_STORE)) {
        const transcripts = database.createObjectStore(TRANSCRIPTS_STORE, {
          keyPath: "arrival",
          autoIncrement: true,
        });
        transcripts.createIndex(
          TRANSCRIPT_SENDER_SEQUENCE_INDEX,
          ["game", "sender", "seq"],
          { unique: true },
        );
        transcripts.createIndex(TRANSCRIPT_GAME_INDEX, "game", { unique: false });
      }
      if (!database.objectStoreNames.contains(AUTHORED_HEADS_STORE)) {
        database.createObjectStore(AUTHORED_HEADS_STORE, {
          keyPath: ["game", "sender"],
        });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Failed to open IndexedDB"));
    request.onblocked = () => reject(new Error("IndexedDB upgrade is blocked by another client"));
  });
}
