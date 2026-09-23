import {
  bytesEqual, deriveEd25519PublicKey, generateEd25519KeyPair,
  importEd25519PublicKey, importEd25519SecretKey,
  type Ed25519KeyPair, type RandomSource,
} from "@p2pcards/crypto";

import { IDENTITY_STORE, openP2pCardsDatabase, type IndexedDbStoreOptions } from "./database";

export class IndexedDbIdentityStore {
  readonly #database: Promise<IDBDatabase>;
  readonly #randomSource: RandomSource | undefined;

  constructor(options: IndexedDbStoreOptions & { readonly randomSource?: RandomSource } = {}) {
    this.#database = openP2pCardsDatabase(options);
    this.#randomSource = options.randomSource;
  }

  async getOrCreateIdentity(): Promise<Ed25519KeyPair> {
    return (await this.#read(true))!;
  }

  async loadIdentity(): Promise<Ed25519KeyPair | null> {
    return this.#read(false);
  }

  async #read(create: boolean): Promise<Ed25519KeyPair | null> {
    const database = await this.#database;
    return new Promise((resolve, reject) => {
      const transaction = database.transaction(IDENTITY_STORE, create ? "readwrite" : "readonly");
      const store = transaction.objectStore(IDENTITY_STORE);
      const request = store.get("self");
      let result: Ed25519KeyPair | null = null;
      let error: unknown;
      request.onsuccess = () => {
        try {
          if (request.result === undefined) {
            if (create) {
              const generated = generateEd25519KeyPair(this.#randomSource);
              const record = { version: 1, secretKey: generated.secretKey.slice(), publicKey: generated.publicKey.slice() };
              result = decodeIdentity(record);
              store.add(record, "self");
            }
          } else {
            result = decodeIdentity(request.result);
          }
        } catch (cause) {
          error = cause;
          transaction.abort();
        }
      };
      transaction.oncomplete = () => resolve(result);
      transaction.onabort = () => reject(error ?? transaction.error ?? new Error("Identity transaction aborted"));
      transaction.onerror = () => { error ??= transaction.error; };
    });
  }

  async close(): Promise<void> {
    (await this.#database).close();
  }
}

function decodeIdentity(value: unknown): Ed25519KeyPair {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Stored identity is malformed; it will not be replaced automatically");
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join(",") !== "publicKey,secretKey,version" || record["version"] !== 1) {
    throw new Error("Stored identity has an unsupported format; recovery is required");
  }
  const secretKey = importEd25519SecretKey(record["secretKey"] as Uint8Array);
  const publicKey = importEd25519PublicKey(record["publicKey"] as Uint8Array);
  if (!bytesEqual(deriveEd25519PublicKey(secretKey), publicKey)) {
    throw new Error("Stored identity keys do not match; recovery is required");
  }
  return Object.freeze({ secretKey, publicKey });
}
