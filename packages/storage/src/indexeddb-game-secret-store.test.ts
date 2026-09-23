import {
  bytesToHex,
  RISTRETTO_SCALAR_ZERO,
  scalarFromBigInt,
} from "@p2pcards/crypto";
import { parseGameId } from "@p2pcards/protocol";
import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it } from "vitest";

import { GAMES_STORE, openP2pCardsDatabase } from "./database";
import {
  GameSecretStoreError,
  IndexedDbGameSecretStore,
} from "./indexeddb-game-secret-store";

const GAME_ID = parseGameId(new Uint8Array(16).fill(0x31));

describe("IndexedDB game-secret store", () => {
  it("persists one non-zero scalar and restores it after reopening", async () => {
    const factory = new IDBFactory();
    const databaseName = "game-secret-restart";
    const firstStore = new IndexedDbGameSecretStore({ factory, databaseName });
    let createCalls = 0;

    const first = await firstStore.getOrCreateGameSecret(GAME_ID, () => {
      createCalls += 1;
      return scalarFromBigInt(17n);
    });
    const repeated = await firstStore.getOrCreateGameSecret(GAME_ID, () => {
      createCalls += 1;
      return scalarFromBigInt(18n);
    });
    await firstStore.close();

    const resumedStore = new IndexedDbGameSecretStore({ factory, databaseName });
    expect(await resumedStore.loadGameSecret(GAME_ID)).toBe(first);
    expect(repeated).toBe(first);
    expect(createCalls).toBe(1);
    await resumedStore.close();
  });

  it("serializes competing creators across database connections", async () => {
    const factory = new IDBFactory();
    const databaseName = "game-secret-concurrency";
    const left = new IndexedDbGameSecretStore({ factory, databaseName });
    const right = new IndexedDbGameSecretStore({ factory, databaseName });
    let createCalls = 0;

    const secrets = await Promise.all([
      left.getOrCreateGameSecret(GAME_ID, () => {
        createCalls += 1;
        return scalarFromBigInt(21n);
      }),
      right.getOrCreateGameSecret(GAME_ID, () => {
        createCalls += 1;
        return scalarFromBigInt(22n);
      }),
    ]);

    expect(secrets[0]).toBe(secrets[1]);
    expect(createCalls).toBe(1);
    await Promise.all([left.close(), right.close()]);
  });

  it("aborts a zero secret without creating a game record", async () => {
    const factory = new IDBFactory();
    const store = new IndexedDbGameSecretStore({ factory, databaseName: "zero-secret" });

    await expect(
      store.getOrCreateGameSecret(GAME_ID, () => RISTRETTO_SCALAR_ZERO),
    ).rejects.toThrow(GameSecretStoreError);
    expect(await store.loadGameSecret(GAME_ID)).toBeNull();
    expect(await store.getOrCreateGameSecret(GAME_ID, () => scalarFromBigInt(1n))).toBe(1n);
    await store.close();
  });

  it("deletes only the secret while preserving other game state", async () => {
    const factory = new IDBFactory();
    const databaseName = "delete-secret";
    const database = await openP2pCardsDatabase({ factory, databaseName });
    const game = bytesToHex(GAME_ID);
    await putGameRecord(database, { game, phase: "setup.keys" });
    database.close();

    const store = new IndexedDbGameSecretStore({ factory, databaseName });
    await store.getOrCreateGameSecret(GAME_ID, () => scalarFromBigInt(29n));
    await store.deleteGameSecret(GAME_ID);
    expect(await store.loadGameSecret(GAME_ID)).toBeNull();
    await store.close();

    const inspection = await openP2pCardsDatabase({ factory, databaseName });
    expect(await getGameRecord(inspection, game)).toEqual({ game, phase: "setup.keys" });
    inspection.close();
  });

  it("rejects malformed persisted scalar bytes", async () => {
    const factory = new IDBFactory();
    const databaseName = "corrupt-secret";
    const database = await openP2pCardsDatabase({ factory, databaseName });
    await putGameRecord(database, {
      game: bytesToHex(GAME_ID),
      gameSecret: new Uint8Array(31),
    });
    database.close();

    const store = new IndexedDbGameSecretStore({ factory, databaseName });
    await expect(store.loadGameSecret(GAME_ID)).rejects.toThrow(GameSecretStoreError);
    await store.close();
  });
});

function putGameRecord(database: IDBDatabase, value: object): Promise<void> {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(GAMES_STORE, "readwrite");
    transaction.objectStore(GAMES_STORE).put(value);
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error);
    transaction.onerror = () => reject(transaction.error);
  });
}

function getGameRecord(database: IDBDatabase, game: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const request = database.transaction(GAMES_STORE, "readonly").objectStore(GAMES_STORE).get(game);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
