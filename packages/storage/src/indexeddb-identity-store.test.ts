import { bytesEqual, deriveEd25519PublicKey } from "@p2pcards/crypto";
import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it } from "vitest";

import { IDENTITY_STORE, openP2pCardsDatabase } from "./database";
import { IndexedDbIdentityStore } from "./indexeddb-identity-store";

describe("browser identity persistence", () => {
  it("atomically creates one identity across connections and restores it without regeneration", async () => {
    const factory = new IDBFactory();
    let generations = 0;
    const options = { factory, databaseName: "identity-concurrent", randomSource: {
      fill(target: Uint8Array) { generations += 1; target.fill(generations); },
    } };
    const first = new IndexedDbIdentityStore(options);
    const second = new IndexedDbIdentityStore(options);
    expect(await first.loadIdentity()).toBeNull();
    const [left, right] = await Promise.all([first.getOrCreateIdentity(), second.getOrCreateIdentity()]);
    expect(left).toEqual(right);
    expect(generations).toBe(1);
    expect(bytesEqual(deriveEd25519PublicKey(left.secretKey), left.publicKey)).toBe(true);
    left.secretKey.fill(0xff);
    left.publicKey.fill(0xff);
    expect(await first.loadIdentity()).toEqual(right);
    await Promise.all([first.close(), second.close()]);
    const restored = new IndexedDbIdentityStore(options);
    expect(await restored.getOrCreateIdentity()).toEqual(right);
    expect(generations).toBe(1);
    await restored.close();
  });

  it.each([
    { version: 2, secretKey: new Uint8Array(32), publicKey: new Uint8Array(32) },
    { version: 1, secretKey: new Uint8Array(31), publicKey: new Uint8Array(32) },
    { version: 1, secretKey: new Uint8Array(32), publicKey: new Uint8Array(32) },
    { version: 1, secretKey: new Uint8Array(32), publicKey: new Uint8Array(32), extra: true },
  ])("fails closed on corrupt stored records instead of replacing an identity: %j", async (record) => {
    const factory = new IDBFactory();
    const options = { factory, databaseName: "identity-corrupt" };
    const database = await openP2pCardsDatabase(options);
    const transaction = database.transaction(IDENTITY_STORE, "readwrite");
    const committed = new Promise<void>((resolve, reject) => {
      transaction.oncomplete = () => resolve(); transaction.onabort = () => reject(transaction.error);
    });
    transaction.objectStore(IDENTITY_STORE).put(record, "self");
    await committed;
    database.close();
    let generated = false;
    const store = new IndexedDbIdentityStore({ ...options, randomSource: { fill() { generated = true; } } });
    await expect(store.getOrCreateIdentity()).rejects.toThrow();
    expect(generated).toBe(false);
    await expect(store.loadIdentity()).rejects.toThrow();
    await store.close();
  });

  it("does not commit a half-created identity when randomness fails", async () => {
    const factory = new IDBFactory();
    const store = new IndexedDbIdentityStore({ factory, databaseName: "identity-abort", randomSource: { fill() { throw new Error("entropy unavailable"); } } });
    await expect(store.getOrCreateIdentity()).rejects.toThrow(/entropy/);
    expect(await store.loadIdentity()).toBeNull();
    await store.close();
  });
});
