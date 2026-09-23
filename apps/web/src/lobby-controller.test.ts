import { bytesToHex } from "@p2pcards/crypto";
import { IndexedDbIdentityStore } from "@p2pcards/storage";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { describe, expect, it, vi } from "vitest";

import { BrowserLobbyController } from "./lobby-controller";

describe("browser lobby controller lifecycle", () => {
  it("initializes a cached public-only snapshot without connecting to relays", async () => {
    const options = { factory: new IDBFactory(), keyRange: IDBKeyRange, databaseName: "controller-identity" };
    const controller = new BrowserLobbyController({ baseUrl: "https://example.test/cards/", storage: options });
    const listener = vi.fn();
    const unsubscribe = controller.subscribe(listener);
    expect(controller.getSnapshot()).toBe(controller.getSnapshot());
    await Promise.all([controller.initialize(), controller.initialize()]);
    const snapshot = controller.getSnapshot();
    expect(snapshot.phase).toBe("welcome");
    expect(snapshot.room).toBeNull();
    expect(snapshot.relays).toEqual([]);
    expect(snapshot.peers).toEqual([]);
    const identities = new IndexedDbIdentityStore(options);
    const identity = (await identities.loadIdentity())!;
    expect(snapshot.identity?.publicKey).toBe(bytesToHex(identity.publicKey));
    expect(JSON.stringify(snapshot)).not.toContain(bytesToHex(identity.secretKey));
    expect(JSON.stringify(snapshot)).not.toContain("secretKey");
    expect(listener).toHaveBeenCalledTimes(1);
    expect(controller.getSnapshot()).toBe(snapshot);
    unsubscribe();
    await Promise.all([identities.close(), controller.dispose()]);
  });

  it("rejects invalid configuration before opening a room and keeps errors actionable", async () => {
    const controller = new BrowserLobbyController({
      baseUrl: "https://example.test/cards/",
      storage: { factory: new IDBFactory(), keyRange: IDBKeyRange, databaseName: "controller-invalid" },
    });
    await controller.initialize();
    await expect(controller.join("https://example.test/#g=bad")).rejects.toThrow(/Invitation/);
    expect(controller.getSnapshot().error).toMatch(/Invitation/);
    await expect(controller.create("ws://remote.example/")).rejects.toThrow(/wss/);
    expect(controller.getSnapshot()).toMatchObject({ room: null, busy: null, phase: "welcome", peers: [], relays: [] });
    await expect(controller.markReady()).rejects.toThrow(/No active table/);
    await controller.dispose();
  });

  it("does not publish an identity after disposal races initialization", async () => {
    const controller = new BrowserLobbyController({
      baseUrl: "https://example.test/",
      storage: { factory: new IDBFactory(), databaseName: "controller-dispose" },
    });
    const listener = vi.fn();
    controller.subscribe(listener);
    const initialized = controller.initialize();
    await controller.dispose();
    await initialized;
    expect(listener).not.toHaveBeenCalled();
    expect(controller.getSnapshot().identity).toBeNull();
    await expect(controller.create()).rejects.toThrow();
  });
});
