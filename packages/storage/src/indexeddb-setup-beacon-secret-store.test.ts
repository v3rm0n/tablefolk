import {
  bytesToHex,
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  scalarFromBigInt,
} from "@p2pcards/crypto";
import {
  encodeRosterBody,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  parseRandomSecret,
  signEnvelope,
  snapshotSetupBeaconScope,
  type RandomSecret,
  type SetupBeaconScope,
} from "@p2pcards/protocol";
import { IDBFactory } from "fake-indexeddb";
import { afterEach, describe, expect, it, onTestFinished, vi } from "vitest";

import { GAMES_STORE, openP2pCardsDatabase } from "./database";
import {
  IndexedDbSetupBeaconSecretStore,
  SetupBeaconSecretStoreError,
} from "./index";
import { IndexedDbGameSecretStore } from "./indexeddb-game-secret-store";
import { IndexedDbSessionStore } from "./indexeddb-session-store";

const GAME_ID = parseGameId(new Uint8Array(16).fill(0x31));
const OTHER_GAME_ID = parseGameId(new Uint8Array(16).fill(0x32));
const IDENTITIES = Array.from({ length: 9 }, (_, index) =>
  parseIdentityPublicKey(deriveEd25519PublicKey(
    importEd25519SecretKey(new Uint8Array(32).fill(index + 1)),
  )),
);

afterEach(() => vi.restoreAllMocks());

describe("IndexedDB setup beacon secret store", () => {
  it("persists exactly one private field and reuses it after reopening", async () => {
    const { store, database, options } = await fixture();
    const requested = scope();
    const create = vi.fn(() => secretBytes());
    const first = await store.getOrCreateSetupBeaconSecret(requested, create);
    await store.close();

    const reopened = new IndexedDbSetupBeaconSecretStore(options);
    onTestFinished(() => reopened.close());
    expect(await reopened.loadSetupBeaconSecret(requested)).toEqual(first);
    expect(await reopened.getOrCreateSetupBeaconSecret(requested, create)).toEqual(first);
    expect(create).toHaveBeenCalledTimes(1);
    expect(await getGameRecord(database)).toEqual({
      game: bytesToHex(GAME_ID),
      setupBeaconSecret: storedSecret(requested),
    });
  });

  it("serializes two independent connections and invokes only one creator", async () => {
    const { store: left, options } = await fixture();
    const right = new IndexedDbSetupBeaconSecretStore(options);
    onTestFinished(() => right.close());
    const create = vi.fn(() => secretBytes(0x61));
    const competingCreate = vi.fn(() => secretBytes(0x62));
    const [first, second] = await Promise.all([
      left.getOrCreateSetupBeaconSecret(scope(), create),
      right.getOrCreateSetupBeaconSecret(scope(), competingCreate),
    ]);

    expect(first).toEqual(second);
    expect(first).not.toBe(second);
    expect(create.mock.calls.length + competingCreate.mock.calls.length).toBe(1);
    first.fill(0);
    expect(await left.loadSetupBeaconSecret(scope())).toEqual(second);
  });

  it("keeps different game IDs independent even when their bindings differ", async () => {
    const { store, database } = await fixture();
    const other = scope({ gameId: OTHER_GAME_ID, round: 7, sender: IDENTITIES[0]! });
    await store.getOrCreateSetupBeaconSecret(scope(), () => secretBytes(1));
    await store.getOrCreateSetupBeaconSecret(other, () => secretBytes(2));
    expect(await store.loadSetupBeaconSecret(scope())).toEqual(secretBytes(1));
    expect(await store.loadSetupBeaconSecret(other)).toEqual(secretBytes(2));
    expect((await getGameRecord(database, OTHER_GAME_ID))?.["setupBeaconSecret"]).toEqual(
      storedSecret(other, secretBytes(2)),
    );
  });

  it.each([
    ["round", { round: 1 }],
    ["local identity", { sender: IDENTITIES[0]! }],
    ["roster member", { roster: [IDENTITIES[0]!, IDENTITIES[1]!, IDENTITIES[3]!] }],
    ["roster length", { roster: IDENTITIES.slice(0, 4) }],
    ["roster order", { roster: [IDENTITIES[1]!, IDENTITIES[0]!, IDENTITIES[2]!] }],
  ] satisfies [string, Partial<SetupBeaconScope>][])(
    "rejects a changed %s for both reads and creation without calling RNG",
    async (_, changed) => {
      const { store, database } = await fixture();
      await store.getOrCreateSetupBeaconSecret(scope(), () => secretBytes());
      const before = await getGameRecord(database);
      const create = vi.fn(() => secretBytes(0xff));
      await expect(store.loadSetupBeaconSecret(scope(changed))).rejects.toThrow(
        "Stored setup beacon secret has a different scope",
      );
      await expect(store.getOrCreateSetupBeaconSecret(scope(changed), create)).rejects.toThrow(
        SetupBeaconSecretStoreError,
      );
      expect(create).not.toHaveBeenCalled();
      expect(await getGameRecord(database)).toEqual(before);
    },
  );

  it("validates scopes before opening a transaction and never invokes scope getters", async () => {
    const transactions = vi.fn();
    const { store, database } = await fixture(transactions);
    const getter = vi.fn(() => { throw new Error("Unexpected getter"); });
    const accessorScope = Object.defineProperty(scope(), "sender", { get: getter });
    const accessorRoster = [...scope().roster];
    Object.defineProperty(accessorRoster, "1", { get: getter });
    const shortGame = new Uint8Array(15);
    Object.defineProperty(shortGame, "length", { value: 16 });
    const invalid: unknown[] = [
      null, [], Object.create(scope()), { ...scope(), seat: 1 }, accessorScope,
      { ...scope(), roster: accessorRoster },
      ...[-1, -0, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1].map((round) => ({ ...scope(), round })),
      { ...scope(), gameId: shortGame },
      { ...scope(), sender: IDENTITIES[3] },
      { ...scope(), sender: new Uint8Array(31) },
      { ...scope(), roster: IDENTITIES.slice(0, 2) },
      { ...scope(), roster: IDENTITIES },
      { ...scope(), roster: [IDENTITIES[0], IDENTITIES[1], IDENTITIES[1]] },
      { ...scope(), roster: [IDENTITIES[0], IDENTITIES[1], new Uint8Array(32)] },
    ];
    const create = vi.fn(() => secretBytes());
    for (const candidate of invalid) {
      await expect(store.loadSetupBeaconSecret(candidate as SetupBeaconScope)).rejects.toThrow();
      await expect(store.getOrCreateSetupBeaconSecret(candidate as SetupBeaconScope, create)).rejects.toThrow();
    }
    expect(getter).not.toHaveBeenCalled();
    expect(create).not.toHaveBeenCalled();
    expect(transactions).not.toHaveBeenCalled();
    expect(await getGameRecord(database)).toBeUndefined();
  });

  it("snapshots public bytes, roster order, and round before any async database work", async () => {
    const { store, database } = await fixture();
    const input = { ...scope(), roster: [...scope().roster] };
    const original = snapshotSetupBeaconScope(input);
    const pending = store.getOrCreateSetupBeaconSecret(input, () => secretBytes());
    input.gameId.fill(0);
    input.sender.fill(0);
    input.round = 19;
    input.roster.reverse();
    input.roster[0]!.fill(0);
    await pending;
    expect((await getGameRecord(database))?.["setupBeaconSecret"]).toEqual(storedSecret(original));

    const loadInput = { ...scope(), roster: [...scope().roster] };
    const loading = store.loadSetupBeaconSecret(loadInput);
    loadInput.gameId.fill(0xff);
    loadInput.sender.fill(0xff);
    loadInput.roster.reverse();
    loadInput.roster[0]!.fill(0xff);
    loadInput.round = 20;
    expect(await loading).toEqual(secretBytes());

    const deletingId = parseGameId(GAME_ID);
    const deleting = store.deleteSetupBeaconSecret(deletingId);
    deletingId.fill(0);
    await deleting;
    expect(await getGameRecord(database)).toBeUndefined();
  });

  it("detaches creator, selected, record, and returned bytes across a pending commit", async () => {
    const candidate = secretBytes();
    let committed = false;
    const { store } = await fixture((transaction) => {
      const games = transaction.objectStore(GAMES_STORE);
      const put = games.put.bind(games);
      vi.spyOn(games, "put").mockImplementation((value, key) => {
        const request = put(value, key);
        (value as { setupBeaconSecret: { secret: Uint8Array } }).setupBeaconSecret.secret.fill(0xaa);
        request.addEventListener("success", () => candidate.fill(0xbb));
        return request;
      });
      transaction.addEventListener("complete", () => { committed = true; });
    });
    const first = await store.getOrCreateSetupBeaconSecret(scope(), () => {
      queueMicrotask(() => candidate.fill(0xcc));
      return candidate;
    });
    expect(committed).toBe(true);
    expect(candidate).toEqual(secretBytes(0xbb));
    expect(first).toEqual(secretBytes());
    expect(first).not.toBe(candidate);
    first.fill(0xdd);

    const loaded = await store.loadSetupBeaconSecret(scope());
    expect(loaded).toEqual(secretBytes());
    loaded!.fill(0xee);
    const reused = await store.getOrCreateSetupBeaconSecret(scope(), () => { throw new Error("No RNG"); });
    expect(reused).toEqual(secretBytes());
    reused.fill(0xff);
    expect(await store.loadSetupBeaconSecret(scope())).toEqual(secretBytes());
  });

  it("accepts all-zero and full-ff bytes without imposing scalar restrictions", async () => {
    const { store } = await fixture();
    for (const [fill, gameId] of [[0, GAME_ID], [0xff, OTHER_GAME_ID]] as const) {
      const requested = scope({ gameId, round: Number.MAX_SAFE_INTEGER, roster: IDENTITIES.slice(0, 8) });
      expect(await store.getOrCreateSetupBeaconSecret(requested, () => secretBytes(fill))).toEqual(secretBytes(fill));
      expect(await store.loadSetupBeaconSecret(requested)).toEqual(secretBytes(fill));
    }
  });

  it("rejects every malformed present field, including undefined, without replacement", async () => {
    const { store, database } = await fixture();
    const valid = storedSecret(scope());
    const invalid: unknown[] = [
      undefined, null, [], 1, new Uint8Array(32), {},
      ...Object.keys(valid).map((missing) => Object.fromEntries(
        Object.entries(valid).filter(([key]) => key !== missing),
      )),
      { ...valid, version: 2 }, { ...valid, version: "1" },
      ...["seat", "commitment", "seed", "phase"].map((extra) => ({ ...valid, [extra]: 0 })),
      ...[-1, -0, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1].map((round) => ({ ...valid, round })),
      { ...valid, sender: new Uint8Array(31) },
      { ...valid, sender: IDENTITIES[3] },
      { ...valid, roster: null },
      { ...valid, roster: IDENTITIES.slice(0, 2) },
      { ...valid, roster: IDENTITIES },
      { ...valid, roster: [IDENTITIES[0], IDENTITIES[1], IDENTITIES[1]] },
      { ...valid, roster: [IDENTITIES[0], IDENTITIES[1], new Uint8Array(32)] },
      { ...valid, roster: [IDENTITIES[0], IDENTITIES[1], new Uint8Array(31)] },
      { ...valid, roster: [IDENTITIES[0], IDENTITIES[1], ,] },
      ...[undefined, null, [], "secret", new Uint8Array(31), new Uint8Array(33), new Uint16Array(32)]
        .map((secret) => ({ ...valid, secret })),
    ];
    const create = vi.fn(() => secretBytes());
    for (const setupBeaconSecret of invalid) {
      await putGameRecord(database, { game: bytesToHex(GAME_ID), setupBeaconSecret, other: "keep" });
      const before = await getGameRecord(database);
      await expect(store.loadSetupBeaconSecret(scope())).rejects.toThrow(SetupBeaconSecretStoreError);
      await expect(store.getOrCreateSetupBeaconSecret(scope(), create)).rejects.toThrow(SetupBeaconSecretStoreError);
      expect(await getGameRecord(database)).toEqual(before);
    }
    expect(create).not.toHaveBeenCalled();
  });

  it("rejects accessor, hidden, symbol, and non-plain stored shapes without reading getters", async () => {
    const getter = vi.fn(() => { throw new Error("Unexpected stored getter"); });
    let stored: unknown;
    const { store, database } = await fixture((transaction) => {
      const games = transaction.objectStore(GAMES_STORE);
      const get = games.get.bind(games);
      vi.spyOn(games, "get").mockImplementation((key) => {
        const request = get(key);
        request.addEventListener("success", () => {
          Object.defineProperty(request, "result", { value: { game: bytesToHex(GAME_ID), setupBeaconSecret: stored } });
        });
        return request;
      });
    });
    const invalid = [
      Object.defineProperty(storedSecret(scope()), "secret", { get: getter }),
      Object.defineProperty(storedSecret(scope()), "round", { enumerable: false }),
      { ...storedSecret(scope()), [Symbol("extra")]: true },
      Object.assign(Object.create({ inherited: true }) as object, storedSecret(scope())),
    ];
    const create = vi.fn(() => secretBytes());
    for (stored of invalid) {
      await expect(store.loadSetupBeaconSecret(scope())).rejects.toThrow(SetupBeaconSecretStoreError);
      await expect(store.getOrCreateSetupBeaconSecret(scope(), create)).rejects.toThrow(SetupBeaconSecretStoreError);
    }
    expect(getter).not.toHaveBeenCalled();
    expect(create).not.toHaveBeenCalled();
    expect(await getGameRecord(database)).toBeUndefined();
  });

  it("rejects invalid creator bytes without modifying an existing unrelated record", async () => {
    const { store, database } = await fixture();
    await expect(store.getOrCreateSetupBeaconSecret(scope(), () => new Uint8Array(31) as RandomSecret)).rejects.toThrow(
      SetupBeaconSecretStoreError,
    );
    expect(await getGameRecord(database)).toBeUndefined();
    const before = { game: bytesToHex(GAME_ID), other: { retained: true } };
    await putGameRecord(database, before);
    const spoofed = new Uint8Array(31);
    Object.defineProperties(spoofed, {
      length: { value: 32 }, byteLength: { value: 32 }, slice: { value: () => secretBytes() },
    });
    const throwingConstructor = new Uint8Array(32);
    Object.defineProperty(throwingConstructor, "constructor", { get() { throw new Error("Getter failure"); } });
    const invalid = [
      undefined, null, [], "secret", 1n, new Uint8Array(31), new Uint8Array(33),
      new Uint16Array(32), new DataView(new ArrayBuffer(32)), spoofed, throwingConstructor,
    ];
    for (const candidate of invalid) {
      await expect(store.getOrCreateSetupBeaconSecret(scope(), () => candidate as RandomSecret)).rejects.toThrow(
        SetupBeaconSecretStoreError,
      );
      expect(await getGameRecord(database)).toEqual(before);
    }
    await expect(store.getOrCreateSetupBeaconSecret(scope(), null as unknown as () => RandomSecret)).rejects.toThrow(TypeError);
    expect(await store.loadSetupBeaconSecret(scope())).toBeNull();
  });

  it("preserves callback failures including throw undefined and leaves no unused game row", async () => {
    const { store, database } = await fixture();
    for (const failure of [new Error("Creator failed"), undefined, null]) {
      await expect(store.getOrCreateSetupBeaconSecret(scope(), () => { throw failure; })).rejects.toBe(failure);
      expect(await getGameRecord(database)).toBeUndefined();
    }
    expect(await store.getOrCreateSetupBeaconSecret(scope(), () => secretBytes())).toEqual(secretBytes());
  });

  it("rejects accidental async creators and observes their rejected promises", async () => {
    const { store, database } = await fixture();
    for (const create of [
      async () => secretBytes(),
      async () => { throw new Error("Async creator failed"); },
      () => Promise.reject(undefined),
    ]) {
      await expect(store.getOrCreateSetupBeaconSecret(scope(), create as unknown as () => RandomSecret)).rejects.toThrow(
        SetupBeaconSecretStoreError,
      );
      expect(await getGameRecord(database)).toBeUndefined();
    }
    expect(await store.loadSetupBeaconSecret(scope())).toBeNull();
  });

  it("uses intrinsic byte sizes and never reads hostile size, buffer, iterator, or slice getters", async () => {
    const { store } = await fixture();
    const requested = scope();
    const candidate = secretBytes();
    const getter = vi.fn(() => { throw new Error("Custom byte access"); });
    for (const bytes of [requested.gameId, requested.sender, ...requested.roster, candidate]) {
      for (const key of ["length", "byteLength", "byteOffset", "buffer", "slice", Symbol.iterator]) {
        Object.defineProperty(bytes, key, { get: getter });
      }
    }
    expect(await store.getOrCreateSetupBeaconSecret(requested, () => candidate)).toEqual(secretBytes());
    expect(await store.loadSetupBeaconSecret(requested)).toEqual(secretBytes());
    expect(getter).not.toHaveBeenCalled();
  });

  it("loads missing records and missing fields with readonly transactions and creates no row", async () => {
    const modes: IDBTransactionMode[] = [];
    const { store, database } = await fixture((transaction) => modes.push(transaction.mode));
    expect(await store.loadSetupBeaconSecret(scope())).toBeNull();
    expect(await getGameRecord(database)).toBeUndefined();
    const before = { game: bytesToHex(GAME_ID), other: "keep" };
    await putGameRecord(database, before);
    expect(await store.loadSetupBeaconSecret(scope())).toBeNull();
    expect(await getGameRecord(database)).toEqual(before);
    expect(modes).toEqual(["readonly", "readonly"]);
  });

  it("gates creation, reuse, load, and deletion on actual transaction completion", async () => {
    let settled = false;
    const completionStates: boolean[] = [];
    const modes: IDBTransactionMode[] = [];
    const { store } = await fixture((transaction) => {
      modes.push(transaction.mode);
      transaction.addEventListener("complete", () => completionStates.push(settled));
    });
    const operations = [
      () => store.getOrCreateSetupBeaconSecret(scope(), () => secretBytes()),
      () => store.getOrCreateSetupBeaconSecret(scope(), () => { throw new Error("No RNG"); }),
      () => store.loadSetupBeaconSecret(scope()),
      () => store.deleteSetupBeaconSecret(GAME_ID),
    ];
    for (const operation of operations) {
      settled = false;
      const before = completionStates.length;
      await operation().then(() => { settled = true; });
      expect(completionStates.slice(before)).toEqual([false]);
    }
    expect(modes).toEqual(["readwrite", "readwrite", "readonly", "readwrite"]);
  });

  it("rejects creation and deletion when successful write requests are subsequently aborted", async () => {
    const { store, database } = await fixture((transaction) => {
      const games = transaction.objectStore(GAMES_STORE);
      const put = games.put.bind(games);
      vi.spyOn(games, "put").mockImplementation((value, key) => {
        const request = put(value, key);
        request.addEventListener("success", () => transaction.abort());
        return request;
      });
      const remove = games.delete.bind(games);
      vi.spyOn(games, "delete").mockImplementation((key) => {
        const request = remove(key);
        request.addEventListener("success", () => transaction.abort());
        return request;
      });
    });
    const create = vi.fn(() => secretBytes());
    await expect(store.getOrCreateSetupBeaconSecret(scope(), create)).rejects.toThrow(SetupBeaconSecretStoreError);
    expect(create).toHaveBeenCalledTimes(1);
    expect(await getGameRecord(database)).toBeUndefined();

    const before = { game: bytesToHex(GAME_ID), setupBeaconSecret: storedSecret(scope()) };
    await putGameRecord(database, before);
    await expect(store.deleteSetupBeaconSecret(GAME_ID)).rejects.toThrow(SetupBeaconSecretStoreError);
    expect(await getGameRecord(database)).toEqual(before);
  });

  it("rejects aborted loads and reuse even after a successful read selected valid bytes", async () => {
    const { store, database } = await fixture((transaction) => {
      const games = transaction.objectStore(GAMES_STORE);
      const get = games.get.bind(games);
      vi.spyOn(games, "get").mockImplementation((key) => {
        const request = get(key);
        request.addEventListener("success", () => queueMicrotask(() => transaction.abort()));
        return request;
      });
    });
    const before = { game: bytesToHex(GAME_ID), setupBeaconSecret: storedSecret(scope()) };
    await putGameRecord(database, before);
    const create = vi.fn(() => secretBytes());
    await expect(store.loadSetupBeaconSecret(scope())).rejects.toThrow(SetupBeaconSecretStoreError);
    await expect(store.getOrCreateSetupBeaconSecret(scope(), create)).rejects.toThrow(SetupBeaconSecretStoreError);
    expect(create).not.toHaveBeenCalled();
    expect(await getGameRecord(database)).toEqual(before);
  });

  it("retains transaction failure state for request errors and an already-aborted callback", async () => {
    let active: IDBTransaction;
    const { store, database } = await fixture((transaction) => { active = transaction; });
    await expect(store.getOrCreateSetupBeaconSecret(scope(), () => {
      const games = active.objectStore(GAMES_STORE);
      games.add({ game: "duplicate" });
      games.add({ game: "duplicate" });
      return secretBytes();
    })).rejects.toThrow();
    expect(await getGameRecord(database)).toBeUndefined();

    await expect(store.getOrCreateSetupBeaconSecret(scope(), () => {
      active.abort();
      throw undefined;
    })).rejects.toBeUndefined();
    expect(await getGameRecord(database)).toBeUndefined();
  });

  it("does not return a secret when a handled request error is followed by transaction completion", async () => {
    let active!: IDBTransaction;
    const completed = vi.fn();
    const aborted = vi.fn();
    const { store, database } = await fixture((transaction) => {
      active = transaction;
      transaction.addEventListener("complete", completed);
      transaction.addEventListener("abort", aborted);
    });
    const create = vi.fn(() => {
      const games = active.objectStore(GAMES_STORE);
      games.add({ game: "handled-request-error" });
      const duplicate = games.add({ game: "handled-request-error" });
      duplicate.addEventListener("error", (event) => event.preventDefault());
      return secretBytes();
    });
    await expect(store.getOrCreateSetupBeaconSecret(scope(), create)).rejects.toThrow(SetupBeaconSecretStoreError);
    expect(completed).toHaveBeenCalledOnce();
    expect(aborted).not.toHaveBeenCalled();
    expect(create).toHaveBeenCalledOnce();
    // Completion may still have committed the private value, but the failed call must not expose a commitment.
    expect((await getGameRecord(database))!["setupBeaconSecret"]).toEqual(storedSecret(scope()));
    const noCreate = vi.fn(() => { throw new Error("A committed secret must not be replaced"); });
    await expect(store.getOrCreateSetupBeaconSecret(scope(), noCreate)).resolves.toEqual(secretBytes());
    expect(noCreate).not.toHaveBeenCalled();
  });

  it("deletes only its owned field, removes empty rows, and leaves other games intact", async () => {
    const { store, database } = await fixture();
    await store.deleteSetupBeaconSecret(GAME_ID);
    expect(await getGameRecord(database)).toBeUndefined();
    const other = scope({ gameId: OTHER_GAME_ID });
    await store.getOrCreateSetupBeaconSecret(other, () => secretBytes(2));
    await store.getOrCreateSetupBeaconSecret(scope(), () => secretBytes());
    await store.deleteSetupBeaconSecret(GAME_ID);
    expect(await getGameRecord(database)).toBeUndefined();
    expect(await store.loadSetupBeaconSecret(other)).toEqual(secretBytes(2));

    const unrelated = { game: bytesToHex(GAME_ID), other: { retained: true } };
    await putGameRecord(database, { ...unrelated, setupBeaconSecret: undefined });
    await store.deleteSetupBeaconSecret(GAME_ID);
    expect(await getGameRecord(database)).toEqual(unrelated);
    await store.deleteSetupBeaconSecret(GAME_ID);
    expect(await getGameRecord(database)).toEqual(unrelated);
    await putGameRecord(database, { game: bytesToHex(GAME_ID) });
    await store.deleteSetupBeaconSecret(GAME_ID);
    expect(await getGameRecord(database)).toBeUndefined();
  });

  it("coexists with game secrets and accepted lobby rosters without altering their transcript", async () => {
    const { store, database, options } = await fixture();
    const gameSecrets = new IndexedDbGameSecretStore(options);
    const sessions = new IndexedDbSessionStore(options);
    onTestFinished(() => Promise.all([gameSecrets.close(), sessions.close()]).then(() => {}));
    await putGameRecord(database, { game: bytesToHex(GAME_ID), other: "keep" });
    const roster = signEnvelope({
      v: 1,
      game: GAME_ID,
      from: IDENTITIES[0]!,
      seq: 0,
      prev: parseHash256(new Uint8Array(32)),
      round: 0,
      phase: "lobby",
      type: "ROSTER",
      body: encodeRosterBody({
        gameId: GAME_ID,
        rulesHash: parseHash256(new Uint8Array(32).fill(1)),
        iceConfigHash: parseHash256(new Uint8Array(32).fill(2)),
        seats: scope().roster,
      }),
    }, importEd25519SecretKey(new Uint8Array(32).fill(1)));
    await Promise.all([
      gameSecrets.getOrCreateGameSecret(GAME_ID, () => scalarFromBigInt(17n)),
      sessions.persistAcceptedRoster(IDENTITIES[0]!, roster),
      store.getOrCreateSetupBeaconSecret(scope(), () => secretBytes()),
    ]);
    const before = (await getGameRecord(database))!;
    const transcript = await sessions.loadTranscript(GAME_ID);
    expect(before["setupBeaconSecret"]).toEqual(storedSecret(scope()));
    delete before["setupBeaconSecret"];
    await store.deleteSetupBeaconSecret(GAME_ID);
    expect(await getGameRecord(database)).toEqual(before);
    expect(await gameSecrets.loadGameSecret(GAME_ID)).toBe(17n);
    expect((await sessions.loadLobbyRoster(GAME_ID, IDENTITIES[0]!))?.artifact.hash).toEqual(roster.hash);
    expect(await sessions.loadTranscript(GAME_ID)).toEqual(transcript);
    expect(await store.loadSetupBeaconSecret(scope())).toBeNull();
  });
});

function scope(overrides: Partial<SetupBeaconScope> = {}): SetupBeaconScope {
  return {
    gameId: parseGameId(GAME_ID),
    round: 0,
    roster: IDENTITIES.slice(0, 3).map(parseIdentityPublicKey),
    sender: parseIdentityPublicKey(IDENTITIES[1]!),
    ...overrides,
  };
}

function secretBytes(fill = 0x5a): RandomSecret {
  return parseRandomSecret(new Uint8Array(32).fill(fill));
}

function storedSecret(requested: SetupBeaconScope, secret = secretBytes()) {
  return { version: 1, round: requested.round, sender: requested.sender, roster: requested.roster, secret };
}

async function fixture(observe?: (transaction: IDBTransaction) => void) {
  const options = { factory: new IDBFactory(), databaseName: "setup-beacon-secret" };
  const database = await openP2pCardsDatabase(options);
  onTestFinished(() => database.close());
  if (observe !== undefined) {
    const open = options.factory.open.bind(options.factory);
    vi.spyOn(options.factory, "open").mockImplementation((...args) => {
      const request = open(...args);
      request.addEventListener("success", () => {
        const connection = request.result;
        const transaction = connection.transaction.bind(connection);
        vi.spyOn(connection, "transaction").mockImplementation((...transactionArgs) => {
          const result = transaction(...transactionArgs);
          observe(result);
          return result;
        });
      });
      return request;
    });
  }
  const store = new IndexedDbSetupBeaconSecretStore(options);
  onTestFinished(() => store.close());
  return { store, database, options };
}

function putGameRecord(database: IDBDatabase, value: object): Promise<void> {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(GAMES_STORE, "readwrite");
    transaction.objectStore(GAMES_STORE).put(value);
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error);
  });
}

function getGameRecord(database: IDBDatabase, gameId = GAME_ID): Promise<Record<string, unknown> | undefined> {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(GAMES_STORE, "readonly");
    const request = transaction.objectStore(GAMES_STORE).get(bytesToHex(gameId));
    transaction.oncomplete = () => resolve(request.result as Record<string, unknown> | undefined);
    transaction.onabort = () => reject(transaction.error);
  });
}
