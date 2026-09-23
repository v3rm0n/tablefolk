import { bytesToHex, encodeRistrettoScalar } from "@p2pcards/crypto";
import { PersistentSetupReceiver, recoverSetup } from "@p2pcards/engine";
import { PersistentSaskuRoundReceiver } from "@p2pcards/game-sasku";
import { parseIdentityPublicKey } from "@p2pcards/protocol";
import {
  MAX_SASKU_HAND_ACTIONS, SASKU_DECK_SPEC, SaskuHandController, parseSaskuCard, type SaskuCardId,
} from "@p2pcards/rules-sasku";
import { PersistentSessionReceiver, SessionChainRegistry, recoverSessionChains } from "@p2pcards/session";
import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it, vi } from "vitest";

import { roundRevealFixture } from "../../engine/src/round-reveal.test-fixture";
import {
  AUTHORED_HEADS_STORE, GAMES_STORE, IDENTITY_STORE, TRANSCRIPTS_STORE,
  openP2pCardsDatabase, type IndexedDbStoreOptions,
} from "./database";
import { GameSecretStoreError, IndexedDbGameSecretStore } from "./indexeddb-game-secret-store";
import { IndexedDbSessionStore } from "./indexeddb-session-store";

const LOCAL_SEAT = 2;

describe("private Sasku hand recovery with IndexedDB", () => {
  it("recovers the original and remaining private cards after durable play using only the saved key and transcript", async () => {
    const round = await durableRound();
    const { fixture: f, game, store, secrets, identity, key } = round;
    try {
      await finishDeals(round);
      const dealt = Object.fromEntries(f.cards.flatMap((card, pos) =>
        game.ownerAt(pos) === LOCAL_SEAT ? [[pos, parseSaskuCard(card).id]] : []));
      expect(Object.keys(dealt).map(Number)).toEqual([0, 1, 2, 3, 16, 17, 18, 19, 20]);
      const beforeReads = await databaseContents(round.options);
      const snapshot = game.snapshot;
      const initial = game.readPrivateHand(identity, key)!;
      expect(initial).toEqual({ dealt, remaining: dealt });
      expect(Object.keys(initial.dealt)).toHaveLength(9);
      for (const value of [initial, initial.dealt, initial.remaining]) expect(Object.isFrozen(value)).toBe(true);
      expect(Reflect.deleteProperty(initial.remaining, "0")).toBe(false);
      expect(game.readPrivateHand(identity, key)).toEqual(initial);
      expect(game.snapshot).toBe(snapshot);
      expectNoHiddenCards(round, game);
      expect(await databaseContents(round.options)).toEqual(beforeReads);
      expect(await secrets.loadGameSecret(f.gameId)).toBe(key);

      const hands: [SaskuCardId[], SaskuCardId[], SaskuCardId[], SaskuCardId[]] = [[], [], [], []];
      f.cards.forEach((card, pos) => hands[game.ownerAt(pos)].push(parseSaskuCard(card).id));
      const reference = new SaskuHandController({ dealer: 3, hands });
      const bid = f.action(0, [], 0, "diamonds");
      await expect(game.receive(bid)).resolves.toMatchObject({ status: "accepted", persistenceStatus: "stored" });
      round.messages.push(bid);
      reference.apply({ type: "diamonds", seat: 0 });
      expect(game.readPrivateHand(identity, key)).toEqual(initial);

      const remaining = { ...dealt };
      let localPlays = 0;
      for (let play = 0; play < 8; play += 1) {
        const seat = reference.snapshot.turn!;
        const legal = reference.legalCardsForTurn();
        const privateBefore = game.readPrivateHand(identity, key)!;
        const pos = seat === LOCAL_SEAT
          ? Number(Object.entries(privateBefore.remaining).find(([, card]) => legal.includes(card))![0])
          : f.cards.indexOf(legal[0]!);
        const card = parseSaskuCard(f.cards[pos]).id;
        expect(game.ownerAt(pos)).toBe(seat);
        const action = f.action(seat, [pos], game.snapshot.ledger.actionIndex);
        const before = game.snapshot;
        const receiving = game.receive(action);
        // A real IndexedDB receipt is still pending; no delayed-write mock is needed here.
        expect(game.readPrivateHand(identity, key)).toEqual(privateBefore);
        expect(game.snapshot).toBe(before);
        await expect(receiving).resolves.toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "stored" });
        round.messages.push(action);
        reference.apply({ type: "play", seat, card });
        if (seat === LOCAL_SEAT) { delete remaining[pos]; localPlays += 1; }
        expect(game.readPrivateHand(identity, key)).toEqual({ dealt, remaining });
        expectNoHiddenCards(round, game);
      }
      expect(localPlays).toBe(2);
      expect(Object.keys(remaining)).toHaveLength(7);
      expect(initial).toEqual({ dealt, remaining: dealt });
      const privateBeforeRestart = game.readPrivateHand(identity, key);
      const publicBeforeRestart = game.snapshot;
      const stored = await databaseContents(round.options);
      expect(stored).toEqual(expectedContents(round));
      expect(round.messages).toHaveLength(45);
      game.close();
      expect(() => game.readPrivateHand(identity, key)).toThrow(expect.objectContaining({ code: "closed" }));
      await Promise.all([store.close(), secrets.close()]);

      const reopenedStore = new IndexedDbSessionStore(round.options);
      const reopenedSecrets = new IndexedDbGameSecretStore(round.options);
      const noCreate = vi.spyOn(reopenedSecrets, "getOrCreateGameSecret")
        .mockImplementation(() => { throw new Error("Recovery must not generate a game secret"); });
      let replay: PersistentSaskuRoundReceiver | undefined;
      try {
        const loaded = await reopenedSecrets.loadGameSecret(f.gameId);
        expect(loaded).toBe(key);
        if (loaded === null) throw new Error("Saved local key is missing");
        replay = await replayRound(round, reopenedStore);
        expect(replay.snapshot).toEqual(publicBeforeRestart);
        const before = replay.snapshot;
        const recovered = replay.readPrivateHand(identity, loaded)!;
        expect(recovered).toEqual(privateBeforeRestart);
        for (const value of [recovered, recovered.dealt, recovered.remaining]) expect(Object.isFrozen(value)).toBe(true);
        expect(replay.readPrivateHand(identity, loaded)).toEqual(recovered);
        expect(replay.snapshot).toBe(before);
        expectNoHiddenCards(round, replay);
        expect(await reopenedSecrets.loadGameSecret(f.gameId)).toBe(loaded);
        expect(await databaseContents(round.options)).toEqual(stored);
        expect(noCreate).not.toHaveBeenCalled();
        replay.close();
        expect(() => replay!.readPrivateHand(identity, loaded)).toThrow(expect.objectContaining({ code: "closed" }));
      } finally {
        replay?.close();
        noCreate.mockRestore();
        await Promise.all([reopenedStore.close(), reopenedSecrets.close()]);
      }
    } finally {
      game.close();
      await Promise.all([store.close(), secrets.close()]);
    }
  }, 15_000);

  it("does not generate or repair a missing, corrupt, or mismatched key on restart", async () => {
    const round = await durableRound();
    const { fixture: f, game, store, secrets, identity, key } = round;
    try {
      await finishDeals(round);
      const originalHand = game.readPrivateHand(identity, key);
      expect(originalHand).not.toBeNull();
      const stored = await databaseContents(round.options);
      expect(stored).toEqual(expectedContents(round));
      game.close();
      await Promise.all([store.close(), secrets.close()]);

      const wrongKey = f.secrets[0]!;
      for (const mode of ["missing", "corrupt", "wrong"] as const) {
        const record = mode === "missing" ? { game: bytesToHex(f.gameId) } : {
          game: bytesToHex(f.gameId),
          gameSecret: mode === "corrupt" ? new Uint8Array(32).fill(0xff) : encodeRistrettoScalar(wrongKey),
        };
        await replaceGameRecord(round.options, record);
        const before = await databaseContents(round.options);
        expect(before).toEqual({ ...stored, [GAMES_STORE]: [record] });
        const reopenedStore = new IndexedDbSessionStore(round.options);
        const reopenedSecrets = new IndexedDbGameSecretStore(round.options);
        const noCreate = vi.spyOn(reopenedSecrets, "getOrCreateGameSecret")
          .mockImplementation(() => { throw new Error("Recovery must not generate a game secret"); });
        let replay: PersistentSaskuRoundReceiver | undefined;
        try {
          if (mode === "corrupt") {
            await expect(reopenedSecrets.loadGameSecret(f.gameId)).rejects.toThrow(GameSecretStoreError);
          } else {
            const loaded = await reopenedSecrets.loadGameSecret(f.gameId);
            if (mode === "missing") {
              expect(loaded).toBeNull();
            } else {
              expect(loaded).toBe(wrongKey);
              if (loaded === null) throw new Error("Expected a canonical but mismatched key");
              replay = await replayRound(round, reopenedStore);
              const snapshot = replay.snapshot;
              expect(() => replay!.readPrivateHand(identity, loaded)).toThrow(expect.objectContaining({ code: "invalid_local_key" }));
              expect(() => replay!.readPrivateHand(f.identities[4]!.publicKey, loaded))
                .toThrow(expect.objectContaining({ code: "unknown_sender" }));
              expect(replay.failure).toBeNull();
              // The transcript is recoverable with the original key, but reads must not repair storage.
              expect(replay.readPrivateHand(identity, key)).toEqual(originalHand);
              expect(() => replay!.readPrivateHand(identity, loaded)).toThrow(expect.objectContaining({ code: "invalid_local_key" }));
              expect(replay.snapshot).toBe(snapshot);
              expectNoHiddenCards(round, replay);
              expect(await reopenedSecrets.loadGameSecret(f.gameId)).toBe(wrongKey);
            }
          }
          expect(noCreate).not.toHaveBeenCalled();
          expect(await databaseContents(round.options)).toEqual(before);
        } finally {
          replay?.close();
          noCreate.mockRestore();
          await Promise.all([reopenedStore.close(), reopenedSecrets.close()]);
        }
      }
    } finally {
      game.close();
      await Promise.all([store.close(), secrets.close()]);
    }
  });

  it("rejects private reads after a terminal durable-receipt failure without deleting the saved key", async () => {
    const round = await durableRound();
    const { fixture: f, game, store, secrets, identity, key } = round;
    const persist = store.persistAcceptedEnvelope.bind(store);
    const fault = vi.spyOn(store, "persistAcceptedEnvelope").mockImplementationOnce(async (received) => {
      const receipt = await persist(received);
      received.hash.fill(0xff);
      return receipt;
    });
    try {
      expect(game.readPrivateHand(identity, key)).toBeNull();
      const before = game.snapshot;
      const message = f.deal(0, 3);
      await expect(game.receive(message)).rejects.toMatchObject({ code: "invalid_receipt" });
      round.messages.push(message);
      expect(game.failure?.code).toBe("invalid_receipt");
      const stored = await databaseContents(round.options);
      expect(stored).toEqual(expectedContents(round));
      expect(() => game.readPrivateHand(identity, key)).toThrow(game.failure!);
      expect(game.snapshot).toBe(before);
      expectNoHiddenCards(round, game);
      expect(await secrets.loadGameSecret(f.gameId)).toBe(key);
      expect(await databaseContents(round.options)).toEqual(stored);
      expect(fault).toHaveBeenCalledTimes(1);
    } finally {
      fault.mockRestore();
      game.close();
      await Promise.all([store.close(), secrets.close()]);
    }
  });
});

async function durableRound() {
  const fixture = roundRevealFixture({
    seats: 4, deckSpec: SASKU_DECK_SPEC, maxActions: MAX_SASKU_HAND_ACTIONS,
    schedule: [2, 0, 3, 1, 2, 3, 1, 0].map((to, index) => ({ to, count: index < 4 ? 4 : 5 })),
  });
  const options = { factory: new IDBFactory(), databaseName: "private-hand-recovery" };
  const store = new IndexedDbSessionStore(options);
  const secrets = new IndexedDbGameSecretStore(options);
  const chains = new SessionChainRegistry(fixture.gameId, fixture.roster);
  const receiver = new PersistentSessionReceiver(chains, store);
  const identity = parseIdentityPublicKey(fixture.roster[LOCAL_SEAT]!.slice());
  const setupReceiver = new PersistentSetupReceiver({ round: 0, self: identity, session: chains, sessionReceiver: receiver });
  const create = vi.fn(() => fixture.secrets[LOCAL_SEAT]!);
  const getOrCreate = vi.spyOn(secrets, "getOrCreateGameSecret");
  try {
    // Only initial setup creates a key, durably before accepting its signed KEY_SHARE.
    const key = await secrets.getOrCreateGameSecret(fixture.gameId, create);
    expect(await secrets.loadGameSecret(fixture.gameId)).toBe(key);
    for (const message of fixture.setupEnvelopes) {
      await expect(setupReceiver.receive(message)).resolves.toMatchObject({
        status: "accepted", chainResult: { status: "accepted", persistenceStatus: "stored" },
      });
    }
    expect(create).toHaveBeenCalledTimes(1);
    expect(getOrCreate).toHaveBeenCalledTimes(1);
    const setup = setupReceiver.getCompletedSetup();
    const game = new PersistentSaskuRoundReceiver({
      setup, round: fixture.round, deck: fixture.deck, schedule: fixture.options.schedule, dealer: 3,
      session: chains, sessionReceiver: receiver,
    });
    return { fixture, options, store, secrets, chains, game, identity, key, messages: [...fixture.setupEnvelopes] };
  } catch (cause) {
    await Promise.all([store.close(), secrets.close()]);
    throw cause;
  } finally { getOrCreate.mockRestore(); }
}

async function finishDeals(round: Awaited<ReturnType<typeof durableRound>>) {
  const { fixture: f, game, identity, key } = round;
  for (let step = 0; step < f.plans.length; step += 1) {
    for (const actor of [3, 1, 0, 2]) {
      if (actor === f.plans[step]!.to) continue;
      // Even once this seat has all nine cards, the rest of the initial deal must commit.
      expect(game.readPrivateHand(identity, key)).toBeNull();
      const message = f.deal(step, actor);
      const receiving = game.receive(message);
      expect(game.readPrivateHand(identity, key)).toBeNull();
      await expect(receiving).resolves.toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "stored" });
      round.messages.push(message);
      expect(game.snapshot.ledger.revealed).toEqual({});
    }
  }
  expect(game.snapshot.ledger.deal).toBeNull();
}

async function replayRound(round: Awaited<ReturnType<typeof durableRound>>, store: IndexedDbSessionStore) {
  const f = round.fixture;
  const records = await store.loadTranscript(f.gameId);
  expect(records.map(({ artifact }) => artifact.canonicalBytes)).toEqual(round.messages.map(({ canonicalBytes }) => canonicalBytes));
  const transcript = records.map(({ artifact }) => artifact).reverse();
  const chains = recoverSessionChains(f.gameId, f.roster, transcript).registry;
  const setup = recoverSetup(f.gameId, 0, f.roster, transcript).coordinator;
  const heads = chains.heads();
  expect(heads).toEqual(round.chains.heads());
  const persist = vi.spyOn(store, "persistAcceptedEnvelope").mockImplementation(() => {
    throw new Error("Recovery must not persist accepted envelopes");
  });
  let game: PersistentSaskuRoundReceiver | undefined;
  try {
    game = PersistentSaskuRoundReceiver.recover({
      setup, round: f.round, deck: f.deck, schedule: f.options.schedule, dealer: 3,
      session: chains, sessionReceiver: new PersistentSessionReceiver(chains, store),
    });
    expect(persist).not.toHaveBeenCalled();
    expect(chains.heads()).toEqual(heads);
    return game;
  } catch (cause) {
    game?.close();
    throw cause;
  } finally { persist.mockRestore(); }
}

function expectNoHiddenCards(round: Awaited<ReturnType<typeof durableRound>>, game: PersistentSaskuRoundReceiver) {
  const snapshot = JSON.stringify(game.snapshot);
  round.fixture.cards.forEach((card, pos) => {
    if (!Object.hasOwn(game.snapshot.ledger.revealed, pos)) expect(snapshot).not.toContain(JSON.stringify(card));
  });
}

function expectedContents(round: Awaited<ReturnType<typeof durableRound>>) {
  const game = bytesToHex(round.fixture.gameId);
  return {
    [GAMES_STORE]: [{ game, gameSecret: encodeRistrettoScalar(round.key) }],
    [TRANSCRIPTS_STORE]: round.messages.map(({ envelope, canonicalBytes }, index) => ({
      arrival: index + 1, game, sender: bytesToHex(envelope.from), seq: envelope.seq, bytes: canonicalBytes, authored: false,
    })),
    [IDENTITY_STORE]: [],
    [AUTHORED_HEADS_STORE]: [],
  };
}

async function databaseContents(options: IndexedDbStoreOptions): Promise<Record<string, unknown[]>> {
  const database = await openP2pCardsDatabase(options);
  try {
    return await new Promise((resolve, reject) => {
      const names = Array.from(database.objectStoreNames);
      const transaction = database.transaction(names, "readonly");
      const requests = names.map((name) => [name, transaction.objectStore(name).getAll()] as const);
      transaction.oncomplete = () => resolve(Object.fromEntries(requests.map(([name, request]) => [name, request.result])));
      transaction.onabort = () => reject(transaction.error);
      transaction.onerror = () => reject(transaction.error);
    });
  } finally { database.close(); }
}

async function replaceGameRecord(options: IndexedDbStoreOptions, record: object) {
  const database = await openP2pCardsDatabase(options);
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(GAMES_STORE, "readwrite");
      transaction.objectStore(GAMES_STORE).put(record);
      transaction.oncomplete = () => resolve();
      transaction.onabort = () => reject(transaction.error);
      transaction.onerror = () => reject(transaction.error);
    });
  } finally { database.close(); }
}
