import { decodeActionBody } from "@p2pcards/deck";
import { PersistentSetupReceiver, recoverSetup } from "@p2pcards/engine";
import { PersistentSaskuRoundReceiver } from "@p2pcards/game-sasku";
import { decodeAndVerifyEnvelope } from "@p2pcards/protocol";
import {
  MAX_SASKU_HAND_ACTIONS, SASKU_DECK_SPEC, SaskuHandController,
  auditSaskuHand, parseSaskuCard, type SaskuCardId, type SaskuDeal,
} from "@p2pcards/rules-sasku";
import { PersistentSessionReceiver, SessionChainRegistry, recoverSessionChains } from "@p2pcards/session";
import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it, vi } from "vitest";

import { roundRevealFixture } from "../../engine/src/round-reveal.test-fixture";
import { openP2pCardsDatabase, type IndexedDbStoreOptions } from "./database";
import { IndexedDbSessionStore } from "./indexeddb-session-store";

describe("production Sasku receiver with IndexedDB", () => {
  it("plays a supplied Sasku ciphertext fixture and recovers pending and completed audits from fresh connections", async () => {
    const round = await durableRound();
    const { fixture: f, game, store, chains } = round;
    const options = { factory: round.factory, databaseName: "round-reveal-integration" };
    try {
      expect(game.snapshot.audit).toBeNull();
      const initialHands = [[], [], [], []] as SaskuCardId[][];
      f.cards.forEach((card, pos) => initialHands[game.ownerAt(pos)]!.push(parseSaskuCard(card).id));
      const reference = new SaskuHandController({ dealer: 3, hands: initialHands as unknown as SaskuDeal });
      await round.receive(f.action(0, [], 0, "diamonds"));
      reference.apply({ type: "diamonds", seat: 0 });
      for (let play = 0; play < 36; play += 1) {
        expect(game.snapshot.audit).toBeNull();
        const seat = reference.snapshot.turn!;
        const card = reference.legalCardsForTurn()[0]!;
        const pos = f.cards.indexOf(card);
        const envelope = f.action(seat, [pos], game.snapshot.ledger.actionIndex);
        await expect(round.receive(envelope)).resolves.toMatchObject({ status: "accepted" });
        reference.apply({ type: "play", seat, card });
        const { score, ...expected } = reference.snapshot;
        expect(game.snapshot.hand).toEqual({ ...expected, provisionalScore: score });
      }
      expect(game.snapshot.ledger.actionIndex).toBe(37);
      expect(Object.keys(game.snapshot.ledger.revealed)).toHaveLength(36);
      const auditPhase = `round.${f.round}.audit`;
      expect(game.snapshot.audit).toEqual({ phase: auditPhase, pendingSenders: [0, 1, 2, 3], result: null });
      const disclosed = [[], [], [], []] as SaskuCardId[][];
      for (let pos = 0; pos < 36; pos += 1) {
        disclosed[game.ownerAt(pos)]!.push(parseSaskuCard(game.snapshot.ledger.revealed[pos]).id);
      }
      expect(auditSaskuHand({ dealer: 3, hands: disclosed as unknown as SaskuDeal }, game.snapshot.history)).toEqual({ status: "valid", snapshot: reference.snapshot });

      const disclosures = [0, 1, 2, 3].map((seat) => f.sign(seat, "AUDIT_DISCLOSE", auditPhase, { items: [] }));
      for (let seat = 0; seat < 3; seat += 1) {
        await expect(round.receive(disclosures[seat]!)).resolves.toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "stored" });
        expect(game.snapshot.audit).toEqual({ phase: auditPhase, pendingSenders: [0, 1, 2, 3].slice(seat + 1), result: null });
      }
      const waiting = game.snapshot;
      const waitingHeads = chains.heads();
      await expect(round.receive(disclosures[0]!)).resolves.toMatchObject({ status: "duplicate", chainStatus: "duplicate", persistenceStatus: "duplicate" });
      expect(game.snapshot).toBe(waiting);
      expect(chains.heads()).toEqual(waitingHeads);

      const fourthBytes = disclosures[3]!.canonicalBytes.slice();
      const started = deferred();
      const release = deferred();
      const write = vi.spyOn(store, "persistAcceptedEnvelope").mockImplementationOnce(async () => {
        started.resolve();
        await release.promise;
        throw new Error("audit disk failure");
      });
      const receiving = expect(round.receive(disclosures[3]!)).rejects.toThrow("audit disk failure");
      try {
        await started.promise;
        expect(write).toHaveBeenCalledTimes(1);
        expect(game.pendingEnvelopes).toBe(1);
        expect(game.snapshot).toBe(waiting);
        expect(chains.heads()).toEqual(waitingHeads);
        expect(await store.loadTranscript(f.gameId)).toHaveLength(64);
      } finally { release.resolve(); await receiving; }
      expect(game.snapshot).toBe(waiting);
      expect(chains.heads()).toEqual(waitingHeads);
      expect(game.failure).toBeNull();
      expect(game.pendingEnvelopes).toBe(0);
      expect(game.pendingBytes).toBe(0);
      expect(await store.loadTranscript(f.gameId)).toHaveLength(64);

      const auditResult = { status: "valid", score: reference.snapshot.score };
      const partialStore = new IndexedDbSessionStore(options);
      let recoveredAudit: typeof waiting;
      try {
        const records = await partialStore.loadTranscript(f.gameId);
        expect(records).toHaveLength(64);
        expect(records.filter(({ artifact }) => artifact.envelope.type === "AUDIT_DISCLOSE")).toHaveLength(3);
        const transcript = records.map(({ artifact }) => artifact).reverse();
        const recoveredChains = recoverSessionChains(f.gameId, f.roster, transcript).registry;
        expect(recoveredChains.heads()).toEqual(waitingHeads);
        const restoredSetup = recoverSetup(f.gameId, 0, f.roster, transcript).coordinator;
        const stored = await databaseContents(options);
        const persist = vi.spyOn(partialStore, "persistAcceptedEnvelope").mockImplementation(() => {
          throw new Error("Recovery must not persist accepted envelopes");
        });
        let replay: PersistentSaskuRoundReceiver;
        try {
          replay = PersistentSaskuRoundReceiver.recover({
            setup: restoredSetup, round: f.round, deck: f.deck, schedule: f.options.schedule, dealer: 3,
            session: recoveredChains, sessionReceiver: new PersistentSessionReceiver(recoveredChains, partialStore),
          });
          expect(persist).not.toHaveBeenCalled();
          expect(recoveredChains.heads()).toEqual(waitingHeads);
          expect(await databaseContents(options)).toEqual(stored);
        } finally { persist.mockRestore(); }
        expect(replay.snapshot).toEqual(waiting);
        expect(replay.snapshot.audit).toEqual({ phase: auditPhase, pendingSenders: [3], result: null });
        await expect(replay.receive(decodeAndVerifyEnvelope(fourthBytes))).resolves.toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "stored" });
        recoveredAudit = replay.snapshot;
        expect(recoveredAudit.audit).toEqual({ phase: auditPhase, pendingSenders: [], result: auditResult });
        expect(await partialStore.loadTranscript(f.gameId)).toHaveLength(65);
      } finally { await partialStore.close(); }

      expect(game.snapshot).toBe(waiting);
      expect(chains.heads()).toEqual(waitingHeads);
      await expect(round.receive(decodeAndVerifyEnvelope(fourthBytes))).resolves.toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "duplicate" });
      expect(game.snapshot).toEqual(recoveredAudit);
      expect(game.snapshot.audit).toEqual({ phase: auditPhase, pendingSenders: [], result: auditResult });
      expect(game.snapshot.hand).toBe(waiting.hand);
      expect(game.snapshot.hand.provisionalScore).toEqual(reference.snapshot.score);
      expect(game.snapshot.hand).not.toHaveProperty("score");
      expect(game.snapshot.ledger).toBe(waiting.ledger);
      expect(game.snapshot.history).toBe(waiting.history);
      expect(write).toHaveBeenCalledTimes(2);
      for (const [received] of write.mock.calls) expect(received.canonicalBytes).toEqual(fourthBytes);

      const audited = game.snapshot;
      const heads = chains.heads();
      await expect(round.receive(f.sign(0, "AUDIT_DISCLOSE", auditPhase, { items: [] }))).rejects.toMatchObject({ code: "conflicting_contribution" });
      await expect(game.receive(f.action(0, [], 37, "pass"))).rejects.toMatchObject({ code: "hand_complete" });
      expect(game.snapshot).toBe(audited);
      expect(chains.heads()).toEqual(heads);
      expect(write).toHaveBeenCalledTimes(2);
      expect(game.failure).toBeNull();
      await store.close();

      const completedStore = new IndexedDbSessionStore(options);
      try {
        const records = await completedStore.loadTranscript(f.gameId);
        expect(records).toHaveLength(65);
        expect(records.filter(({ artifact }) => artifact.envelope.type === "AUDIT_DISCLOSE").map(({ artifact }) => artifact.canonicalBytes))
          .toEqual(disclosures.map(({ canonicalBytes }) => canonicalBytes));
        const transcript = records.map(({ artifact }) => artifact).reverse();
        const recoveredChains = recoverSessionChains(f.gameId, f.roster, transcript).registry;
        expect(recoveredChains.heads()).toEqual(heads);
        const restoredSetup = recoverSetup(f.gameId, 0, f.roster, transcript).coordinator;
        const stored = await databaseContents(options);
        const persist = vi.spyOn(completedStore, "persistAcceptedEnvelope").mockImplementation(() => {
          throw new Error("Recovery must not persist accepted envelopes");
        });
        let replay: PersistentSaskuRoundReceiver;
        try {
          replay = PersistentSaskuRoundReceiver.recover({
            setup: restoredSetup, round: f.round, deck: f.deck, schedule: f.options.schedule, dealer: 3,
            session: recoveredChains, sessionReceiver: new PersistentSessionReceiver(recoveredChains, completedStore),
          });
          expect(persist).not.toHaveBeenCalled();
          expect(recoveredChains.heads()).toEqual(heads);
          expect(await databaseContents(options)).toEqual(stored);
        } finally { persist.mockRestore(); }
        expect(replay.snapshot).toEqual(game.snapshot);
        expect(replay.snapshot.audit?.result).toEqual(auditResult);
        expect(auditSaskuHand({ dealer: 3, hands: disclosed as unknown as SaskuDeal }, replay.snapshot.history).status).toBe("valid");
        const complete = replay.snapshot;
        const messages = transcript.filter(({ envelope }) => envelope.round === f.round &&
          (envelope.type === "SHARES" || envelope.type === "ACTION" || envelope.type === "AUDIT_DISCLOSE"));
        for (const envelope of messages.reverse()) await expect(replay.receive(envelope)).resolves.toMatchObject({ status: "duplicate", chainStatus: "duplicate", persistenceStatus: "duplicate" });
        expect(replay.snapshot).toBe(complete);
        expect(recoveredChains.heads()).toEqual(heads);
        expect(await completedStore.loadTranscript(f.gameId)).toHaveLength(65);
      } finally { await completedStore.close(); }
    } finally { await store.close(); }
  }, 120_000); // Full hand plus multiple cryptographic recovery passes on CI CPUs.

  it("keeps action and public-hand state unchanged until IndexedDB commit resolves", async () => {
    const round = await durableRound();
    const started = deferred();
    const release = deferred();
    const persist = round.store.persistAcceptedEnvelope.bind(round.store);
    vi.spyOn(round.store, "persistAcceptedEnvelope").mockImplementationOnce(async (received) => {
      started.resolve();
      await release.promise;
      return persist(received);
    });
    try {
      const envelope = round.fixture.action(0, [], 0, "diamonds");
      const original = envelope.canonicalBytes.slice();
      const beforeLedger = round.game.snapshot.ledger;
      const beforeHand = round.game.snapshot.hand;
      const beforeHeads = round.chains.heads();
      const receiving = round.receive(envelope);
      envelope.canonicalBytes.fill(0xff); envelope.hash.fill(0xff);
      await started.promise;
      expect(round.game.snapshot.ledger).toEqual(beforeLedger);
      expect(round.game.snapshot.hand).toEqual(beforeHand);
      expect(round.chains.heads()).toEqual(beforeHeads);
      expect(await round.store.loadTranscript(round.fixture.gameId)).toHaveLength(24);
      release.resolve();
      await expect(receiving).resolves.toMatchObject({ status: "accepted" });
      expect(round.game.snapshot.ledger.actionIndex).toBe(1);
      expect(round.game.snapshot.hand.phase).toBe("playing");
      const completed = round.game.snapshot.hand;
      await expect(round.receive(decodeAndVerifyEnvelope(original))).resolves.toMatchObject({ status: "duplicate" });
      expect(round.game.snapshot.ledger.actionIndex).toBe(1);
      expect(round.game.snapshot.hand).toEqual(completed);
      expect(await round.store.loadTranscript(round.fixture.gameId)).toHaveLength(25);
    } finally { release.resolve(); await round.store.close(); }
  });

  it("does not mutate either state on storage failure and retries the original envelope without resigning", async () => {
    const round = await durableRound();
    try {
      const envelope = round.fixture.action(0, [], 0, "diamonds");
      const beforeLedger = round.game.snapshot.ledger;
      const beforeHand = round.game.snapshot.hand;
      const beforeHeads = round.chains.heads();
      vi.spyOn(round.store, "persistAcceptedEnvelope").mockRejectedValueOnce(new Error("disk failure"));
      await expect(round.receive(envelope)).rejects.toThrow("disk failure");
      expect(round.game.snapshot.ledger).toEqual(beforeLedger);
      expect(round.game.snapshot.hand).toEqual(beforeHand);
      expect(round.chains.heads()).toEqual(beforeHeads);
      expect(await round.store.loadTranscript(round.fixture.gameId)).toHaveLength(24);
      await expect(round.receive(envelope)).resolves.toMatchObject({ status: "accepted" });
      expect(round.game.snapshot.ledger.actionIndex).toBe(1);
    } finally { await round.store.close(); }
  });

  it("does not consume an owned reveal on a chain gap, then accepts it after the missing control arrives", async () => {
    const round = await durableRound();
    const f = round.fixture;
    try {
      await round.receive(f.action(0, [], 0, "diamonds"));
      const witness = f.sign(0, "WITNESS", round.game.snapshot.ledger.phase, { heads: [] });
      const play = f.action(0, [0], 1);
      const before = round.game.snapshot.ledger;
      const hand = round.game.snapshot.hand;
      await expect(round.receive(play)).resolves.toMatchObject({ status: "rejected", reason: "gap" });
      expect(round.game.snapshot.ledger).toEqual(before);
      expect(round.game.snapshot.hand).toEqual(hand);
      expect(await round.store.loadTranscript(f.gameId)).toHaveLength(25);
      await expect(round.receiver.receive(witness)).resolves.toMatchObject({ status: "accepted" });
      await expect(round.receive(play)).resolves.toMatchObject({ status: "accepted" });
      expect(round.game.snapshot.ledger.revealed).toEqual({ 0: f.cards[0] });
      expect(round.game.snapshot.hand.trick).toEqual([{ seat: 0, card: f.cards[0] }]);
      await expect(round.receive(play)).resolves.toMatchObject({ status: "duplicate" });
      expect(round.game.snapshot.ledger.actionIndex).toBe(2);
      expect(round.game.snapshot.history).toHaveLength(2);
    } finally { await round.store.close(); }
  });

  it("leaves the ledger and hand unchanged on a durable equal-sequence conflict", async () => {
    const round = await durableRound();
    const f = round.fixture;
    try {
      const action = f.action(0, [], 0, "diamonds");
      const conflict = f.sign(0, "ACTION", action.envelope.phase, { kind: "pass", data: {}, reveal: [], shares: [] }, {
        seq: action.envelope.seq, prev: action.envelope.prev,
      });
      await round.store.persistAcceptedEnvelope(conflict);
      const beforeLedger = round.game.snapshot.ledger;
      const beforeHand = round.game.snapshot.hand;
      const beforeHeads = round.chains.heads();
      await expect(round.receive(action)).resolves.toMatchObject({ status: "rejected", reason: "durable_conflict" });
      expect(round.game.snapshot.ledger).toEqual(beforeLedger);
      expect(round.game.snapshot.hand).toEqual(beforeHand);
      expect(round.chains.heads()).toEqual(beforeHeads);
    } finally { await round.store.close(); }
  });

  it("rejects invalid proofs and public rules before writing any action record", async () => {
    const round = await durableRound();
    const f = round.fixture;
    try {
      const persist = vi.spyOn(round.store, "persistAcceptedEnvelope");
      const wrongRule = f.action(0, [], 0, "choose_trump", { suit: "hearts" });
      await expect(round.receive(wrongRule)).rejects.toThrow(/during bidding/);
      const valid = f.action(0, [0]);
      const decoded = decodeActionBody(valid.envelope.body);
      const badProof = f.sign(0, "ACTION", valid.envelope.phase, {
        kind: "play", data: {}, reveal: [0], shares: [{
          pos: 0, S: decoded.shares[0]!.S.toBytes(), R1: decoded.shares[0]!.proof.R1.toBytes(),
          R2: decoded.shares[0]!.proof.R2.toBytes(), z: new Uint8Array(32),
        }],
      });
      await expect(round.receive(badProof)).rejects.toThrow(expect.objectContaining({ code: "invalid_share_proof" }));
      expect(persist).not.toHaveBeenCalled();
      expect(round.game.snapshot.ledger).toMatchObject({ actionIndex: 0, revealed: {} });
      expect(round.game.snapshot.history).toEqual([]);
      expect(await round.store.loadTranscript(f.gameId)).toHaveLength(24);
    } finally { await round.store.close(); }
  });
});

async function durableRound() {
  const fixture = roundRevealFixture({
    seats: 4, deckSpec: SASKU_DECK_SPEC, schedule: [0, 1, 2, 3].map((to) => ({ to, count: 9 })),
    maxActions: MAX_SASKU_HAND_ACTIONS,
  });
  const factory = new IDBFactory();
  const store = new IndexedDbSessionStore({ factory, databaseName: "round-reveal-integration" });
  const chains = new SessionChainRegistry(fixture.gameId, fixture.roster);
  const receiver = new PersistentSessionReceiver(chains, store);
  const setupReceiver = new PersistentSetupReceiver({
    round: 0, self: fixture.roster[0]!, session: chains, sessionReceiver: receiver,
  });
  for (const envelope of fixture.setupEnvelopes) await setupReceiver.receive(envelope);
  const setup = setupReceiver.getCompletedSetup();
  const game = new PersistentSaskuRoundReceiver({
    setup, round: fixture.round, deck: fixture.deck, schedule: fixture.options.schedule, dealer: 3,
    session: chains, sessionReceiver: receiver,
  });
  const receive = game.receive.bind(game);
  for (let step = 0; step < fixture.plans.length; step += 1) {
    for (let actor = 3; actor >= 0; actor -= 1) {
      if (actor !== fixture.plans[step]!.to) await receive(fixture.deal(step, actor));
    }
  }
  return { fixture, factory, store, chains, receiver, game, receive };
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

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}
