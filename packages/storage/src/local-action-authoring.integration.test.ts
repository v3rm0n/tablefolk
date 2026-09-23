import { bytesEqual, bytesToHex, encodeRistrettoScalar } from "@p2pcards/crypto";
import { decodeActionBody, verifyProvenDecryptionShare } from "@p2pcards/deck";
import { PersistentSetupReceiver, recoverSetup } from "@p2pcards/engine";
import { PersistentSaskuRoundReceiver } from "@p2pcards/game-sasku";
import { decodeAndVerifyEnvelope, type EnvelopeArtifact } from "@p2pcards/protocol";
import {
  MAX_SASKU_HAND_ACTIONS, SASKU_DECK_SPEC, SaskuHandController, parseSaskuCard, type SaskuCardId,
} from "@p2pcards/rules-sasku";
import {
  PersistentEnvelopeAuthor, PersistentSessionReceiver, SessionChainRegistry, recoverSessionChains, replayAuthoredHistory,
} from "@p2pcards/session";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { describe, expect, it, vi } from "vitest";

import { roundRevealFixture } from "../../engine/src/round-reveal.test-fixture";
import {
  AUTHORED_HEADS_STORE, GAMES_STORE, IDENTITY_STORE, TRANSCRIPTS_STORE,
  openP2pCardsDatabase, type IndexedDbStoreOptions,
} from "./database";
import { IndexedDbAuthoredEnvelopeStore } from "./indexeddb-envelope-store";
import { IndexedDbGameSecretStore } from "./indexeddb-game-secret-store";
import { IndexedDbSessionStore } from "./indexeddb-session-store";

describe("local Sasku action authoring with native IndexedDB history", () => {
  it("authors diamonds and nine private-hand plays through a complete, signed and replayable audit", async () => {
    const round = await durableRound();
    const { fixture: f, game, store, authored, secrets, author, key, reference, messages } = round;
    try {
      const initialPrivate = game.readPrivateHand(author.sender, key)!;
      expect(Object.keys(initialPrivate.remaining)).toHaveLength(9);
      expectPublicHand(f, game, reference);
      await expectStoredRound(round);

      const before = game.snapshot;
      const opening = await game.authorAction(author, key, before, { type: "diamonds" }, f.source);
      expect(opening).toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "duplicate" });
      if (opening.status === "rejected") throw new Error("Local diamonds was rejected");
      expect(opening.snapshot).toBe(game.snapshot);
      expect(game.snapshot).not.toBe(before);
      expect(opening.received.envelope).toMatchObject({
        type: "ACTION", round: f.round, phase: before.ledger.phase, from: author.sender, seq: 6,
        body: { kind: "diamonds", data: {}, reveal: [], shares: [] },
      });
      expect(decodeActionBody(opening.received.envelope.body)).toEqual({ kind: "diamonds", data: {}, reveal: [], shares: [] });
      const original = decodeAndVerifyEnvelope(opening.received.canonicalBytes);
      messages.push(original);
      reference.apply({ type: "diamonds", seat: 0 });
      expectPublicHand(f, game, reference);
      expect(game.readPrivateHand(author.sender, key)).toEqual(initialPrivate);

      // Returned buffers are not the native checkpoint, transcript, or accepted chain's buffers.
      opening.received.canonicalBytes.fill(0xff);
      opening.received.hash.fill(0xff);
      opening.received.envelope.from.fill(0xff);
      expect(await authored.readAuthoredHead(f.gameId, author.sender)).toEqual(original);
      await expect(game.receive(original)).resolves.toMatchObject({
        status: "duplicate", chainStatus: "duplicate", persistenceStatus: "duplicate",
      });
      expect(game.snapshot).toBe(opening.snapshot);
      await expectStoredRound(round);

      let localPlays = 0;
      for (let play = 0; play < 36; play += 1) {
        const seat = reference.snapshot.turn!;
        const legal = reference.legalCardsForTurn();
        const privateHand = game.readPrivateHand(author.sender, key)!;
        const position = seat === 0
          ? Number(Object.entries(privateHand.remaining).find(([, card]) => legal.includes(card))![0])
          : f.cards.indexOf(legal[0]!);
        const card = seat === 0 ? privateHand.remaining[position]! : parseSaskuCard(f.cards[position]).id;
        const expected = game.snapshot;
        expect(game.ownerAt(position)).toBe(seat);
        const result = seat === 0
          ? await game.authorAction(author, key, expected, { type: "play", position }, f.source)
          : await game.receive(f.action(seat, [position], expected.ledger.actionIndex));
        expect(result).toMatchObject({
          status: "accepted", chainStatus: "accepted", persistenceStatus: seat === 0 ? "duplicate" : "stored",
        });
        if (result.status === "rejected") throw new Error("Legal play was rejected");
        expect(result.snapshot).toBe(game.snapshot);
        messages.push(result.received);
        reference.apply({ type: "play", seat, card });
        expectPublicHand(f, game, reference);
        expect(game.snapshot.ledger.revealed[position]).toBe(card);
        if (seat === 0) {
          localPlays += 1;
          expectPlayProof(f, result.received, expected.ledger.phase, position);
          const remaining = { ...privateHand.remaining };
          delete remaining[position];
          expect(game.readPrivateHand(author.sender, key)).toEqual({ dealt: initialPrivate.dealt, remaining });
        } else {
          expect(game.readPrivateHand(author.sender, key)).toEqual(privateHand);
        }
      }
      expect(localPlays).toBe(9);
      expect(game.snapshot.ledger.actionIndex).toBe(37);
      expect(Object.keys(game.snapshot.ledger.revealed)).toHaveLength(36);
      expect(game.readPrivateHand(author.sender, key)).toEqual({ dealt: initialPrivate.dealt, remaining: {} });
      const phase = `round.${f.round}.audit`;
      expect(game.snapshot.audit).toEqual({ phase, pendingSenders: [0, 1, 2, 3], result: null });
      for (let seat = 0; seat < 4; seat += 1) {
        // Audit authoring is outside authorAction; the fixture's local head is now stale.
        const artifact = seat === 0
          ? await author.author({ type: "AUDIT_DISCLOSE", round: f.round, phase, body: { items: [] } })
          : f.sign(seat, "AUDIT_DISCLOSE", phase, { items: [] });
        await expect(game.receive(artifact)).resolves.toMatchObject({
          status: "accepted", chainStatus: "accepted", persistenceStatus: seat === 0 ? "duplicate" : "stored",
        });
        messages.push(artifact);
      }
      expect(game.snapshot.audit).toEqual({
        phase, pendingSenders: [], result: { status: "valid", score: reference.snapshot.score },
      });
      const records = await store.loadTranscript(f.gameId);
      expect(records).toHaveLength(65);
      expect(records.filter(({ authored }) => authored)).toHaveLength(17);
      expect(records.filter(({ authored }) => !authored)).toHaveLength(48);
      await expectStoredRound(round);
      const completed = game.snapshot;
      const heads = round.chains.heads();
      const stored = await databaseContents(round.options);
      game.close();
      await Promise.all([store.close(), authored.close(), secrets.close()]);

      const reopened = new IndexedDbSessionStore(round.options);
      let replay: PersistentSaskuRoundReceiver | undefined;
      try {
        const recovered = await replayRound(f, reopened);
        replay = recovered.game;
        expect(replay.snapshot).toEqual(completed);
        expect(recovered.chains.heads()).toEqual(heads);
        expect(await databaseContents(round.options)).toEqual(stored);
      } finally {
        replay?.close();
        await reopened.close();
      }
    } finally {
      game.close();
      await Promise.all([store.close(), authored.close(), secrets.close()]);
    }
  }, 20_000);

  it("requires reconstruction after authored commit but failed local receipt, then continues the original chain once", async () => {
    const round = await durableRound();
    const { fixture: f, game, store, authored, secrets, author, key, reference, messages } = round;
    const before = game.snapshot;
    const heads = round.chains.heads();
    const previous = (await authored.readAuthoredHead(f.gameId, author.sender))!;
    const authoring = vi.spyOn(author, "author");
    const append = vi.spyOn(authored, "appendNext");
    const diskFailure = new Error("local receipt disk failure after authored commit");
    const receipt = vi.spyOn(store, "persistAcceptedEnvelope").mockImplementationOnce(async (received) => {
      expect(await authored.readAuthoredHead(f.gameId, author.sender)).toEqual(received);
      const rows = await store.loadTranscript(f.gameId);
      expect(rows).toHaveLength(messages.length + 1);
      expect(rows.at(-1)).toEqual({ arrival: messages.length + 1, artifact: received, authored: true });
      expect(game.snapshot).toBe(before);
      expect(round.chains.heads()).toEqual(heads);
      throw diskFailure;
    });
    try {
      await expect(game.authorAction(author, key, before, { type: "diamonds" }, f.source))
        .rejects.toMatchObject({ code: "recovery_required", cause: diskFailure });
      expect(game.failure).toMatchObject({ code: "recovery_required", cause: diskFailure });
      expect(game.snapshot).toBe(before);
      expect(round.chains.heads()).toEqual(heads);
      expect(game.pendingEnvelopes).toBe(0);
      expect(game.pendingBytes).toBe(0);
      const unapplied = (await authored.readAuthoredHead(f.gameId, author.sender))!;
      expect(unapplied.envelope).toMatchObject({
        type: "ACTION", phase: before.ledger.phase, seq: previous.envelope.seq + 1, prev: previous.hash,
        body: { kind: "diamonds", data: {}, reveal: [], shares: [] },
      });
      messages.push(unapplied);
      await expectStoredRound(round);
      const stored = await databaseContents(round.options);
      for (const attempt of [author, new PersistentEnvelopeAuthor(f.gameId, f.identities[0]!.secretKey, authored)]) {
        await expect(game.authorAction(attempt, key, before, { type: "diamonds" }, f.source)).rejects.toBe(game.failure);
      }
      await expect(game.receive(unapplied)).rejects.toBe(game.failure);
      expect(authoring).toHaveBeenCalledTimes(1);
      expect(append).toHaveBeenCalledTimes(1);
      expect(receipt).toHaveBeenCalledTimes(1);
      expect(game.snapshot).toBe(before);
      expect(round.chains.heads()).toEqual(heads);
      expect(await databaseContents(round.options)).toEqual(stored);
      game.close();
      await Promise.all([store.close(), authored.close(), secrets.close()]);

      const reopenedStore = new IndexedDbSessionStore(round.options);
      const reopenedAuthored = new IndexedDbAuthoredEnvelopeStore(round.options);
      const reopenedSecrets = new IndexedDbGameSecretStore(round.options);
      const noCreate = vi.spyOn(reopenedSecrets, "getOrCreateGameSecret").mockImplementation(() => {
        throw new Error("Restart must load, not create, the game secret");
      });
      const resumedAppend = vi.spyOn(reopenedAuthored, "appendNext");
      let replay: PersistentSaskuRoundReceiver | undefined;
      try {
        const loaded = await reopenedSecrets.loadGameSecret(f.gameId);
        expect(loaded).toBe(key);
        if (loaded === null) throw new Error("Saved local game secret is missing");
        const recovered = await replayRound(f, reopenedStore);
        replay = recovered.game;
        reference.apply({ type: "diamonds", seat: 0 });
        expectPublicHand(f, replay, reference);
        expect(replay.snapshot.ledger).toEqual({ ...before.ledger, actionIndex: 1, phase: `round.${f.round}.play.1` });
        expect(recovered.chains.heads()).toEqual(heads.map((head) => bytesEqual(head.from, author.sender)
          ? { from: author.sender, seq: unapplied.envelope.seq, hash: unapplied.hash } : head));
        expect(replay.failure).toBeNull();
        expect(await databaseContents(round.options)).toEqual(stored);

        const originals: Uint8Array[] = [];
        await expect(replayAuthoredHistory(reopenedAuthored, f.gameId, author.sender, async (bytes) => {
          originals.push(bytes);
        })).resolves.toMatchObject({
          status: "replayed", submittedCount: 7, checkpoint: { seq: unapplied.envelope.seq, hash: unapplied.hash },
        });
        expect(originals).toEqual(messages.filter(({ envelope }) => bytesEqual(envelope.from, author.sender))
          .map(({ canonicalBytes }) => canonicalBytes));
        expect(resumedAppend).not.toHaveBeenCalled();
        const recoveredSnapshot = replay.snapshot;
        await expect(replay.receive(decodeAndVerifyEnvelope(originals.at(-1)!))).resolves.toMatchObject({
          status: "duplicate", chainStatus: "duplicate", persistenceStatus: "duplicate",
        });
        expect(replay.snapshot).toBe(recoveredSnapshot);
        expect(await databaseContents(round.options)).toEqual(stored);

        const resumedAuthor = new PersistentEnvelopeAuthor(f.gameId, f.identities[0]!.secretKey, reopenedAuthored);
        const privateHand = replay.readPrivateHand(resumedAuthor.sender, loaded)!;
        expect(Object.keys(privateHand.remaining)).toHaveLength(9);
        const [positionText, card] = Object.entries(privateHand.remaining)
          .find(([, card]) => reference.legalCardsForTurn().includes(card))!;
        const position = Number(positionText);
        const result = await replay.authorAction(resumedAuthor, loaded, recoveredSnapshot, { type: "play", position }, f.source);
        expect(result).toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "duplicate" });
        if (result.status === "rejected") throw new Error("Recovered local play was rejected");
        expect(result.snapshot).toBe(replay.snapshot);
        expect(result.received.envelope).toMatchObject({ seq: unapplied.envelope.seq + 1, prev: unapplied.hash });
        expectPlayProof(f, result.received, recoveredSnapshot.ledger.phase, position);
        messages.push(result.received);
        reference.apply({ type: "play", seat: 0, card });
        expectPublicHand(f, replay, reference);
        expect(replay.snapshot.ledger.actionIndex).toBe(2);
        expect(replay.snapshot.ledger.revealed).toEqual({ [position]: card });
        const remaining = { ...privateHand.remaining };
        delete remaining[position];
        expect(replay.readPrivateHand(resumedAuthor.sender, loaded)).toEqual({ dealt: privateHand.dealt, remaining });
        expect(await reopenedAuthored.readAuthoredHead(f.gameId, resumedAuthor.sender)).toEqual(result.received);
        const advanced = replay.snapshot;
        await expect(replay.receive(result.received)).resolves.toMatchObject({ status: "duplicate", persistenceStatus: "duplicate" });
        expect(replay.snapshot).toBe(advanced);
        expect(resumedAppend).toHaveBeenCalledTimes(1);
        expect(noCreate).not.toHaveBeenCalled();
        expect(await reopenedSecrets.loadGameSecret(f.gameId)).toBe(loaded);
        await expectStoredRound(round);
      } finally {
        replay?.close();
        noCreate.mockRestore();
        resumedAppend.mockRestore();
        await Promise.all([reopenedStore.close(), reopenedAuthored.close(), reopenedSecrets.close()]);
      }
    } finally {
      receipt.mockRestore();
      authoring.mockRestore();
      append.mockRestore();
      game.close();
      await Promise.all([store.close(), authored.close(), secrets.close()]);
    }
  }, 15_000);
});

async function durableRound() {
  const fixture = roundRevealFixture({
    seats: 4, deckSpec: SASKU_DECK_SPEC, maxActions: MAX_SASKU_HAND_ACTIONS,
    schedule: [0, 1, 2, 3].map((to) => ({ to, count: 9 })),
  });
  const options = { factory: new IDBFactory(), databaseName: "local-action-authoring", keyRange: IDBKeyRange };
  const store = new IndexedDbSessionStore(options);
  const authored = new IndexedDbAuthoredEnvelopeStore(options);
  const secrets = new IndexedDbGameSecretStore(options);
  const author = new PersistentEnvelopeAuthor(fixture.gameId, fixture.identities[0]!.secretKey, authored);
  const chains = new SessionChainRegistry(fixture.gameId, fixture.roster);
  const sessionReceiver = new PersistentSessionReceiver(chains, store);
  const setupReceiver = new PersistentSetupReceiver({ round: 0, self: author.sender, session: chains, sessionReceiver });
  const messages: EnvelopeArtifact[] = [];
  let game: PersistentSaskuRoundReceiver | undefined;
  const nativeLocal = async (artifact: EnvelopeArtifact) => {
    if (!bytesEqual(artifact.envelope.from, author.sender)) return artifact;
    const { round, phase, type, body } = artifact.envelope;
    const original = await author.author({ round, phase, type, body });
    // Deterministic signing keeps the fixture's sender head coherent until local ACTION authoring starts.
    expect(original.canonicalBytes).toEqual(artifact.canonicalBytes);
    return original;
  };
  try {
    const create = vi.fn(() => fixture.secrets[0]!);
    await secrets.getOrCreateGameSecret(fixture.gameId, create);
    const key = await secrets.loadGameSecret(fixture.gameId);
    if (key === null) throw new Error("Local key must be durable before KEY_SHARE authoring");
    expect(create).toHaveBeenCalledTimes(1);
    for (const artifact of fixture.setupEnvelopes) {
      const message = await nativeLocal(artifact);
      await expect(setupReceiver.receive(message)).resolves.toMatchObject({
        status: "accepted", chainResult: {
          status: "accepted", persistenceStatus: bytesEqual(message.envelope.from, author.sender) ? "duplicate" : "stored",
        },
      });
      messages.push(message);
    }
    const setup = setupReceiver.getCompletedSetup();
    game = new PersistentSaskuRoundReceiver({
      setup, round: fixture.round, deck: fixture.deck, schedule: fixture.options.schedule, dealer: 3,
      session: chains, sessionReceiver,
    });
    for (let step = 0; step < fixture.plans.length; step += 1) {
      for (let seat = 3; seat >= 0; seat -= 1) {
        if (seat === fixture.plans[step]!.to) continue;
        const message = await nativeLocal(fixture.deal(step, seat));
        await expect(game.receive(message)).resolves.toMatchObject({
          status: "accepted", chainStatus: "accepted", persistenceStatus: seat === 0 ? "duplicate" : "stored",
        });
        messages.push(message);
      }
    }
    const hands: [SaskuCardId[], SaskuCardId[], SaskuCardId[], SaskuCardId[]] = [[], [], [], []];
    fixture.cards.forEach((card, position) => hands[game!.ownerAt(position)].push(parseSaskuCard(card).id));
    const reference = new SaskuHandController({ dealer: 3, hands });
    expect(messages).toHaveLength(24);
    expect(game.snapshot.ledger.deal).toBeNull();
    return { fixture, options, store, authored, secrets, author, key, chains, game, reference, messages };
  } catch (cause) {
    game?.close();
    await Promise.all([store.close(), authored.close(), secrets.close()]);
    throw cause;
  }
}

function expectPlayProof(f: ReturnType<typeof roundRevealFixture>, artifact: EnvelopeArtifact, phase: string, position: number) {
  expect(artifact.envelope).toMatchObject({ type: "ACTION", game: f.gameId, from: f.roster[0], round: f.round, phase });
  const body = decodeActionBody(artifact.envelope.body);
  expect(body.shares).toHaveLength(1);
  const share = body.shares[0]!;
  expect(artifact.envelope.body).toEqual({
    kind: "play", data: {}, reveal: [position], shares: [{
      pos: position, S: share.S.toBytes(), R1: share.proof.R1.toBytes(), R2: share.proof.R2.toBytes(), z: encodeRistrettoScalar(share.proof.z),
    }],
  });
  const context = { gameId: f.gameId, round: f.round, phase };
  const publicKey = f.setup.publicKeyAt(0)!;
  const previousPhase = `round.${f.round}.play.${Number(phase.split(".").at(-1)) - 1}`;
  expect(verifyProvenDecryptionShare(context, position, publicKey, f.deck[position]!.A, share)).toBe(true);
  expect(verifyProvenDecryptionShare({ ...context, phase: `round.${f.round}.deal.0` }, position, publicKey, f.deck[position]!.A, share)).toBe(false);
  expect(verifyProvenDecryptionShare({ ...context, phase: previousPhase }, position, publicKey, f.deck[position]!.A, share)).toBe(false);
  expect(verifyProvenDecryptionShare(context, (position + 1) % 36, publicKey, f.deck[position]!.A, share)).toBe(false);
}

function expectPublicHand(f: ReturnType<typeof roundRevealFixture>, game: PersistentSaskuRoundReceiver, reference: SaskuHandController) {
  const { score, ...expected } = reference.snapshot;
  expect(game.snapshot.hand).toEqual({ ...expected, provisionalScore: score });
  expect(game.snapshot.history).toEqual(reference.history);
  expect(game.snapshot.ledger).toEqual({
    phase: `round.${f.round}.play.${reference.history.length}`,
    dealIndex: f.plans.length, actionIndex: reference.history.length, deal: null,
    revealed: Object.fromEntries(reference.history.flatMap((action) => action.type === "play"
      ? [[f.cards.indexOf(action.card), action.card]] : [])),
  });
  expect(Object.keys(game.snapshot).sort()).toEqual(["audit", "hand", "history", "ledger"]);
  const snapshot = JSON.stringify(game.snapshot);
  f.cards.forEach((card, position) => {
    if (!Object.hasOwn(game.snapshot.ledger.revealed, position)) expect(snapshot).not.toContain(JSON.stringify(card));
  });
}

async function replayRound(f: ReturnType<typeof roundRevealFixture>, store: IndexedDbSessionStore) {
  const transcript = (await store.loadTranscript(f.gameId)).map(({ artifact }) => artifact).reverse();
  const chains = recoverSessionChains(f.gameId, f.roster, transcript).registry;
  const setup = recoverSetup(f.gameId, 0, f.roster, transcript).coordinator;
  const heads = chains.heads();
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
    return { game, chains };
  } catch (cause) {
    game?.close();
    throw cause;
  } finally { persist.mockRestore(); }
}

async function expectStoredRound(round: Awaited<ReturnType<typeof durableRound>>) {
  const game = bytesToHex(round.fixture.gameId);
  const sender = bytesToHex(round.author.sender);
  const own = round.messages.filter(({ envelope }) => bytesToHex(envelope.from) === sender);
  expect(own.map(({ envelope }) => envelope.seq)).toEqual(own.map((_, index) => index));
  expect(await databaseContents(round.options)).toEqual({
    [GAMES_STORE]: [{ game, gameSecret: encodeRistrettoScalar(round.key) }],
    [IDENTITY_STORE]: [],
    [AUTHORED_HEADS_STORE]: [{ game, sender, bytes: own.at(-1)!.canonicalBytes }],
    [TRANSCRIPTS_STORE]: round.messages.map(({ envelope, canonicalBytes }, index) => ({
      arrival: index + 1, game, sender: bytesToHex(envelope.from), seq: envelope.seq,
      bytes: canonicalBytes, authored: bytesToHex(envelope.from) === sender,
    })),
  });
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
