import { bytesEqual, bytesToHex, encodeRistrettoScalar } from "@p2pcards/crypto";
import { decodeActionBody, decodeSharesBody } from "@p2pcards/deck";
import { PersistentSetupReceiver, recoverSetup } from "@p2pcards/engine";
import { PersistentSaskuRoundReceiver, type SaskuRoundReceiveResult } from "@p2pcards/game-sasku";
import { decodeAndVerifyEnvelope, type EnvelopeArtifact } from "@p2pcards/protocol";
import {
  MAX_SASKU_HAND_ACTIONS, SASKU_DECK_SPEC, SaskuHandController, parseSaskuCard, type SaskuCardId,
} from "@p2pcards/rules-sasku";
import {
  PersistentEnvelopeAuthor, PersistentSessionReceiver, SessionChainRegistry,
  orderEnvelopeTranscript, recoverSessionChains, replayAuthoredHistory,
} from "@p2pcards/session";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { describe, expect, it, vi } from "vitest";

import * as protocolRandom from "../../crypto/src/random";
import { roundRevealFixture } from "../../engine/src/round-reveal.test-fixture";
import {
  AUTHORED_HEADS_STORE, GAMES_STORE, IDENTITY_STORE, TRANSCRIPTS_STORE,
  openP2pCardsDatabase, type IndexedDbStoreOptions,
} from "./database";
import { IndexedDbAuthoredEnvelopeStore } from "./indexeddb-envelope-store";
import { IndexedDbGameSecretStore } from "./indexeddb-game-secret-store";
import { IndexedDbSessionStore } from "./indexeddb-session-store";

type Fixture = ReturnType<typeof roundRevealFixture>;
type Peer = Awaited<ReturnType<typeof durablePeer>>;

describe("four-peer local Sasku contribution authoring with native IndexedDB history", () => {
  it("exchanges 65 originals and recovers authored-but-unapplied SHARES and final AUDIT_DISCLOSE without resigning", async () => {
    // Explicitly trusted test deck, dealer, and schedule, not production shuffle verification or game policy.
    const f = roundRevealFixture({
      seats: 4, deckSpec: SASKU_DECK_SPEC, maxActions: MAX_SASKU_HAND_ACTIONS,
      schedule: [0, 1, 2, 3].map((to) => ({ to, count: 9 })),
    });
    const peers: Peer[] = [];
    // Observe protocol RNG, not the native curve library's internal scalar blinding.
    const random = vi.spyOn(protocolRandom, "randomBytes");
    try {
      for (let seat = 0; seat < 4; seat += 1) peers.push(await durablePeer(f, seat));
      expect(new Set(peers.map(({ options }) => options.factory)).size).toBe(4);
      expect(new Set(peers.map(({ options }) => options.databaseName)).size).toBe(4);
      expectPeers(f, peers);
      // Each of these setup originals was natively authored in its sender's own database.
      const originals = peers.flatMap((peer) => peer.messages.filter(({ envelope }) => bytesEqual(envelope.from, peer.author.sender)));
      expect(originals).toHaveLength(12);
      let recoveredShares: EnvelopeArtifact | undefined;
      for (let step = 0; step < f.plans.length; step += 1) {
        const plan = f.plans[step]!;
        const donors = peers.filter(({ seat }) => seat !== plan.to);
        const contributions: EnvelopeArtifact[] = [];
        for (const peer of donors) {
          const before = peer.game.snapshot;
          expect(before.ledger.deal).toEqual({ ...plan, pendingSenders: donors.map(({ seat }) => seat) });
          expect(peer.game.readPrivateHand(peer.author.sender, peer.key)).toBeNull();
          let artifact: EnvelopeArtifact;
          if (step === 0 && peer.seat === 3) {
            const otherGames = peers.slice(0, 3).map(({ game }) => game);
            const otherSnapshots = otherGames.map((game) => game.snapshot);
            artifact = await recoverContribution(f, peer, "SHARES");
            recoveredShares = artifact;
            for (let seat = 0; seat < 3; seat += 1) {
              expect(peers[seat]!.game).toBe(otherGames[seat]);
              expect(peers[seat]!.game.snapshot).toBe(otherSnapshots[seat]);
            }
          } else {
            const authoring = peer.game.authorDealShares(peer.author, peer.key, before, f.source);
            expect(peer.game.snapshot).toBe(before);
            expect(peer.game.readPrivateHand(peer.author.sender, peer.key)).toBeNull();
            artifact = recordLocal(peer, await authoring);
          }
          expect(artifact.envelope).toMatchObject({
            type: "SHARES", game: f.gameId, from: f.roster[peer.seat], round: f.round, phase: `round.${f.round}.deal.${step}`,
          });
          const body = decodeSharesBody(artifact.envelope.body);
          expect(body.to).toBe(plan.to);
          expect(body.items.map(({ pos }) => pos)).toEqual(plan.positions);
          expect(peer.game.snapshot.ledger.deal).toEqual({
            ...plan, pendingSenders: donors.filter(({ seat }) => seat !== peer.seat).map(({ seat }) => seat),
          });
          expect(peer.game.readPrivateHand(peer.author.sender, peer.key)).toBeNull();
          if (step === 1 && peer.seat === 3) {
            expect(artifact.envelope).toMatchObject({ seq: recoveredShares!.envelope.seq + 1, prev: recoveredShares!.hash });
            expect(peer.authoring).toHaveBeenCalledTimes(1);
            expect(peer.append).toHaveBeenCalledTimes(1);
          }
          contributions.push(artifact);
        }
        originals.push(...contributions);
        await exchange(peers, contributions);
        expectPeers(f, peers);
        expect(peers[0]!.game.snapshot.ledger.dealIndex).toBe(step + 1);
      }

      const hands: [SaskuCardId[], SaskuCardId[], SaskuCardId[], SaskuCardId[]] = [[], [], [], []];
      f.cards.forEach((card, position) => hands[peers[0]!.game.ownerAt(position)].push(parseSaskuCard(card).id));
      const reference = new SaskuHandController({ dealer: 3, hands });
      const dealt = peers.map((peer) => {
        const expected = Object.fromEntries(f.cards.flatMap((card, position) => peer.game.ownerAt(position) === peer.seat
          ? [[position, parseSaskuCard(card).id]] : []));
        expect(peer.game.readPrivateHand(peer.author.sender, peer.key)).toEqual({ dealt: expected, remaining: expected });
        return expected;
      });
      expectPeers(f, peers, reference);
      const opener = peers[0]!;
      const opening = recordLocal(opener, await opener.game.authorAction(opener.author, opener.key, opener.game.snapshot, { type: "diamonds" }, f.source));
      expect(opening.envelope).toMatchObject({
        type: "ACTION", from: f.roster[0], seq: 6, phase: `round.${f.round}.play.0`,
        body: { kind: "diamonds", data: {}, reveal: [], shares: [] },
      });
      originals.push(opening);
      reference.apply({ type: "diamonds", seat: 0 });
      await exchange(peers, [opening]);
      expectPeers(f, peers, reference);

      const plays = [0, 0, 0, 0];
      for (let play = 0; play < 36; play += 1) {
        const seat = peers[0]!.game.snapshot.hand.turn!;
        expect(seat).toBe(reference.snapshot.turn);
        const peer = peers[seat]!;
        const privateHand = peer.game.readPrivateHand(peer.author.sender, peer.key)!;
        const legal = reference.legalCardsForTurn();
        const [positionText, card] = Object.entries(privateHand.remaining).find(([, card]) => legal.includes(card))!;
        const position = Number(positionText);
        expect(legal).toContain(card);
        expect(peer.game.ownerAt(position)).toBe(seat);
        const before = peer.game.snapshot;
        const artifact = recordLocal(peer, await peer.game.authorAction(peer.author, peer.key, before, { type: "play", position }, f.source));
        expect(artifact.envelope).toMatchObject({ type: "ACTION", from: f.roster[seat], round: f.round, phase: before.ledger.phase });
        const body = decodeActionBody(artifact.envelope.body);
        expect(body).toMatchObject({ kind: "play", data: {}, reveal: [position], shares: [{ pos: position }] });
        expect(body.shares).toHaveLength(1);
        const remaining = { ...privateHand.remaining };
        delete remaining[position];
        expect(peer.game.readPrivateHand(peer.author.sender, peer.key)).toEqual({ dealt: dealt[seat], remaining });
        originals.push(artifact);
        plays[seat]! += 1;
        reference.apply({ type: "play", seat, card });
        await exchange(peers, [artifact]);
        expectPeers(f, peers, reference);
      }
      expect(plays).toEqual([9, 9, 9, 9]);
      expect(random).toHaveBeenCalled();
      const drawsBeforeAudit = random.mock.calls.length;
      const phase = `round.${f.round}.audit`;
      for (const peer of peers) {
        expect(peer.game.snapshot.hand.phase).toBe("complete");
        expect(peer.game.snapshot.ledger.actionIndex).toBe(37);
        expect(Object.keys(peer.game.snapshot.ledger.revealed)).toHaveLength(36);
        expect(peer.game.readPrivateHand(peer.author.sender, peer.key)).toEqual({ dealt: dealt[peer.seat], remaining: {} });
        expect(peer.game.snapshot.audit).toEqual({ phase, pendingSenders: [0, 1, 2, 3], result: null });
      }
      for (const seat of [0, 1, 3]) {
        const peer = peers[seat]!;
        const artifact = recordLocal(peer, await peer.game.authorAuditDisclose(peer.author, peer.game.snapshot));
        expect(artifact.envelope).toMatchObject({ type: "AUDIT_DISCLOSE", from: f.roster[seat], round: f.round, phase, body: { items: [] } });
        originals.push(artifact);
        await exchange(peers, [artifact]);
        expectPeers(f, peers, reference);
        expect(peers[0]!.game.snapshot.audit!.result).toBeNull();
      }
      const otherSnapshots = peers.map(({ game }) => game.snapshot);
      expect(otherSnapshots[2]!.audit).toEqual({ phase, pendingSenders: [2], result: null });
      const finalDisclosure = await recoverContribution(f, peers[2]!, "AUDIT_DISCLOSE");
      expect(finalDisclosure.envelope).toMatchObject({ type: "AUDIT_DISCLOSE", from: f.roster[2], round: f.round, phase, body: { items: [] } });
      expect(peers[2]!.game.snapshot.audit).toEqual({ phase, pendingSenders: [], result: { status: "valid", score: reference.snapshot.score } });
      for (const seat of [0, 1, 3]) expect(peers[seat]!.game.snapshot).toBe(otherSnapshots[seat]);
      originals.push(finalDisclosure);
      await exchange(peers, [finalDisclosure]);
      expectPeers(f, peers, reference);
      expect(random).toHaveBeenCalledTimes(drawsBeforeAudit);
      expect(originals).toHaveLength(65);
      expect(originals.filter(({ envelope }) => envelope.type === "SHARES")).toHaveLength(12);
      expect(originals.filter(({ envelope }) => envelope.type === "ACTION")).toHaveLength(37);
      expect(originals.filter(({ envelope }) => envelope.type === "AUDIT_DISCLOSE")).toHaveLength(4);
      const canonical = orderEnvelopeTranscript(f.gameId, originals).map(({ canonicalBytes }) => canonicalBytes);
      expect(new Set(canonical.map(bytesToHex)).size).toBe(65);
      for (const peer of peers) {
        const records = await peer.store.loadCanonicalEnvelopeTranscript(f.gameId);
        expect(records).toHaveLength(65);
        expect(records.map(({ artifact }) => artifact.canonicalBytes)).toEqual(canonical);
        expect(records.filter(({ authored }) => authored)).toHaveLength(peer.seat === 0 ? 17 : 16);
        expect(records.filter(({ authored }) => !authored)).toHaveLength(peer.seat === 0 ? 48 : 49);
        const stored = await expectStoredPeer(f, peer);
        expect(peer.noCreate).not.toHaveBeenCalled();
        peer.game.close();
        await Promise.all([peer.store.close(), peer.authored.close(), peer.keyStore.close()]);
        const callerKeys = new IndexedDbGameSecretStore(peer.options);
        const noCreate = vi.spyOn(callerKeys, "getOrCreateGameSecret").mockImplementation(() => { throw new Error("Final callers must only load their saved key"); });
        try {
          expect(await callerKeys.loadGameSecret(f.gameId)).toBe(peer.key);
          expect(noCreate).not.toHaveBeenCalled();
          expect(await databaseContents(peer.options)).toEqual(stored);
        } finally { await callerKeys.close(); }
      }
    } finally {
      for (const peer of peers) peer.game.close();
      await Promise.all(peers.flatMap((peer) => [peer.store.close(), peer.authored.close(), peer.keyStore.close()]));
      vi.restoreAllMocks();
    }
  }, 30_000);
});

async function durablePeer(f: Fixture, seat: number) {
  const options = { factory: new IDBFactory(), databaseName: `local-contribution-authoring-${seat}`, keyRange: IDBKeyRange };
  const store = new IndexedDbSessionStore(options);
  const authored = new IndexedDbAuthoredEnvelopeStore(options);
  const keyStore = new IndexedDbGameSecretStore(options);
  const author = new PersistentEnvelopeAuthor(f.gameId, f.identities[seat]!.secretKey, authored);
  const chains = new SessionChainRegistry(f.gameId, f.roster);
  const sessionReceiver = new PersistentSessionReceiver(chains, store);
  const setupReceiver = new PersistentSetupReceiver({ round: 0, self: author.sender, session: chains, sessionReceiver });
  const messages: EnvelopeArtifact[] = [];
  let game: PersistentSaskuRoundReceiver | undefined;
  try {
    const create = vi.fn(() => f.secrets[seat]!);
    await keyStore.getOrCreateGameSecret(f.gameId, create);
    const key = await keyStore.loadGameSecret(f.gameId);
    if (key === null) throw new Error("The peer's own game key must be durable before its native KEY_SHARE");
    expect(key).toBe(f.secrets[seat]);
    expect(create).toHaveBeenCalledTimes(1);
    const noCreate = vi.spyOn(keyStore, "getOrCreateGameSecret").mockImplementation(() => { throw new Error("An established peer must only load its saved key"); });
    for (const artifact of f.setupEnvelopes) {
      const own = bytesEqual(artifact.envelope.from, author.sender);
      let message = artifact;
      if (own) {
        const { round, phase, type, body } = artifact.envelope;
        message = await author.author({ round, phase, type, body });
        // Native deterministic signatures establish the exact fixture prefix, not imported authored flags.
        expect(message.canonicalBytes).toEqual(artifact.canonicalBytes);
      }
      await expect(setupReceiver.receive(message)).resolves.toMatchObject({
        status: "accepted", chainResult: { status: "accepted", persistenceStatus: own ? "duplicate" : "stored" },
      });
      messages.push(message);
    }
    const setup = setupReceiver.getCompletedSetup();
    game = new PersistentSaskuRoundReceiver({
      setup, round: f.round, deck: f.deck, schedule: f.options.schedule, dealer: 3, session: chains, sessionReceiver,
    });
    const authoring = vi.spyOn(author, "author");
    const append = vi.spyOn(authored, "appendNext");
    const peer = { seat, options, store, authored, keyStore, author, key, chains, game, messages, noCreate, authoring, append };
    await expectStoredPeer(f, peer);
    return peer;
  } catch (cause) {
    game?.close();
    await Promise.all([store.close(), authored.close(), keyStore.close()]);
    throw cause;
  }
}

function recordLocal(peer: Peer, result: SaskuRoundReceiveResult): EnvelopeArtifact {
  expect(result).toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "duplicate" });
  if (result.status === "rejected") throw new Error("Local authoring was rejected");
  expect(result.snapshot).toBe(peer.game.snapshot);
  const previous = peer.messages.filter(({ envelope }) => bytesEqual(envelope.from, peer.author.sender)).at(-1)!;
  expect(result.received.envelope).toMatchObject({ from: peer.author.sender, seq: previous.envelope.seq + 1, prev: previous.hash });
  peer.messages.push(result.received);
  return result.received;
}

async function exchange(peers: readonly Peer[], originals: readonly EnvelopeArtifact[]) {
  // Direct delivery of original artifacts to independent controllers, deliberately not a real transport.
  for (const artifact of originals) {
    await Promise.all(peers.filter((peer) => !bytesEqual(artifact.envelope.from, peer.author.sender)).map(async (peer) => {
      const before = peer.game.snapshot;
      if (before.ledger.deal !== null) expect(peer.game.readPrivateHand(peer.author.sender, peer.key)).toBeNull();
      const receiving = peer.game.receive(artifact);
      expect(peer.game.snapshot).toBe(before);
      if (before.ledger.deal !== null) expect(peer.game.readPrivateHand(peer.author.sender, peer.key)).toBeNull();
      await expect(receiving).resolves.toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "stored" });
      peer.messages.push(artifact);
      if (peer.game.snapshot.ledger.deal !== null) expect(peer.game.readPrivateHand(peer.author.sender, peer.key)).toBeNull();
    }));
  }
}

function expectPeers(f: Fixture, peers: readonly Peer[], reference?: SaskuHandController) {
  const snapshot = peers[0]!.game.snapshot;
  for (const peer of peers) {
    expect(peer.game.snapshot).toEqual(snapshot);
    expect(peer.chains.heads()).toEqual(peers[0]!.chains.heads());
    expect(peer.game.failure).toBeNull();
    expect(peer.game.pendingEnvelopes).toBe(0);
    expect(peer.game.pendingBytes).toBe(0);
    if (snapshot.ledger.deal !== null) expect(peer.game.readPrivateHand(peer.author.sender, peer.key)).toBeNull();
  }
  expect(Object.keys(snapshot).sort()).toEqual(["audit", "hand", "history", "ledger"]);
  const publicState = JSON.stringify(snapshot);
  f.cards.forEach((card, position) => {
    if (!Object.hasOwn(snapshot.ledger.revealed, position)) expect(publicState).not.toContain(JSON.stringify(card));
  });
  if (reference !== undefined) {
    const { score, ...hand } = reference.snapshot;
    expect(snapshot.hand).toEqual({ ...hand, provisionalScore: score });
    expect(snapshot.history).toEqual(reference.history);
    expect(snapshot.ledger).toEqual({
      phase: `round.${f.round}.play.${reference.history.length}`, dealIndex: f.plans.length,
      actionIndex: reference.history.length, deal: null,
      revealed: Object.fromEntries(reference.history.flatMap((action) => action.type === "play" ? [[f.cards.indexOf(action.card), action.card]] : [])),
    });
  }
}

async function recoverContribution(f: Fixture, peer: Peer, type: "SHARES" | "AUDIT_DISCLOSE"): Promise<EnvelopeArtifact> {
  const before = peer.game.snapshot;
  const heads = peer.chains.heads();
  const previous = (await peer.authored.readAuthoredHead(f.gameId, peer.author.sender))!;
  const diskFailure = new Error(`Local ${type} receipt failed after native authored append`);
  const submit = (expected = peer.game.snapshot) => type === "SHARES"
    ? peer.game.authorDealShares(peer.author, peer.key, expected, f.source)
    : peer.game.authorAuditDisclose(peer.author, expected);
  const authorCalls = peer.authoring.mock.calls.length;
  const appendCalls = peer.append.mock.calls.length;
  const receipt = vi.spyOn(peer.store, "persistAcceptedEnvelope").mockImplementationOnce(async (received) => {
    expect(await peer.authored.readAuthoredHead(f.gameId, peer.author.sender)).toEqual(received);
    const rows = await peer.store.loadTranscript(f.gameId);
    expect(rows).toHaveLength(peer.messages.length + 1);
    expect(rows.at(-1)).toEqual({ arrival: peer.messages.length + 1, artifact: received, authored: true });
    expect(peer.game.snapshot).toBe(before);
    expect(peer.chains.heads()).toEqual(heads);
    throw diskFailure;
  });
  try {
    await expect(submit(before)).rejects.toMatchObject({ code: "recovery_required", cause: diskFailure });
    expect(peer.game.failure).toMatchObject({ code: "recovery_required", cause: diskFailure });
    expect(peer.game.snapshot).toBe(before);
    expect(peer.chains.heads()).toEqual(heads);
    expect(peer.game.pendingEnvelopes).toBe(0);
    expect(peer.game.pendingBytes).toBe(0);
    const unapplied = (await peer.authored.readAuthoredHead(f.gameId, peer.author.sender))!;
    expect(unapplied.envelope).toMatchObject({
      type, game: f.gameId, from: peer.author.sender, round: f.round, phase: type === "SHARES" ? before.ledger.phase : before.audit!.phase,
      seq: previous.envelope.seq + 1, prev: previous.hash,
    });
    peer.messages.push(unapplied);
    const stored = await expectStoredPeer(f, peer);
    await expect(submit(before)).rejects.toBe(peer.game.failure);
    await expect(peer.game.receive(unapplied)).rejects.toBe(peer.game.failure);
    expect(peer.authoring).toHaveBeenCalledTimes(authorCalls + 1);
    expect(peer.append).toHaveBeenCalledTimes(appendCalls + 1);
    expect(receipt).toHaveBeenCalledTimes(1);
    expect(peer.game.snapshot).toBe(before);
    expect(peer.chains.heads()).toEqual(heads);
    expect(await databaseContents(peer.options)).toEqual(stored);
    expect(peer.noCreate).not.toHaveBeenCalled();
    peer.game.close();
    await Promise.all([peer.store.close(), peer.authored.close(), peer.keyStore.close()]);

    peer.store = new IndexedDbSessionStore(peer.options);
    peer.authored = new IndexedDbAuthoredEnvelopeStore(peer.options);
    peer.keyStore = new IndexedDbGameSecretStore(peer.options);
    peer.noCreate = vi.spyOn(peer.keyStore, "getOrCreateGameSecret").mockImplementation(() => { throw new Error("Recovery must load, never create, the peer's key"); });
    peer.author = new PersistentEnvelopeAuthor(f.gameId, f.identities[peer.seat]!.secretKey, peer.authored);
    peer.authoring = vi.spyOn(peer.author, "author");
    peer.append = vi.spyOn(peer.authored, "appendNext");
    const drawsBeforeReplay = vi.mocked(protocolRandom.randomBytes).mock.calls.length;
    const noProofRandom = vi.spyOn(f.source, "fill").mockImplementation(() => { throw new Error("Replay must reuse original proofs without randomness"); });
    try {
      const loaded = await peer.keyStore.loadGameSecret(f.gameId);
      expect(loaded).toBe(peer.key);
      if (loaded === null) throw new Error("Recovery lost the peer's own game key");
      peer.key = loaded;
      const recovered = await replayRound(f, peer.store);
      peer.game = recovered.game;
      peer.chains = recovered.chains;
      expect(peer.game.failure).toBeNull();
      expect(peer.chains.heads()).toEqual(heads.map((head) => bytesEqual(head.from, peer.author.sender)
        ? { from: peer.author.sender, seq: unapplied.envelope.seq, hash: unapplied.hash } : head));
      if (type === "SHARES") {
        expect(peer.game.snapshot).toEqual({ ...before, ledger: { ...before.ledger, deal: {
          ...before.ledger.deal!, pendingSenders: before.ledger.deal!.pendingSenders.filter((seat) => seat !== peer.seat),
        } } });
      } else {
        expect(peer.game.snapshot).toEqual({ ...before, audit: {
          phase: before.audit!.phase, pendingSenders: [], result: { status: "valid", score: before.hand.provisionalScore },
        } });
      }
      expect(await databaseContents(peer.options)).toEqual(stored);
      expect(await peer.authored.readAuthoredHead(f.gameId, peer.author.sender)).toEqual(unapplied);
      const bytes: Uint8Array[] = [];
      await expect(replayAuthoredHistory(peer.authored, f.gameId, peer.author.sender, async (original) => {
        bytes.push(original);
      })).resolves.toMatchObject({
        status: "replayed", submittedCount: unapplied.envelope.seq + 1,
        checkpoint: { seq: unapplied.envelope.seq, hash: unapplied.hash },
      });
      expect(bytes).toEqual(peer.messages.filter(({ envelope }) => bytesEqual(envelope.from, peer.author.sender)).map(({ canonicalBytes }) => canonicalBytes));
      const original = decodeAndVerifyEnvelope(bytes.at(-1)!);
      expect(original).toEqual(unapplied);
      const applied = peer.game.snapshot;
      await expect(peer.game.receive(original)).resolves.toMatchObject({ status: "duplicate", chainStatus: "duplicate", persistenceStatus: "duplicate" });
      await expect(submit()).rejects.toMatchObject({ code: "conflicting_contribution" });
      await expect(submit(before)).rejects.toMatchObject({ code: "stale_contribution" });
      expect(peer.game.snapshot).toBe(applied);
      expect(peer.chains.heads()).toEqual(recovered.heads);
      expect(peer.authoring).not.toHaveBeenCalled();
      expect(peer.append).not.toHaveBeenCalled();
      expect(peer.noCreate).not.toHaveBeenCalled();
      expect(noProofRandom).not.toHaveBeenCalled();
      expect(protocolRandom.randomBytes).toHaveBeenCalledTimes(drawsBeforeReplay);
      expect(await databaseContents(peer.options)).toEqual(stored);
      return original;
    } finally { noProofRandom.mockRestore(); }
  } finally { receipt.mockRestore(); }
}

async function replayRound(f: Fixture, store: IndexedDbSessionStore) {
  const records = await store.loadTranscript(f.gameId);
  const transcript = records.map(({ artifact }) => artifact).reverse();
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
    return { game, chains, heads };
  } catch (cause) {
    game?.close();
    throw cause;
  } finally { persist.mockRestore(); }
}

async function expectStoredPeer(f: Fixture, peer: Peer): Promise<Record<string, unknown[]>> {
  const game = bytesToHex(f.gameId);
  const sender = bytesToHex(peer.author.sender);
  const own = peer.messages.filter(({ envelope }) => bytesToHex(envelope.from) === sender);
  expect(own.map(({ envelope }) => envelope.seq)).toEqual(own.map((_, index) => index));
  expect(await peer.store.loadTranscript(f.gameId)).toEqual(peer.messages.map((artifact, index) => ({
    arrival: index + 1, artifact, authored: bytesEqual(artifact.envelope.from, peer.author.sender),
  })));
  const stored = await databaseContents(peer.options);
  expect(stored).toEqual({
    [GAMES_STORE]: [{ game, gameSecret: encodeRistrettoScalar(peer.key) }],
    [IDENTITY_STORE]: [],
    [AUTHORED_HEADS_STORE]: [{ game, sender, bytes: own.at(-1)!.canonicalBytes }],
    [TRANSCRIPTS_STORE]: peer.messages.map(({ envelope, canonicalBytes }, index) => ({
      arrival: index + 1, game, sender: bytesToHex(envelope.from), seq: envelope.seq,
      bytes: canonicalBytes, authored: bytesToHex(envelope.from) === sender,
    })),
  });
  return stored;
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
