import { bytesEqual, bytesToHex, encodeRistrettoScalar } from "@p2pcards/crypto";
import { decodeActionBody, decodeSharesBody } from "@p2pcards/deck";
import { PersistentSetupReceiver } from "@p2pcards/engine";
import {
  DEFAULT_MAX_PENDING_SASKU_INBOX_BYTES, DEFAULT_MAX_PENDING_SASKU_INBOX_ENVELOPES,
  PersistentSaskuRoundReceiver, SaskuRoundInbox, type SaskuRoundReceiveResult,
} from "@p2pcards/game-sasku";
import { decodeAndVerifyEnvelope, type EnvelopeArtifact } from "@p2pcards/protocol";
import {
  MAX_SASKU_HAND_ACTIONS, SASKU_DECK_SPEC, SaskuHandController, parseSaskuCard, type SaskuCardId,
} from "@p2pcards/rules-sasku";
import { PersistentEnvelopeAuthor, PersistentSessionReceiver, SessionChainRegistry, orderEnvelopeTranscript } from "@p2pcards/session";
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

type Fixture = ReturnType<typeof roundRevealFixture>;
type Peer = Awaited<ReturnType<typeof durablePeer>>;

describe("four independent native IndexedDB peers with Sasku round inboxes", () => {
  it("exchanges 65 originals with genuine cross-sender deal, play, and audit phase reordering", async () => {
    // Explicitly trusted test setup/ciphertexts, dealer, and 4x9 schedule, not verified shuffle provenance or policy.
    const f = roundRevealFixture({
      seats: 4, deckSpec: SASKU_DECK_SPEC, maxActions: MAX_SASKU_HAND_ACTIONS,
      schedule: [0, 1, 2, 3].map((to) => ({ to, count: 9 })),
    });
    const peers: Peer[] = [];
    try {
      for (let seat = 0; seat < 4; seat += 1) peers.push(await durablePeer(f, seat));
      expect(new Set(peers.map(({ options }) => options.factory)).size).toBe(4);
      expect(new Set(peers.map(({ options }) => options.databaseName)).size).toBe(4);
      for (const field of ["store", "authored", "keyStore", "author", "key", "chains", "sessionReceiver", "setup", "game", "inbox"] as const) {
        expect(new Set(peers.map((peer) => peer[field])).size).toBe(4);
      }
      expect(DEFAULT_MAX_PENDING_SASKU_INBOX_ENVELOPES).toBe(32);
      expect(DEFAULT_MAX_PENDING_SASKU_INBOX_BYTES).toBe(1024 * 1024);
      expectPeers(f, peers);

      const stepZero: EnvelopeArtifact[] = [];
      for (const seat of [1, 2, 3]) stepZero.push(await authorShares(f, peers[seat]!));
      const heldShares = stepZero[0]!;
      await exchange(peers, peers[2]!, stepZero[1]!);
      await exchange(peers, peers[3]!, stepZero[2]!);
      await exchange([peers[0]!, peers[2]!], peers[1]!, heldShares);
      expectPeers(f, peers.slice(0, 3));
      expect(peers[0]!.game.snapshot.ledger).toMatchObject({ dealIndex: 1, deal: { ...f.plans[1]!, pendingSenders: [0, 2, 3] } });
      expect(peers[3]!.game.snapshot.ledger).toMatchObject({ dealIndex: 0, deal: { ...f.plans[0]!, pendingSenders: [1] } });

      // Seat 2 really completed step 0 before authoring step 1; seat 1's earlier stream is delayed only at seat 3.
      const earlyShares = await authorShares(f, peers[2]!);
      await exchange(peers.slice(0, 2), peers[2]!, earlyShares);
      expectPeers(f, peers.slice(0, 3));
      await expectDeferredThenReleased(f, peers[3]!, [peers[2]!, earlyShares], [peers[1]!, heldShares]);
      expectPeers(f, peers);
      expect(peers[0]!.game.snapshot.ledger).toMatchObject({ dealIndex: 1, deal: { ...f.plans[1]!, pendingSenders: [0, 3] } });

      for (let step = 1; step < f.plans.length; step += 1) {
        const pending = peers[0]!.game.snapshot.ledger.deal!.pendingSenders;
        expect(pending).toEqual(step === 1 ? [0, 3] : [0, 1, 2, 3].filter((seat) => seat !== f.plans[step]!.to));
        for (const seat of pending) {
          const peer = peers[seat]!;
          await exchange(peers, peer, await authorShares(f, peer));
          expectPeers(f, peers);
        }
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
      const opening = await recordLocal(opener, await opener.game.authorAction(opener.author, opener.key, opener.game.snapshot, { type: "diamonds" }, f.source));
      expect(opening.envelope).toMatchObject({
        type: "ACTION", from: f.roster[0], seq: 6, phase: `round.${f.round}.play.0`,
        body: { kind: "diamonds", data: {}, reveal: [], shares: [] },
      });
      reference.apply({ type: "diamonds", seat: 0 });
      await exchange(peers, opener, opening);
      expectPeers(f, peers, reference);

      const plays = [0, 0, 0, 0];
      let heldFirstPlay: EnvelopeArtifact | undefined;
      let firstAuditor: Peer | undefined;
      for (let play = 0; play < 36; play += 1) {
        const seat = reference.snapshot.turn!;
        const peer = peers[seat]!;
        const before = peer.game.snapshot;
        expect(before.hand.turn).toBe(seat);
        expect(before.history).toEqual(reference.history);
        const privateHand = peer.game.readPrivateHand(peer.author.sender, peer.key)!;
        const legal = reference.legalCardsForTurn();
        const [positionText, card] = Object.entries(privateHand.remaining).find(([, card]) => legal.includes(card))!;
        const position = Number(positionText);
        expect(legal).toContain(card);
        expect(peer.game.ownerAt(position)).toBe(seat);
        const artifact = await recordLocal(peer, await peer.game.authorAction(peer.author, peer.key, before, { type: "play", position }, f.source));
        expect(artifact.envelope).toMatchObject({ type: "ACTION", from: f.roster[seat], round: f.round, phase: `round.${f.round}.play.${play + 1}` });
        const body = decodeActionBody(artifact.envelope.body);
        expect(body).toMatchObject({ kind: "play", data: {}, reveal: [position], shares: [{ pos: position }] });
        expect(body.shares).toHaveLength(1);
        const remaining = { ...privateHand.remaining };
        delete remaining[position];
        expect(peer.game.readPrivateHand(peer.author.sender, peer.key)).toEqual({ dealt: dealt[seat], remaining });
        plays[seat]! += 1;
        reference.apply({ type: "play", seat, card });

        if (play === 0) {
          expect(seat).toBe(0);
          heldFirstPlay = artifact;
          await exchange(peers.filter(({ seat }) => seat !== 2), peer, artifact);
          expectPeers(f, peers.filter(({ seat }) => seat !== 2), reference);
          expect(peers[2]!.game.snapshot).toEqual(before);
          continue;
        } else if (play === 1) {
          expect(seat).toBe(1);
          await exchange(peers.filter(({ seat }) => seat !== 2), peer, artifact);
          expectPeers(f, peers.filter(({ seat }) => seat !== 2), reference);
          expect(peers[2]!.game.snapshot).toMatchObject({
            ledger: { actionIndex: 1, revealed: {} }, hand: { phase: "playing", turn: 0 }, audit: null,
          });
          await expectDeferredThenReleased(f, peers[2]!, [peer, artifact], [opener, heldFirstPlay!]);
        } else if (play === 35) {
          const lagger = peers[(seat + 1) % 4]!;
          firstAuditor = peers[(seat + 2) % 4]!;
          expect(new Set([peer.seat, lagger.seat, firstAuditor.seat]).size).toBe(3);
          const advanced = peers.filter((candidate) => candidate !== lagger);
          await exchange(advanced, peer, artifact);
          expectPeers(f, advanced, reference);
          expect(lagger.game.snapshot).toEqual(before);
          expect(lagger.game.snapshot).toMatchObject({ ledger: { actionIndex: 36 }, hand: { phase: "playing", turn: seat }, audit: null });
          expect(Object.keys(lagger.game.snapshot.ledger.revealed)).toHaveLength(35);
          expect(firstAuditor.game.snapshot.audit).toEqual({ phase: `round.${f.round}.audit`, pendingSenders: [0, 1, 2, 3], result: null });
          const audit = await recordLocal(firstAuditor, await firstAuditor.game.authorAuditDisclose(firstAuditor.author, firstAuditor.game.snapshot));
          expect(audit.envelope).toMatchObject({ type: "AUDIT_DISCLOSE", from: f.roster[firstAuditor.seat], round: f.round, phase: `round.${f.round}.audit`, body: { items: [] } });
          await exchange(advanced, firstAuditor, audit);
          await expectDeferredThenReleased(f, lagger, [firstAuditor, audit], [peer, artifact]);
        } else {
          await exchange(peers, peer, artifact);
        }
        expectPeers(f, peers, reference);
      }

      expect(plays).toEqual([9, 9, 9, 9]);
      expect(firstAuditor).toBeDefined();
      expect(reference.snapshot.score).not.toBeNull();
      const phase = `round.${f.round}.audit`;
      for (const peer of peers) {
        expect(peer.game.snapshot.hand.phase).toBe("complete");
        expect(peer.game.snapshot.ledger.actionIndex).toBe(37);
        expect(Object.keys(peer.game.snapshot.ledger.revealed)).toHaveLength(36);
        expect(peer.game.readPrivateHand(peer.author.sender, peer.key)).toEqual({ dealt: dealt[peer.seat], remaining: {} });
        expect(peer.game.snapshot.audit).toEqual({ phase, pendingSenders: [0, 1, 2, 3].filter((seat) => seat !== firstAuditor!.seat), result: null });
      }
      for (const peer of peers.filter((peer) => peer !== firstAuditor)) {
        const pending = peer.game.snapshot.audit!.pendingSenders.filter((seat) => seat !== peer.seat);
        const audit = await recordLocal(peer, await peer.game.authorAuditDisclose(peer.author, peer.game.snapshot));
        expect(audit.envelope).toMatchObject({ type: "AUDIT_DISCLOSE", from: f.roster[peer.seat], round: f.round, phase, body: { items: [] } });
        await exchange(peers, peer, audit);
        expectPeers(f, peers, reference);
        expect(peer.game.snapshot.audit).toEqual({
          phase, pendingSenders: pending, result: pending.length === 0 ? { status: "valid", score: reference.snapshot.score } : null,
        });
      }

      const originals = peers.flatMap((peer) => peer.messages.filter(({ envelope }) => bytesEqual(envelope.from, peer.author.sender)));
      expect(originals).toHaveLength(65);
      expect(originals.filter(({ envelope }) => envelope.round === 0)).toHaveLength(12);
      expect(originals.filter(({ envelope }) => envelope.type === "SHARES")).toHaveLength(12);
      expect(originals.filter(({ envelope }) => envelope.type === "ACTION")).toHaveLength(37);
      expect(originals.filter(({ envelope }) => envelope.type === "AUDIT_DISCLOSE")).toHaveLength(4);
      const canonical = orderEnvelopeTranscript(f.gameId, originals).map(({ canonicalBytes }) => canonicalBytes);
      expect(new Set(canonical.map(bytesToHex)).size).toBe(65);
      for (const peer of peers) {
        const records = await peer.store.loadCanonicalEnvelopeTranscript(f.gameId);
        expect(records).toHaveLength(65);
        expect(records.map(({ artifact }) => artifact.canonicalBytes)).toEqual(canonical);
        expect(await peer.store.loadTranscript(f.gameId)).toEqual(peer.messages.map((artifact, index) => ({
          arrival: index + 1, artifact, authored: bytesEqual(artifact.envelope.from, peer.author.sender),
        })));
        const own = peer.messages.filter(({ envelope }) => bytesEqual(envelope.from, peer.author.sender));
        expect(own).toHaveLength(peer.seat === 0 ? 17 : 16);
        expect(records.filter(({ authored }) => authored).map(({ artifact }) => artifact)).toEqual(own);
        expect(peer.authoring).toHaveBeenCalledTimes(own.length);
        expect(peer.append).toHaveBeenCalledTimes(own.length);
        expect(await Promise.all(peer.authoring.mock.results.map(({ value }) => value))).toEqual(own);
        expect(await peer.authored.readAuthoredHead(f.gameId, peer.author.sender)).toEqual(own.at(-1));
        expect(await peer.keyStore.loadGameSecret(f.gameId)).toBe(peer.key);
        expect(peer.noCreate).not.toHaveBeenCalled();
        expect(peer.persist).toHaveBeenCalledTimes(65);
        expect(peer.remoteReceive.mock.calls.map(([artifact]) => artifact)).toEqual(peer.messages.filter(({ envelope }) =>
          envelope.round === f.round && !bytesEqual(envelope.from, peer.author.sender)));
        for (const sender of peers) {
          const authored = originals.filter(({ envelope }) => bytesEqual(envelope.from, sender.author.sender));
          expect(authored.map(({ envelope }) => envelope.seq)).toEqual(authored.map((_, index) => index));
          for (const artifact of authored) expect(decodeAndVerifyEnvelope(artifact.canonicalBytes)).toEqual(artifact);
          if (sender !== peer) expect(peer.incoming.filter(({ envelope }) => bytesEqual(envelope.from, sender.author.sender))).toEqual(authored);
          expect(peer.chains.readRange(sender.author.sender, 0, authored.length - 1)).toEqual({ status: "complete", envelopes: authored });
          expect(peer.chains.heads().find(({ from }) => bytesEqual(from, sender.author.sender))).toEqual({
            from: sender.author.sender, seq: authored.at(-1)!.envelope.seq, hash: authored.at(-1)!.hash,
          });
        }
        const game = bytesToHex(f.gameId);
        expect(await databaseContents(peer.options)).toEqual({
          [GAMES_STORE]: [{ game, gameSecret: encodeRistrettoScalar(peer.key) }],
          [IDENTITY_STORE]: [],
          [AUTHORED_HEADS_STORE]: [{ game, sender: bytesToHex(peer.author.sender), bytes: own.at(-1)!.canonicalBytes }],
          [TRANSCRIPTS_STORE]: peer.messages.map(({ envelope, canonicalBytes }, index) => ({
            arrival: index + 1, game, sender: bytesToHex(envelope.from), seq: envelope.seq,
            bytes: canonicalBytes, authored: bytesEqual(envelope.from, peer.author.sender),
          })),
        });
        expect(peer.game.snapshot.audit).toEqual({ phase, pendingSenders: [], result: { status: "valid", score: reference.snapshot.score } });
      }
    } finally {
      // Cancel deferred admissions, but let any submitted durable receipt finish before closing its dependencies.
      for (const peer of peers) peer.inbox.close();
      await Promise.all(peers.map(({ inbox }) => inbox.whenIdle()));
      for (const peer of peers) peer.game.close();
      await Promise.all(peers.map(({ game }) => game.whenIdle()));
      await Promise.all(peers.flatMap((peer) => [peer.store.close(), peer.authored.close(), peer.keyStore.close()]));
      vi.restoreAllMocks();
    }
  // One complete native four-peer crypto round, not a global timeout change.
  }, 45_000);
});

async function durablePeer(f: Fixture, seat: number) {
  const options = { factory: new IDBFactory(), databaseName: `round-inbox-${seat}`, keyRange: IDBKeyRange };
  const store = new IndexedDbSessionStore(options);
  const authored = new IndexedDbAuthoredEnvelopeStore(options);
  const keyStore = new IndexedDbGameSecretStore(options);
  const author = new PersistentEnvelopeAuthor(f.gameId, f.identities[seat]!.secretKey, authored);
  const chains = new SessionChainRegistry(f.gameId, f.roster);
  const sessionReceiver = new PersistentSessionReceiver(chains, store);
  const setupReceiver = new PersistentSetupReceiver({ round: 0, self: author.sender, session: chains, sessionReceiver });
  const authoring = vi.spyOn(author, "author");
  const append = vi.spyOn(authored, "appendNext");
  const persist = vi.spyOn(store, "persistAcceptedEnvelope");
  const messages: EnvelopeArtifact[] = [];
  let game: PersistentSaskuRoundReceiver | undefined;
  try {
    const create = vi.fn(() => f.secrets[seat]!);
    await keyStore.getOrCreateGameSecret(f.gameId, create);
    const key = await keyStore.loadGameSecret(f.gameId);
    if (key === null) throw new Error("The peer's own key must be durable before native setup authoring");
    expect(key).toBe(f.secrets[seat]);
    expect(create).toHaveBeenCalledTimes(1);
    const noCreate = vi.spyOn(keyStore, "getOrCreateGameSecret").mockImplementation(() => { throw new Error("An established peer must only load its saved key"); });
    for (const artifact of f.setupEnvelopes) {
      const own = bytesEqual(artifact.envelope.from, author.sender);
      let message = artifact;
      if (own) {
        const { round, phase, type, body } = artifact.envelope;
        message = await author.author({ round, phase, type, body });
        // Native deterministic signatures establish the fixture prefix; no imported authored flags or rewritten headers.
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
    const inbox = new SaskuRoundInbox({ receiver: game, session: chains, self: f.roster[seat]! });
    const remoteReceive = vi.spyOn(game, "receive");
    // Caller-fixture premise only: these direct remotes are authenticatedReady. This is NOT transport, readiness, or sync.
    const authenticatedReady = new Set(f.roster.filter((_, remoteSeat) => remoteSeat !== seat).map(bytesToHex));
    const incoming = messages.filter(({ envelope }) => !bytesEqual(envelope.from, author.sender));
    return { seat, options, store, authored, keyStore, author, key, chains, sessionReceiver, setup, game, inbox,
      messages, incoming, authenticatedReady, noCreate, authoring, append, persist, remoteReceive };
  } catch (cause) {
    game?.close();
    await game?.whenIdle();
    await Promise.all([store.close(), authored.close(), keyStore.close()]);
    throw cause;
  }
}

async function recordLocal(peer: Peer, result: SaskuRoundReceiveResult): Promise<EnvelopeArtifact> {
  expect(result).toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "duplicate" });
  if (result.status === "rejected") throw new Error("Native local authoring was rejected");
  expect(result.snapshot).toBe(peer.game.snapshot);
  const previous = peer.messages.filter(({ envelope }) => bytesEqual(envelope.from, peer.author.sender)).at(-1)!;
  expect(result.received.envelope).toMatchObject({ from: peer.author.sender, seq: previous.envelope.seq + 1, prev: previous.hash });
  peer.messages.push(result.received);
  // Local authoring is outside the inbox; there is deliberately no observer/subscription to wake it.
  await peer.inbox.processPending();
  return result.received;
}

async function authorShares(f: Fixture, peer: Peer): Promise<EnvelopeArtifact> {
  const before = peer.game.snapshot;
  const plan = f.plans[before.ledger.dealIndex]!;
  expect(before.ledger.deal!.pendingSenders).toContain(peer.seat);
  expect(peer.game.readPrivateHand(peer.author.sender, peer.key)).toBeNull();
  const artifact = await recordLocal(peer, await peer.game.authorDealShares(peer.author, peer.key, before, f.source));
  expect(artifact.envelope).toMatchObject({ type: "SHARES", from: f.roster[peer.seat], round: f.round, phase: `round.${f.round}.deal.${before.ledger.dealIndex}` });
  const body = decodeSharesBody(artifact.envelope.body);
  expect(body.to).toBe(plan.to);
  expect(body.items.map(({ pos }) => pos)).toEqual(plan.positions);
  return artifact;
}

function receiveOriginal(peer: Peer, sender: Peer, artifact: EnvelopeArtifact): Promise<SaskuRoundReceiveResult> {
  const remote = sender.author.sender;
  expect(sender.seat).not.toBe(peer.seat);
  expect(peer.authenticatedReady.has(bytesToHex(remote))).toBe(true);
  expect(artifact.envelope.from).toEqual(remote);
  const previous = peer.incoming.filter(({ envelope }) => bytesEqual(envelope.from, remote)).at(-1)!;
  // Check admission order, not completion order: only different direct sender streams may overtake each other.
  expect(artifact.envelope).toMatchObject({ seq: previous.envelope.seq + 1, prev: previous.hash });
  peer.incoming.push(artifact);
  const receipt = peer.inbox.receive(remote, artifact.canonicalBytes).then((result) => {
    expect(result).toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "stored" });
    expect(result.received).toEqual(artifact);
    peer.messages.push(artifact);
    return result;
  });
  // Future receipts are awaited only after their prerequisite arrives; handle rejection immediately, including cleanup.
  void receipt.catch(() => undefined);
  return receipt;
}

async function exchange(peers: readonly Peer[], sender: Peer, artifact: EnvelopeArtifact): Promise<void> {
  await Promise.all(peers.filter((peer) => peer !== sender).map((peer) => receiveOriginal(peer, sender, artifact)));
}

async function expectDeferredThenReleased(
  f: Fixture, peer: Peer,
  [futureSender, future]: readonly [Peer, EnvelopeArtifact],
  [heldSender, held]: readonly [Peer, EnvelopeArtifact],
): Promise<void> {
  expect(futureSender.seat).not.toBe(heldSender.seat);
  // Both sender chains are ready now. Deferral must be due to round semantics, never an artificial sender-sequence gap.
  expect(peer.chains.classify(future).status).toBe("accepted");
  expect(peer.chains.classify(held).status).toBe("accepted");
  const before = peer.game.snapshot;
  const heads = peer.chains.heads();
  const stored = await databaseContents(peer.options);
  const messages = [...peer.messages];
  const spies = [peer.persist, peer.remoteReceive, peer.authoring, peer.append];
  const counts = spies.map((spy) => spy.mock.calls.length);
  const receipt = receiveOriginal(peer, futureSender, future);
  const settled = vi.fn();
  void receipt.then(settled, settled);
  await peer.inbox.whenIdle();
  expect(settled).not.toHaveBeenCalled();
  expect(peer.inbox.pendingEnvelopes).toBe(1);
  expect(peer.inbox.pendingBytes).toBe(future.canonicalBytes.length);
  expect(peer.inbox.failure).toBeNull();
  expect(peer.game.pendingEnvelopes).toBe(0);
  expect(peer.game.pendingBytes).toBe(0);
  expect(peer.game.failure).toBeNull();
  expect(peer.game.snapshot).toBe(before);
  expect(peer.chains.heads()).toEqual(heads);
  expect(peer.chains.readRange(futureSender.author.sender, future.envelope.seq, future.envelope.seq)).toEqual({
    status: "missing", firstMissingSeq: future.envelope.seq,
  });
  expect(spies.map((spy) => spy.mock.calls.length)).toEqual(counts);
  expect(peer.messages).toEqual(messages);
  expect(await databaseContents(peer.options)).toEqual(stored);

  // Remote prerequisite receipt automatically drains the future; no manual retry, reauthoring, or wake here.
  await Promise.all([receiveOriginal(peer, heldSender, held), receipt]);
  await peer.inbox.whenIdle();
  expect(settled).toHaveBeenCalledTimes(1);
  expect(peer.inbox.pendingEnvelopes).toBe(0);
  expect(peer.inbox.pendingBytes).toBe(0);
  expect(peer.game.snapshot).not.toBe(before);
  expect(peer.messages).toEqual([...messages, held, future]);
  expect(spies.map((spy) => spy.mock.calls.length)).toEqual([counts[0]! + 2, counts[1]! + 2, counts[2], counts[3]]);
  for (const artifact of [held, future]) {
    expect(peer.chains.classify(artifact).status).toBe("duplicate");
    expect(peer.chains.readRange(artifact.envelope.from, artifact.envelope.seq, artifact.envelope.seq)).toEqual({ status: "complete", envelopes: [artifact] });
  }
  expect(await databaseContents(peer.options)).toEqual({
    ...stored,
    [TRANSCRIPTS_STORE]: [...stored[TRANSCRIPTS_STORE]!, ...[held, future].map(({ envelope, canonicalBytes }, index) => ({
      arrival: messages.length + index + 1, game: bytesToHex(f.gameId), sender: bytesToHex(envelope.from),
      seq: envelope.seq, bytes: canonicalBytes, authored: false,
    }))],
  });
}

function expectPeers(f: Fixture, peers: readonly Peer[], reference?: SaskuHandController): void {
  const snapshot = peers[0]!.game.snapshot;
  for (const peer of peers) {
    expect(peer.game.snapshot).toEqual(snapshot);
    expect(peer.chains.heads()).toEqual(peers[0]!.chains.heads());
    for (const receiver of [peer.game, peer.inbox]) {
      expect(receiver.failure).toBeNull();
      expect(receiver.closed).toBe(false);
      expect(receiver.pendingEnvelopes).toBe(0);
      expect(receiver.pendingBytes).toBe(0);
    }
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
