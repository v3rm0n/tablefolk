import { CandidateSaskuRoundOwner } from "../../packages/game-sasku/src/candidate-round-owner.ts";
import { recoverCandidateShuffledSaskuRound } from "../../packages/game-sasku/src/candidate-shuffled-round.ts";
import { legalSaskuCards } from "../../packages/rules-sasku/src/index.ts";
import { PersistentCandidateShuffleReceiver } from "../../packages/engine/src/persistent-candidate-shuffle.ts";
import { PersistentSessionReceiver, PersistentEnvelopeAuthor, SessionChainRegistry, recoverSessionChains } from "../../packages/session/src/index.ts";
import { IndexedDbSessionStore } from "../../packages/storage/src/indexeddb-session-store.ts";
import { IndexedDbAuthoredEnvelopeStore } from "../../packages/storage/src/indexeddb-envelope-store.ts";
import { CandidateShuffleClient } from "../../apps/web/src/candidate-shuffle-client.ts";
import { CandidateShuffleLedger } from "../../packages/engine/src/candidate-shuffle-ledger.ts";
import { roundRevealFixture } from "../../packages/engine/src/round-reveal.test-fixture.ts";
import { SASKU_DECK_SPEC } from "../../packages/rules-sasku/src/index.ts";
import { encodeCandidateShuffleProof36 } from "../../packages/deck/src/index.ts";
import { parseHash256, encodeSyncRequestBody, encodeSyncResponseBody } from "../../packages/protocol/src/index.ts";
globalThis.runWebShuffleChecks = async () => {
    const f = roundRevealFixture({ seats: 4, deckSpec: SASKU_DECK_SPEC });
    const client = new CandidateShuffleClient();
    const ledger = new CandidateShuffleLedger({ setup: f.setup, round: f.round, deckSpec: SASKU_DECK_SPEC, verifier: client,
      roster: { gameId: f.gameId, seats: f.roster, rulesHash: parseHash256(new Uint8Array(32)), iceConfigHash: parseHash256(new Uint8Array(32)) } });
    const accepted = [];
    let invalidRejected = false;
    try {
      const pending = client.prove(ledger.nextStatement()); client.cancel();
      let cancelled = false; try { await pending; } catch { cancelled = true; }
      for (let seat = 0; seat < 4; seat++) {
        const result = await client.prove(ledger.nextStatement());
        if (seat === 0) {
          const invalid = f.sign(seat, "SHUFFLE", `round.${f.round}.shuffle.${seat}`, {
            statement: result.statement,
            proof: encodeCandidateShuffleProof36(Array.from({ length: 106 }, () => new Uint8Array(32))),
          });
          try { await ledger.accept(invalid.canonicalBytes); } catch { invalidRejected = ledger.nextSeat === 0; }
          if (!invalidRejected) throw new Error("Invalid proof advanced the shuffle ledger");
        }
        const artifact = f.sign(seat, "SHUFFLE", `round.${f.round}.shuffle.${seat}`, result);
        accepted.push(await ledger.accept(artifact.canonicalBytes));
        if (await ledger.accept(artifact.canonicalBytes) !== "duplicate") throw new Error("Replay handling failed");
      }
      return { cancelled, invalidRejected, accepted, complete: ledger.complete, deckSize: ledger.finalDeck.length, durable: await durableChecks(client) };
    } finally { client.close(); ledger.close(); }
};

async function durableChecks(client) {
  const f = roundRevealFixture({ seats: 4, deckSpec: SASKU_DECK_SPEC });
  const databaseName = `candidate-shuffle-${crypto.randomUUID()}`;
  let store = new IndexedDbSessionStore({ databaseName });
  const authored = new IndexedDbAuthoredEnvelopeStore({ databaseName });
  let session = new SessionChainRegistry(f.gameId, f.roster), durable = new PersistentSessionReceiver(session, store);
  const options = { roster: { gameId: f.gameId, seats: f.roster, rulesHash: parseHash256(new Uint8Array(32)), iceConfigHash: parseHash256(new Uint8Array(32)) },
    self: f.roster[0], setupRound: 0, round: f.round, deckSpec: SASKU_DECK_SPEC, verifier: client };
  let receiver;
  const recoveredSeats = [];
  try {
    for (const artifact of f.setupEnvelopes) {
      // This isolated harness emulates all four native authors in one database.
      await authored.appendNext(f.gameId, artifact.envelope.from, () => artifact);
      await durable.receive(artifact);
    }
    receiver = await PersistentCandidateShuffleReceiver.open({ ...options, session, sessionReceiver: durable });
    const author = new PersistentEnvelopeAuthor(f.gameId, f.identities[0].secretKey, authored);
    for (let seat = 0; seat < 4; seat++) {
      const prepared = await client.prove(receiver.nextStatement());
      let result;
      if (seat === 0) result = await receiver.author(author, prepared, receiver.snapshot);
      else {
        const artifact = f.sign(seat, "SHUFFLE", `round.${f.round}.shuffle.${seat}`, prepared);
        await authored.appendNext(f.gameId, f.roster[seat], () => artifact);
        result = await receiver.receive(artifact);
      }
      if (result.status !== "accepted") throw new Error("Durable contribution failed");
      const before = receiver.snapshot;
      receiver.close(); await store.close();
      store = new IndexedDbSessionStore({ databaseName });
      const records = await store.loadTranscript(f.gameId);
      if (records.length !== 13 + seat) throw new Error("Unexpected durable transcript length");
      session = recoverSessionChains(f.gameId, f.roster, records.map(r => r.artifact).reverse()).registry;
      durable = new PersistentSessionReceiver(session, store);
      receiver = await PersistentCandidateShuffleReceiver.open({ ...options, session, sessionReceiver: durable });
      if (receiver.snapshot.nextSeat !== before.nextSeat || receiver.snapshot.complete !== before.complete) throw new Error("Recovered shuffle state differs");
      if ((await receiver.receive(result.received)).status !== "duplicate") throw new Error("Recovered receipt is not idempotent");
      if ((await store.loadTranscript(f.gameId)).length !== records.length) throw new Error("Recovery rewrote transcript");
      recoveredSeats.push(receiver.snapshot.nextSeat);
    }
    const result = { recoveredSeats, complete: receiver.snapshot.complete, deckSize: receiver.finalDeck.length, authoredSequence: (await author.readHead()).envelope.seq };
    receiver.close();
    const roundOptions = { ...options, session, sessionReceiver: durable, dealer: 3,
      schedule: [0, 1, 2, 3].map(to => ({ to, count: 9 })) };
    const authors = f.identities.slice(0, 4).map(i => new PersistentEnvelopeAuthor(f.gameId, i.secretKey, authored));
    let game = await recoverCandidateShuffledSaskuRound(roundOptions);
    const receive = async promise => { if ((await promise).status !== "accepted") throw new Error("Round contribution rejected"); };
    try {
      while (game.snapshot.ledger.deal !== null) {
        for (const seat of game.snapshot.ledger.deal.pendingSenders) {
          await receive(game.authorDealShares(authors[seat], f.secrets[seat], game.snapshot));
        }
      }
      const hands = f.roster.map((id, seat) => game.readPrivateHand(id, f.secrets[seat]));
      const cards = hands.flatMap(h => Object.values(h.dealt));
      if (cards.length !== 36 || new Set(cards).size !== 36) throw new Error("Invalid private deal");
      game.close();
      game = await recoverCandidateShuffledSaskuRound(roundOptions);
      for (let seat = 0; seat < 4; seat++) {
        if (JSON.stringify(game.readPrivateHand(f.roster[seat], f.secrets[seat])) !== JSON.stringify(hands[seat])) throw new Error("Private hand recovery differs");
      }
      await receive(game.authorAction(authors[0], f.secrets[0], game.snapshot, { type: "diamonds" }));
      for (let play = 0; play < 36; play++) {
        const seat = game.snapshot.hand.turn;
        const hand = game.readPrivateHand(f.roster[seat], f.secrets[seat]);
        const card = legalSaskuCards(Object.values(hand.remaining), game.snapshot.hand.trick, "diamonds")[0];
        const position = Number(Object.keys(hand.remaining).find(pos => hand.remaining[pos] === card));
        await receive(game.authorAction(authors[seat], f.secrets[seat], game.snapshot, { type: "play", position }));
      }
      for (let seat = 0; seat < 4; seat++) await receive(game.authorAuditDisclose(authors[seat], game.snapshot));
      if (game.snapshot.audit.result.status !== "valid") throw new Error("Invalid hand audit");
      const completed = JSON.stringify(game.snapshot);
      game.close(); await store.close();
      store = new IndexedDbSessionStore({ databaseName });
      const records = await store.loadTranscript(f.gameId);
      session = recoverSessionChains(f.gameId, f.roster, records.map(r => r.artifact).reverse()).registry;
      durable = new PersistentSessionReceiver(session, store);
      game = await recoverCandidateShuffledSaskuRound({ ...roundOptions, session, sessionReceiver: durable });
      if (JSON.stringify(game.snapshot) !== completed) throw new Error("Completed hand recovery differs");
      game.close();
      const controlOwner = await CandidateSaskuRoundOwner.open({ ...roundOptions, session, sessionReceiver: durable });
      try {
        const requestBody = { from: f.roster[1], fromSeq: 3, toSeq: 3 };
        const outgoing = await controlOwner.authorSyncRequest(authors[0], requestBody);
        if (outgoing.status !== "accepted") throw new Error("Owned request authoring failed");
        const incoming = await authors[2].author({ type: "SYNC_REQ", round: f.round, phase: "control.sync", body: encodeSyncRequestBody(requestBody) });
        await controlOwner.receiveSyncRequest(f.roster[2], incoming.canonicalBytes);
        const served = await controlOwner.authorSyncResponse(authors[0], f.roster[2], incoming);
        if (served.status !== "accepted" || served.received.envelope.seq !== outgoing.received.envelope.seq + 1) throw new Error("Owned response authoring failed");
      } finally { controlOwner.close(); }
      const coordinated = await replayWithOwner(f, options, client, records, completed, authors[3]);
      return { ...result, hand: { privateHandSizes: hands.map(h => Object.keys(h.dealt).length), plays: 36, audit: game.snapshot.audit.result.status, recovered: true }, coordinated };
    } finally { game.close(); }
  } finally {
    receiver?.close(); await store.close(); await authored.close();
    await new Promise((resolve, reject) => { const request = indexedDB.deleteDatabase(databaseName); request.onsuccess = resolve; request.onerror = () => reject(request.error); });
  }
}

async function replayWithOwner(f, options, client, records, completed, remoteAuthor) {
  const databaseName = `candidate-owner-${crypto.randomUUID()}`;
  const store = new IndexedDbSessionStore({ databaseName });
  const session = new SessionChainRegistry(f.gameId, f.roster);
  const durable = new PersistentSessionReceiver(session, store);
  let owner;
  try {
    for (const artifact of f.setupEnvelopes) await durable.receive(artifact);
    owner = await CandidateSaskuRoundOwner.open({ ...options, session, sessionReceiver: durable,
      verifier: client, dealer: 3, schedule: [0, 1, 2, 3].map(to => ({ to, count: 9 })), maxPendingEnvelopes: 128 });
    const traffic = records.map(r => r.artifact).filter(a => ["SHUFFLE", "SHARES", "ACTION", "AUDIT_DISCLOSE"].includes(a.envelope.type)).reverse();
    const results = await Promise.all(traffic.map(a => owner.receiveHistory(a)));
    await owner.whenIdle();
    if (results.some(r => r.status !== "accepted") || owner.snapshot.phase !== "round" || JSON.stringify(owner.snapshot.state) !== completed) throw new Error("Coordinated replay differs");
    if (owner.pendingBytes !== 0 || owner.pendingEnvelopes !== 0) throw new Error("Owner retained pending work");
    const original = records.map(r => r.artifact).find(a => a.envelope.type === "SHUFFLE" && a.envelope.from.every((byte, i) => byte === f.roster[0][i]));
    const request = { from: f.roster[0], fromSeq: original.envelope.seq, toSeq: original.envelope.seq };
    const response = await remoteAuthor.author({ type: "SYNC_RESP", round: f.round, phase: "control.sync", body: encodeSyncResponseBody({ envelopes: [original] }) });
    const synced = await owner.receiveSyncResponse(f.roster[3], response.canonicalBytes, request);
    if (synced.status !== "range_received" || synced.outerStatus !== "accepted" || synced.receipts[0] !== "duplicate") throw new Error("Coordinated sync receipt failed");
    return { reverseHistoryEnvelopes: results.length, audit: owner.snapshot.state.audit.result.status, pending: owner.pendingEnvelopes, sync: synced.status };
  } finally {
    owner?.close(); await store.close();
    await new Promise((resolve, reject) => { const request = indexedDB.deleteDatabase(databaseName); request.onsuccess = resolve; request.onerror = () => reject(request.error); });
  }
}
