import { deriveEd25519PublicKey, importEd25519SecretKey } from "@p2pcards/crypto";
import { decodeEquivocationViolationBody, parseGameId, parseHash256, parseIdentityPublicKey, signEnvelope } from "@p2pcards/protocol";
import { PersistentEnvelopeAuthor, recoverSessionChains, SessionChainRegistry } from "@p2pcards/session";
import { IndexedDbAuthoredEnvelopeStore, IndexedDbSessionStore } from "@p2pcards/storage";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { expect, it, vi } from "vitest";

import { LiveRound } from "./live-round";

it("records and publishes signed equivocation evidence and keeps the table ended after reload", async () => {
  const secrets = [1, 2, 3, 4].map(fill => importEd25519SecretKey(new Uint8Array(32).fill(fill)));
  const seats = secrets.map(secret => parseIdentityPublicKey(deriveEd25519PublicKey(secret)));
  const gameId = parseGameId(new Uint8Array(16));
  const zero = parseHash256(new Uint8Array(32));
  const roster = { gameId, seats, rulesHash: zero, iceConfigHash: zero };
  const self = seats[0]!;
  const storage = { factory: new IDBFactory(), keyRange: IDBKeyRange, databaseName: "live-equivocation" };
  const authored = new IndexedDbAuthoredEnvelopeStore(storage);
  const stored = new IndexedDbSessionStore(storage);
  const author = new PersistentEnvelopeAuthor(gameId, secrets[0]!, authored);
  const session = new SessionChainRegistry(gameId, seats);
  const published = vi.fn();
  const options = { roster, self, author, stored, storage, changed: () => undefined, published };
  let live: LiveRound | undefined;

  try {
    await author.author({ type: "ROSTER", round: 0, phase: "lobby", body: {} }).then(artifact => session.ingest(artifact));
    const remote = { v: 1, game: gameId, from: seats[1]!, seq: 0, prev: zero, type: "JOIN", round: 0, phase: "lobby" } as const;
    const left = signEnvelope({ ...remote, body: { client: "one" } }, secrets[1]!);
    const right = signEnvelope({ ...remote, body: { client: "two" } }, secrets[1]!);
    await stored.persistAcceptedEnvelope(left);
    expect(session.ingest(left).status).toBe("accepted");
    live = new LiveRound({ ...options, session, restoredViolations: [] });

    live.reportEquivocation(left, right);
    await vi.waitFor(() => expect(published).toHaveBeenCalledTimes(1));
    const records = (await stored.loadTranscript(gameId)).map(({ artifact }) => artifact);
    const evidence = records.find(({ envelope }) => envelope.type === "VIOLATION")!;
    expect(evidence.envelope).toMatchObject({ from: self, seq: 1, phase: "control.equivocation" });
    const decoded = decodeEquivocationViolationBody(evidence.envelope.body);
    expect(decoded.seat).toBe(1);
    expect(decoded.evidence).toEqual(expect.arrayContaining([left, right]));
    expect(live.view.error).toContain("Player 2 signed conflicting history");
    await live.close();

    const restored = recoverSessionChains(gameId, seats, records).registry;
    live = new LiveRound({ ...options, session: restored, restoredViolations: [evidence] });
    await vi.waitFor(() => expect(live?.view.error).toContain("Player 2 signed conflicting history"));
    expect(published).toHaveBeenCalledTimes(1);
  } finally {
    await live?.close();
    await Promise.all([authored.close(), stored.close()]);
  }
});
