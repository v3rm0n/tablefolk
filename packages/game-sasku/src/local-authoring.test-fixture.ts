import { bytesEqual, bytesToHex, RistrettoPoint } from "@p2pcards/crypto";
import { decodeAndVerifyEnvelope, type EnvelopeArtifact, type GameId, type IdentityPublicKey } from "@p2pcards/protocol";
import { SASKU_DECK_SPEC, type SaskuSeat } from "@p2pcards/rules-sasku";
import {
  AuthoredEnvelopeStoreError, PersistentEnvelopeAuthor, PersistentSessionReceiver, SessionChainRegistry,
  type AcceptedEnvelopePersistenceOutcome, type AcceptedEnvelopeStore, type AuthoredEnvelopeStore,
} from "@p2pcards/session";
import { expect } from "vitest";

import { roundRevealFixture } from "../../engine/src/round-reveal.test-fixture";
import {
  PersistentSaskuRoundReceiver, type PersistentSaskuRoundOptions, type SaskuActionIntent, type SaskuRoundSnapshot,
} from "./persistent-round-receiver";

export async function context(overrides: Partial<PersistentSaskuRoundOptions> = {}, corruptPosition?: number, ready = true) {
  const f = roundRevealFixture({ seats: 4, deckSpec: SASKU_DECK_SPEC, schedule: [0, 1, 2, 3].map((to) => ({ to, count: 9 })) });
  // One store emulates all four native authors only in this deterministic test fixture.
  const store = new MemoryStore();
  const authors = f.roster.map((_, seat) => new PersistentEnvelopeAuthor(f.gameId, f.identities[seat]!.secretKey, store));
  const session = new SessionChainRegistry(f.gameId, f.roster);
  const durable = new PersistentSessionReceiver(session, store);
  const native = async (fixtureArtifact: EnvelopeArtifact) => {
    const { round, phase, type, body, from } = fixtureArtifact.envelope;
    const artifact = await authors[session.seatOf(from)!]!.author({ round, phase, type, body });
    expect(artifact.canonicalBytes).toEqual(fixtureArtifact.canonicalBytes);
    return artifact;
  };
  for (const artifact of f.setupEnvelopes) {
    await expect(durable.receive(await native(artifact))).resolves.toMatchObject({ status: "accepted", persistenceStatus: "duplicate" });
  }
  const options: PersistentSaskuRoundOptions = {
    setup: f.setup, round: f.round, schedule: f.options.schedule, dealer: 3, session, sessionReceiver: durable,
    deck: f.deck.map((card, position) => position === corruptPosition ? { ...card, B: card.B.add(RistrettoPoint.base()) } : card),
    ...overrides,
  };
  const game = new PersistentSaskuRoundReceiver(options);
  const deals: EnvelopeArtifact[] = [];
  if (ready) {
    for (let step = 0; step < f.plans.length; step += 1) {
      for (let seat = 0; seat < 4; seat += 1) {
        if (seat === f.plans[step]!.to) continue;
        const artifact = await native(f.deal(step, seat));
        await expect(game.receive(artifact)).resolves.toMatchObject({ status: "accepted", chainStatus: "accepted", persistenceStatus: "duplicate" });
        deals.push(artifact);
      }
    }
    expect(game.snapshot.ledger.deal).toBeNull();
  }
  const records = store.artifacts();
  expect(records).toHaveLength(ready ? 24 : 12);
  expect(records.every(({ authored }) => authored)).toBe(true);
  // Fixture signing heads are now obsolete: subsequent input always uses these native authors.
  return { f, store, authors, author: authors[0]!, session, durable, options, game, deals };
}

export function act(c: Awaited<ReturnType<typeof context>>, seat: SaskuSeat, intent: SaskuActionIntent, expected: SaskuRoundSnapshot = c.game.snapshot) {
  return c.game.authorAction(c.authors[seat]!, c.f.secrets[seat]!, expected, intent, c.f.source);
}

class MemoryStore implements AuthoredEnvelopeStore, AcceptedEnvelopeStore {
  readonly #heads = new Map<string, EnvelopeArtifact>();
  readonly #records = new Map<string, { readonly artifact: EnvelopeArtifact; readonly authored: boolean }>();

  head(game: GameId, sender: IdentityPublicKey): EnvelopeArtifact | null {
    const head = this.#heads.get(`${bytesToHex(game)}:${bytesToHex(sender)}`);
    return head === undefined ? null : decodeAndVerifyEnvelope(head.canonicalBytes);
  }

  artifacts(): readonly { readonly artifact: EnvelopeArtifact; readonly authored: boolean }[] {
    return Object.freeze([...this.#records.values()].map(({ artifact, authored }) =>
      Object.freeze({ artifact: decodeAndVerifyEnvelope(artifact.canonicalBytes), authored })));
  }

  async appendNext(game: GameId, sender: IdentityPublicKey, create: (head: EnvelopeArtifact | null) => EnvelopeArtifact): Promise<void> {
    const scope = `${bytesToHex(game)}:${bytesToHex(sender)}`;
    const head = this.head(game, sender);
    const artifact = decodeAndVerifyEnvelope(create(head).canonicalBytes);
    const key = `${scope}:${artifact.envelope.seq}`;
    if (!bytesEqual(artifact.envelope.game, game) || !bytesEqual(artifact.envelope.from, sender) ||
        artifact.envelope.seq !== (head?.envelope.seq ?? -1) + 1 ||
        !bytesEqual(artifact.envelope.prev, head?.hash ?? new Uint8Array(32)) || this.#records.has(key)) {
      throw new AuthoredEnvelopeStoreError("Invalid test-store append");
    }
    const checkpoint = decodeAndVerifyEnvelope(artifact.canonicalBytes);
    // All validation/copying precedes the two synchronous writes; callers never receive retained buffers.
    this.#records.set(key, { artifact, authored: true });
    this.#heads.set(scope, checkpoint);
  }

  async persistAcceptedEnvelope(candidate: EnvelopeArtifact): Promise<AcceptedEnvelopePersistenceOutcome> {
    const received = decodeAndVerifyEnvelope(candidate.canonicalBytes);
    const key = `${bytesToHex(received.envelope.game)}:${bytesToHex(received.envelope.from)}:${received.envelope.seq}`;
    const existing = this.#records.get(key);
    if (existing !== undefined) {
      const record = { artifact: decodeAndVerifyEnvelope(existing.artifact.canonicalBytes) };
      return bytesEqual(existing.artifact.canonicalBytes, received.canonicalBytes)
        ? { status: "duplicate", record }
        : { status: "conflict", existing: record, received };
    }
    const artifact = decodeAndVerifyEnvelope(received.canonicalBytes);
    this.#records.set(key, { artifact, authored: false });
    return { status: "stored", record: { artifact: received } };
  }
}

export function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}
