import {
  bytesEqual, bytesToHex, deriveEd25519PublicKey, importEd25519SecretKey, scalarFromBigInt, type RandomSource,
} from "@p2pcards/crypto";
import { createGameKeyShare } from "@p2pcards/deck";
import {
  decodeAndVerifyEnvelope, parseGameId, parseIdentityPublicKey, parseRandomSecret,
  type EnvelopeArtifact, type GameId, type IdentityPublicKey,
} from "@p2pcards/protocol";
import {
  AuthoredEnvelopeStoreError, PersistentEnvelopeAuthor, PersistentSessionReceiver, SessionChainRegistry,
  type AcceptedEnvelopePersistenceOutcome, type AcceptedEnvelopeStore, type AuthoredEnvelopeStore,
} from "@p2pcards/session";

import { PersistentSetupReceiver, type PersistentSetupReceiverOptions } from "./persistent-setup-receiver";

export function persistentSetupFixture(input: {
  seats?: number; selfSeat?: number;
} & Partial<Pick<PersistentSetupReceiverOptions, "round" | "maxPendingEnvelopes" | "maxPendingBytes" | "historyLimits">> = {}) {
  const { seats = 3, selfSeat = 0, round = 3, ...limits } = input;
  const gameId = parseGameId(new Uint8Array(16).fill(0x41));
  const identities = Array.from({ length: seats + 1 }, (_, seat) => {
    const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(71 + seat));
    return { secretKey, publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)) };
  });
  const roster = identities.slice(0, seats).map(({ publicKey }) => publicKey);
  const self = roster[selfSeat]!;
  const keys = roster.map((_, seat) => scalarFromBigInt(BigInt(seat + 1)));
  const source = deterministicSource();
  const shares = keys.map((key) => createGameKeyShare({ gameId, round, phase: "setup.keys" }, key, source));
  const beaconSecrets = roster.map((_, seat) => parseRandomSecret(new Uint8Array(32).fill(seat + 1)));
  const store = new MemoryStore();
  // Only the local native author writes this store's authored history; received originals never promote it.
  const authors = roster.map((_, seat) => new PersistentEnvelopeAuthor(
    gameId, identities[seat]!.secretKey, seat === selfSeat ? store : new MemoryStore(),
  ));
  const registry = new SessionChainRegistry(gameId, roster);
  const durable = new PersistentSessionReceiver(registry, store);
  const options: PersistentSetupReceiverOptions = { round, self, session: registry, sessionReceiver: durable, ...limits };
  const receiver = new PersistentSetupReceiver(options);
  return { gameId, round, identities, roster, self, selfSeat, keys, shares, beaconSecrets, source,
    store, registry, durable, options, receiver, authors, author: authors[selfSeat]! };
}

export class MemoryStore implements AuthoredEnvelopeStore, AcceptedEnvelopeStore {
  readonly #heads = new Map<string, EnvelopeArtifact>();
  readonly #records = new Map<string, { readonly artifact: EnvelopeArtifact; readonly authored: boolean }>();

  async readAuthoredHead(game: GameId, sender: IdentityPublicKey): Promise<EnvelopeArtifact | null> {
    const head = this.#heads.get(`${bytesToHex(game)}:${bytesToHex(sender)}`);
    return head === undefined ? null : decodeAndVerifyEnvelope(head.canonicalBytes);
  }

  artifacts(): readonly { readonly artifact: EnvelopeArtifact; readonly authored: boolean }[] {
    return Object.freeze([...this.#records.values()].map(({ artifact, authored }) =>
      Object.freeze({ artifact: decodeAndVerifyEnvelope(artifact.canonicalBytes), authored })));
  }

  async appendNext(game: GameId, sender: IdentityPublicKey, create: (head: EnvelopeArtifact | null) => EnvelopeArtifact): Promise<void> {
    const scope = `${bytesToHex(game)}:${bytesToHex(sender)}`;
    const head = this.#heads.get(scope);
    const artifact = decodeAndVerifyEnvelope(create(head === undefined ? null : decodeAndVerifyEnvelope(head.canonicalBytes)).canonicalBytes);
    const key = `${scope}:${artifact.envelope.seq}`;
    if (!bytesEqual(artifact.envelope.game, game) || !bytesEqual(artifact.envelope.from, sender) ||
        artifact.envelope.seq !== (head?.envelope.seq ?? -1) + 1 ||
        !bytesEqual(artifact.envelope.prev, head?.hash ?? new Uint8Array(32)) || this.#records.has(key)) {
      throw new AuthoredEnvelopeStoreError("Invalid test-store append");
    }
    const checkpoint = decodeAndVerifyEnvelope(artifact.canonicalBytes);
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
    this.#records.set(key, { artifact: decodeAndVerifyEnvelope(received.canonicalBytes), authored: false });
    return { status: "stored", record: { artifact: received } };
  }
}

export function deterministicSource(start = 81n): RandomSource {
  let next = start;
  return { fill(target) {
    let value = next++;
    for (let index = 0; index < target.length; index += 1) {
      target[index] = Number(value & 0xffn);
      value >>= 8n;
    }
  } };
}

export function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}
