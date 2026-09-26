import { deriveEd25519PublicKey, importEd25519SecretKey, scalarFromBigInt, type RandomSource } from "@p2pcards/crypto";
import {
  CardPointTable, createGameKeyShare, createProvenDecryptionShare, encodeActionBody, encodeGameKeyShareBody,
  encodeSharesBody, maskCard, type DeckSpec,
} from "@p2pcards/deck";
import type { CborValue } from "@p2pcards/encoding";
import {
  beaconCommitment, encodeRandCommitBody, encodeRandRevealBody, parseGameId, parseHash256, parseIdentityPublicKey,
  parseRandomSecret, signEnvelope, type EnvelopeArtifact, type EnvelopeMessageType, type Hash256, type UnsignedEnvelope,
} from "@p2pcards/protocol";

import { RoundRevealLedger, type PrivateDealStep, type RoundRevealOptions } from "./round-reveal-ledger";
import { SetupEnvelopeCoordinator } from "./setup-envelope-coordinator";

/** Deterministic test ciphertexts and explicit test dealing, never a verified shuffle or production policy. */
export function roundRevealFixture(input: {
  seats?: number; deckSpec?: DeckSpec; schedule?: readonly PrivateDealStep[]; maxActions?: number; round?: number;
  beaconRequired?: boolean; batchDeal?: boolean;
} = {}) {
  const seats = input.seats ?? 3;
  const gameId = parseGameId(new Uint8Array(16).fill(0x61));
  const round = input.round ?? 2;
  const identities = Array.from({ length: seats + 1 }, (_, seat) => {
    const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(81 + seat));
    return { secretKey, publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)) };
  });
  const roster = identities.slice(0, seats).map(({ publicKey }) => publicKey);
  const secrets = Array.from({ length: seats }, (_, seat) => scalarFromBigInt(BigInt(seat + 1)));
  const heads: Array<{ seq: number; hash: Hash256 } | undefined> = [];
  let nonce = 100n;
  const source: RandomSource = {
    fill(bytes) {
      let value = nonce++;
      for (let index = 0; index < bytes.length; index += 1) {
        bytes[index] = Number(value & 0xffn); value >>= 8n;
      }
    },
  };
  const sign = (actor: number, type: EnvelopeMessageType, phase: string, body: CborValue, overrides: Partial<UnsignedEnvelope> = {}) => {
    const identity = identities[actor]!;
    const head = heads[actor];
    const artifact = signEnvelope({
      v: 1, game: gameId, from: identity.publicKey, seq: (head?.seq ?? -1) + 1,
      prev: head?.hash ?? parseHash256(new Uint8Array(32)), round, phase, type, body, ...overrides,
    }, identity.secretKey);
    heads[actor] = { seq: artifact.envelope.seq, hash: parseHash256(artifact.hash) };
    return artifact;
  };
  const setup = new SetupEnvelopeCoordinator(gameId, 0, roster, input.beaconRequired);
  const setupEnvelopes: EnvelopeArtifact[] = [];
  const acceptSetup = (artifact: EnvelopeArtifact) => {
    if (setup.ingest(artifact).status !== "accepted") { throw new Error("Invalid test setup"); }
    setupEnvelopes.push(artifact);
  };
  for (let seat = 0; seat < seats; seat += 1) {
    const key = createGameKeyShare({ gameId, round: 0, phase: "setup.keys" }, secrets[seat]!, source);
    acceptSetup(sign(seat, "KEY_SHARE", "setup.keys", encodeGameKeyShareBody(key), { round: 0 }));
  }
  if (input.beaconRequired !== false) {
    const beaconSecrets = roster.map((_, seat) => parseRandomSecret(new Uint8Array(32).fill(seat + 1)));
    for (let seat = 0; seat < seats; seat += 1) {
      const cm = parseHash256(beaconCommitment(gameId, 0, seat, beaconSecrets[seat]!));
      acceptSetup(sign(seat, "RAND_COMMIT", "setup.rand", encodeRandCommitBody({ cm }), { round: 0 }));
    }
    for (let seat = 0; seat < seats; seat += 1) {
      acceptSetup(sign(seat, "RAND_REVEAL", "setup.rand", encodeRandRevealBody({ s: beaconSecrets[seat]! }), { round: 0 }));
    }
  }
  const deckSpec = input.deckSpec ?? { id: "round-reveal-test/v1", cards: ["card-a", "card-b", "card-c", "card-d"] };
  const table = new CardPointTable(deckSpec);
  const cards = Array.from({ length: table.size }, (_, pos) => table.cardIdAt((pos + 1) % table.size));
  const deck = Array.from({ length: table.size }, (_, pos) =>
    maskCard(table.pointAt((pos + 1) % table.size), scalarFromBigInt(BigInt(pos + 10)), setup.aggregateKey!));
  const schedule = input.schedule ?? [{ to: 0, count: 2 }, { to: 1, count: 1 }];
  let cursor = 0;
  const plans = schedule.map(({ to, count }) => ({ to, positions: Array.from({ length: count }, () => cursor++) }));
  const options: RoundRevealOptions = { setup, round, deckSpec, deck, schedule, maxActions: input.maxActions ?? 64,
    ...(input.batchDeal === undefined ? {} : { batchDeal: input.batchDeal }) };
  const deal = (index: number, actor: number) => {
    const plan = plans[index]!;
    const phase = `round.${round}.deal.${index}`;
    const items = plan.positions.map((pos) => ({
      pos, ...createProvenDecryptionShare({ gameId, round, phase }, pos, secrets[actor]!, deck[pos]!.A, source),
    }));
    return sign(actor, "SHARES", phase, encodeSharesBody({ to: plan.to, items }));
  };
  const dealAll = (actor: number) => {
    const phase = `round.${round}.deal.0`;
    const items = plans.flatMap((plan) => plan.to === actor ? [] : plan.positions.map((pos) => ({
      pos, ...createProvenDecryptionShare({ gameId, round, phase }, pos, secrets[actor]!, deck[pos]!.A, source),
    })));
    return sign(actor, "SHARES", phase, encodeSharesBody({ to: 4, items }));
  };
  const action = (actor: number, positions: readonly number[], index = 0, kind = "play", data: CborValue = {}) => {
    const phase = `round.${round}.play.${index}`;
    const shares = positions.map((pos) => ({
      pos, ...createProvenDecryptionShare({ gameId, round, phase }, pos, secrets[actor]!, (deck[pos] ?? deck[0])!.A, source),
    }));
    return sign(actor, "ACTION", phase, encodeActionBody({ kind, data, reveal: positions, shares }));
  };
  return { gameId, round, identities, roster, secrets, source, setup, setupEnvelopes, table, deck, cards, plans,
    options, ledger: new RoundRevealLedger(options), sign, deal, dealAll, action };
}
