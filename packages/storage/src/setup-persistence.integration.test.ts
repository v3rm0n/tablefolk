import {
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  scalarFromBigInt,
  sha256,
  type Ed25519SecretKey,
  type RandomSource,
} from "@p2pcards/crypto";
import { createGameKeyShare, encodeGameKeyShareBody } from "@p2pcards/deck";
import {
  PersistentSetupReceiver,
  recoverSetup,
} from "@p2pcards/engine";
import {
  beaconCommitment,
  encodeRandCommitBody,
  encodeRandRevealBody,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  parseRandomSecret,
  signEnvelope,
  type EnvelopeArtifact,
  type Hash256,
  type IdentityPublicKey,
  type ProofContext,
} from "@p2pcards/protocol";
import {
  PersistentSessionReceiver,
  SessionChainRegistry,
  recoverSessionChains,
} from "@p2pcards/session";
import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it } from "vitest";

import { IndexedDbSessionStore } from "./indexeddb-session-store";

interface TestIdentity {
  readonly secretKey: Ed25519SecretKey;
  readonly publicKey: IdentityPublicKey;
}

const ALICE = identity(101);
const BOB = identity(102);
const CAROL = identity(103);
const AUTHORS = [ALICE, BOB, CAROL] as const;
const ROSTER = [ALICE.publicKey, BOB.publicKey, CAROL.publicKey] as const;
const GAME_ID = parseGameId(new Uint8Array(16).fill(0x31));
const ROUND = 5;
const ZERO_HASH = parseHash256(new Uint8Array(32));
const KEY_CONTEXT: ProofContext = {
  gameId: GAME_ID,
  round: ROUND,
  phase: "setup.keys",
};
const KEY_SHARES = [7n, 8n, 9n].map((secret, seat) =>
  createGameKeyShare(KEY_CONTEXT, scalarFromBigInt(secret), scalarSource(seat + 111)),
);
const SECRETS = [12, 13, 14].map((fill) =>
  parseRandomSecret(new Uint8Array(32).fill(fill)),
);
const COMMITMENTS = SECRETS.map((secret, seat) =>
  parseHash256(beaconCommitment(GAME_ID, ROUND, seat, secret)),
);

describe("durable setup integration", () => {
  it("reproduces live setup chains and state from IndexedDB after restart", async () => {
    const factory = new IDBFactory();
    const databaseName = "setup-restart-integration";
    const store = new IndexedDbSessionStore({ factory, databaseName });
    const liveChains = new SessionChainRegistry(GAME_ID, ROSTER);
    const chainReceiver = new PersistentSessionReceiver(liveChains, store);
    const receiver = new PersistentSetupReceiver({
      round: ROUND, self: ALICE.publicKey, session: liveChains, sessionReceiver: chainReceiver,
    });
    const artifacts = setupArtifacts();

    for (const index of [2, 0, 1, 4, 5, 3, 8, 6, 7]) {
      await expect(receiver.receive(artifacts[index]!)).resolves.toMatchObject({
        status: "accepted",
      });
    }
    const liveSetup = receiver.getCompletedSetup();
    expect(liveSetup.state).toBe("complete");
    expect(liveSetup.seed).toEqual(sha256(...SECRETS));
    expect(liveChains.heads()).toEqual([
      expect.objectContaining({ from: ALICE.publicKey, seq: 2 }),
      expect.objectContaining({ from: BOB.publicKey, seq: 2 }),
      expect.objectContaining({ from: CAROL.publicKey, seq: 2 }),
    ]);
    await store.close();

    const resumed = new IndexedDbSessionStore({ factory, databaseName });
    const records = await resumed.loadTranscript(GAME_ID);
    const transcript = records.map(({ artifact }) => artifact);
    const recoveredChains = recoverSessionChains(GAME_ID, ROSTER, transcript);
    const recoveredSetup = recoverSetup(GAME_ID, ROUND, ROSTER, transcript);

    expect(records).toHaveLength(9);
    expect(recoveredChains.registry.heads()).toEqual(liveChains.heads());
    expect(recoveredSetup.setupEnvelopeCount).toBe(9);
    expect(recoveredSetup.coordinator.state).toBe("complete");
    expect(recoveredSetup.coordinator.seed).toEqual(liveSetup.seed);
    await resumed.close();
  });
});

function setupArtifacts(): EnvelopeArtifact[] {
  const keys = AUTHORS.map((author, seat) =>
    signEnvelope(
      {
        v: 1,
        game: GAME_ID,
        from: author.publicKey,
        seq: 0,
        prev: ZERO_HASH,
        round: ROUND,
        phase: "setup.keys",
        type: "KEY_SHARE",
        body: encodeGameKeyShareBody(KEY_SHARES[seat]!),
      },
      author.secretKey,
    ),
  );
  const commits = AUTHORS.map((author, seat) =>
    setupBeaconEnvelope(
      author,
      1,
      keys[seat]!.hash,
      "RAND_COMMIT",
      encodeRandCommitBody({ cm: COMMITMENTS[seat]! }),
    ),
  );
  const reveals = AUTHORS.map((author, seat) =>
    setupBeaconEnvelope(
      author,
      2,
      commits[seat]!.hash,
      "RAND_REVEAL",
      encodeRandRevealBody({ s: SECRETS[seat]! }),
    ),
  );
  return [...keys, ...commits, ...reveals];
}

function setupBeaconEnvelope(
  author: TestIdentity,
  seq: number,
  prev: Hash256,
  type: "RAND_COMMIT" | "RAND_REVEAL",
  body: ReturnType<typeof encodeRandCommitBody> | ReturnType<typeof encodeRandRevealBody>,
): EnvelopeArtifact {
  return signEnvelope(
    {
      v: 1,
      game: GAME_ID,
      from: author.publicKey,
      seq,
      prev,
      round: ROUND,
      phase: "setup.rand",
      type,
      body,
    },
    author.secretKey,
  );
}

function identity(fill: number): TestIdentity {
  const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(fill));
  return {
    secretKey,
    publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)),
  };
}

function scalarSource(value: number): RandomSource {
  return {
    fill(target) {
      target.fill(0);
      target[0] = value;
    },
  };
}
