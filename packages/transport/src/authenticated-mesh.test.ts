import {
  bytesEqual,
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  type Ed25519SecretKey,
} from "@p2pcards/crypto";
import {
  decodeAndVerifyEnvelope,
  encodeSyncResponseBody,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  signEnvelope,
  type EnvelopeArtifact,
  type IdentityPublicKey,
} from "@p2pcards/protocol";
import {
  PersistentSessionReceiver,
  PersistentSyncReceiver,
  SessionChainRegistry,
  type AcceptedEnvelopeStore,
  type PersistentSyncReceiveResult,
} from "@p2pcards/session";
import { describe, expect, it, vi } from "vitest";

import {
  AuthenticatedMeshTransport,
  type AuthenticatedMeshTransportOptions,
  type PeerSynchronizationContext,
} from "./authenticated-mesh";
import type {
  MeshPeerConnection,
  MeshPeerConnectionFactory,
} from "./full-mesh";
import { InMemorySignalingNetwork } from "./signaling";

const ROOM = "34".repeat(32);
const GAME_ID = parseGameId(new Uint8Array(16).fill(0x44));
const ALICE = identity(21);
const BOB = identity(22);
const CAROL = identity(23);
const ROSTER = [ALICE.publicKey, BOB.publicKey, CAROL.publicKey] as const;
const ALICE_FINGERPRINT = fingerprintText(0x11);
const BOB_FINGERPRINT = fingerprintText(0x22);

describe("authenticated full-mesh facade", () => {
  it("exposes only authenticated peers and routes framed application payloads", async () => {
    const network = new InMemorySignalingNetwork();
    const aliceHarness = harness("alice", ALICE_FINGERPRINT);
    const bobHarness = harness("bob", BOB_FINGERPRINT);
    const aliceAuthenticated: IdentityPublicKey[] = [];
    const bobAuthenticated: IdentityPublicKey[] = [];
    const aliceMessages: Array<{ remote: IdentityPublicKey; payload: Uint8Array }> = [];
    const bobMessages: Array<{ remote: IdentityPublicKey; payload: Uint8Array }> = [];
    const alice = facade(
      network,
      ALICE,
      aliceHarness,
      aliceAuthenticated,
      aliceMessages,
    );
    const bob = facade(
      network,
      BOB,
      bobHarness,
      bobAuthenticated,
      bobMessages,
    );
    await Promise.all([alice.start(), bob.start()]);
    const aliceWire = aliceHarness.channel(BOB.publicKey);
    const bobWire = bobHarness.channel(ALICE.publicKey);
    aliceWire.link(bobWire);
    bobWire.link(aliceWire);

    await expect(alice.send(BOB.publicKey, new Uint8Array([1]))).rejects.toThrow(
      /authentication and synchronization/,
    );
    await alice.requestNegotiation(BOB.publicKey);
    await settleMeshes(alice, bob);
    expect(aliceAuthenticated).toEqual([]);
    expect(bobAuthenticated).toEqual([]);
    expect(alice.authenticatedPeers).toEqual([]);
    expect(bob.authenticatedPeers).toEqual([]);

    aliceWire.open();
    bobWire.open();
    await Promise.all([
      alice.readyFor(BOB.publicKey),
      bob.readyFor(ALICE.publicKey),
    ]);

    expect(aliceAuthenticated).toEqual([BOB.publicKey]);
    expect(bobAuthenticated).toEqual([ALICE.publicKey]);
    expect(alice.authenticatedPeers).toEqual([BOB.publicKey]);
    expect(bob.authenticatedPeers).toEqual([ALICE.publicKey]);
    expect(alice.readyPeers).toEqual([BOB.publicKey]);
    expect(bob.readyPeers).toEqual([ALICE.publicKey]);

    const payload = new Uint8Array([4, 5, 6]);
    const sending = alice.send(BOB.publicKey, payload);
    payload.fill(0xff);
    await sending;
    await settleMeshes(alice, bob);

    expect(aliceMessages).toEqual([]);
    expect(bobMessages).toEqual([
      { remote: ALICE.publicKey, payload: new Uint8Array([4, 5, 6]) },
    ]);
    expect(alice.failures).toEqual([]);
    expect(bob.failures).toEqual([]);

    await Promise.all([alice.close(), bob.close()]);
  });

  it("closes and reports a channel whose negotiated SDP lacks a fingerprint", async () => {
    const network = new InMemorySignalingNetwork();
    const aliceHarness = harness("alice", null);
    const bobHarness = harness("bob", BOB_FINGERPRINT);
    const alice = facade(network, ALICE, aliceHarness, [], []);
    const bob = facade(network, BOB, bobHarness, [], []);
    await Promise.all([alice.start(), bob.start()]);
    const aliceWire = aliceHarness.channel(BOB.publicKey);
    const bobWire = bobHarness.channel(ALICE.publicKey);
    aliceWire.link(bobWire);
    bobWire.link(aliceWire);
    await alice.requestNegotiation(BOB.publicKey);
    await settleMeshes(alice, bob);

    aliceWire.open();
    bobWire.open();
    await settleMeshes(alice, bob);

    expect(aliceWire.closed).toBe(true);
    expect(bobWire.closed).toBe(true);
    expect(
      [...alice.failures, ...bob.failures].some(({ error }) =>
        /fingerprint/i.test(error.message),
      ),
    ).toBe(true);
    expect(alice.authenticatedPeers).toEqual([]);
    expect(bob.authenticatedPeers).toEqual([]);

    await Promise.all([alice.close(), bob.close()]);
  });

  it("rejects an identity key that does not match the local signer", () => {
    const network = new InMemorySignalingNetwork();
    const aliceHarness = harness("alice", ALICE_FINGERPRINT);
    expect(
      () =>
        new AuthenticatedMeshTransport({
          roomId: ROOM,
          gameId: GAME_ID,
          self: BOB.publicKey,
          secretKey: ALICE.secretKey,
          roster: ROSTER,
          signaling: network.createAdapter(),
          createPeerConnection: aliceHarness.factory,
          synchronizePeer: async () => undefined,
          onMessage: () => undefined,
        }),
    ).toThrow(/does not match/);
  });

  it("requires a synchronizer instead of treating HELLO as session readiness", () => {
    expect(() => pair({
      synchronizePeer: undefined as unknown as AuthenticatedMeshTransportOptions["synchronizePeer"],
    })).toThrow(/explicit peer synchronizer/);
  });

  it("routes pre-ready traffic only through the synchronizer and gates application sends", async () => {
    const controlMessages: Uint8Array[] = [];
    const aliceSync = synchronizer();
    const bobSync = synchronizer((payload) => { controlMessages.push(payload); });
    const ready = vi.fn();
    const peers = pair(
      { synchronizePeer: aliceSync.run, onPeerReady: ready },
      { synchronizePeer: bobSync.run },
    );
    await peers.start();
    expect(peers.alice.authenticatedPeers).toEqual([BOB.publicKey]);
    expect(peers.alice.readyPeers).toEqual([]);
    expect(ready).not.toHaveBeenCalled();
    await expect(peers.alice.send(BOB.publicKey, new Uint8Array([1]))).rejects.toThrow(/synchronization/);

    const context = aliceSync.attempts[0]!.context;
    expect(context.generation).toBe(1);
    context.remote.fill(0xff);
    await context.send(new Uint8Array([7]));
    await settleMeshes(peers.alice, peers.bob);
    expect(controlMessages).toEqual([new Uint8Array([7])]);
    expect(peers.bobMessages).toEqual([]);

    aliceSync.attempts[0]!.done.resolve();
    bobSync.attempts[0]!.done.resolve();
    await Promise.all([peers.alice.readyFor(BOB.publicKey), peers.bob.readyFor(ALICE.publicKey)]);
    expect(ready).toHaveBeenCalledExactlyOnceWith(BOB.publicKey);
    await expect(context.send(new Uint8Array([8]))).rejects.toThrow(/no longer active/);
    expect(() => context.onMessage(() => undefined)).toThrow(/no longer active/);
    await peers.alice.send(BOB.publicKey, new Uint8Array([9]));
    await settleMeshes(peers.alice, peers.bob);
    expect(peers.bobMessages).toEqual([{ remote: ALICE.publicKey, payload: new Uint8Array([9]) }]);
    await peers.close();
  });

  it("waits for queued asynchronous synchronization receipts before becoming ready", async () => {
    const receiptStarted = deferred();
    const durableCommit = deferred();
    const aliceSync = synchronizer(async () => {
      receiptStarted.resolve();
      await durableCommit.promise;
    });
    const bobSync = synchronizer();
    const peers = pair({ synchronizePeer: aliceSync.run }, { synchronizePeer: bobSync.run });
    await peers.start();
    await bobSync.attempts[0]!.context.send(new Uint8Array([1]));
    await receiptStarted.promise;
    aliceSync.attempts[0]!.done.resolve();
    await Promise.resolve();
    expect(peers.alice.readyPeers).toEqual([]);
    await expect(peers.alice.send(BOB.publicKey, new Uint8Array([2]))).rejects.toThrow(/synchronization/);

    durableCommit.resolve();
    bobSync.attempts[0]!.done.resolve();
    await Promise.all([peers.alice.readyFor(BOB.publicKey), peers.bob.readyFor(ALICE.publicKey)]);
    expect(peers.aliceMessages).toEqual([]);
    expect(peers.alice.readyPeers).toEqual([BOB.publicKey]);
    await peers.close();
  });

  it("does not equate a durably received requested range with whole-session readiness", async () => {
    const chains = new SessionChainRegistry(GAME_ID, ROSTER);
    const records = new Map<string, EnvelopeArtifact>();
    const historyStarted = deferred();
    const durableCommit = deferred();
    const rangeReceived = deferred();
    const readinessDecision = deferred();
    const store: AcceptedEnvelopeStore = {
      async persistAcceptedEnvelope(artifact) {
        const received = decodeAndVerifyEnvelope(artifact.canonicalBytes);
        if (bytesEqual(received.envelope.from, CAROL.publicKey)) {
          historyStarted.resolve();
          await durableCommit.promise;
        }
        const key = `${identityKey(received.envelope.from)}:${received.envelope.seq}`;
        const existing = records.get(key);
        if (existing !== undefined) {
          return bytesEqual(existing.canonicalBytes, received.canonicalBytes)
            ? { status: "duplicate", record: { artifact: existing } }
            : { status: "conflict", existing: { artifact: existing }, received };
        }
        records.set(key, received);
        return { status: "stored", record: { artifact: received } };
      },
    };
    const controls = new PersistentSessionReceiver(chains, store);
    const ranges = new PersistentSyncReceiver(chains, controls, {
      receive: async (received) => {
        // Deliberately tiny transport-test semantics, not a production game dispatcher.
        if (received.envelope.type !== "ACTION" ||
            JSON.stringify(received.envelope.body) !== '{"fixture":true}') {
          return { status: "rejected", reason: "unsupported_history", received };
        }
        return controls.receive(received);
      },
    });
    const requested = { from: CAROL.publicKey, fromSeq: 0, toSeq: 0 };
    const bobSync = synchronizer();
    let result: PersistentSyncReceiveResult | undefined;
    const peers = pair({
      synchronizePeer: (context) => {
        context.onMessage(async (payload) => {
          result = await ranges.receiveResponse(decodeAndVerifyEnvelope(payload), requested, { signal: context.signal });
          if (result.status !== "range_received") {
            throw new Error("Requested history was not received");
          }
          rangeReceived.resolve();
        });
        return readinessDecision.promise;
      },
    }, { synchronizePeer: bobSync.run });
    await peers.start();
    const historical = signEnvelope({
      v: 1, game: GAME_ID, from: CAROL.publicKey, seq: 0, prev: parseHash256(new Uint8Array(32)),
      round: 1, phase: "play", type: "ACTION", body: { fixture: true },
    }, CAROL.secretKey);
    const outer = signEnvelope({
      v: 1, game: GAME_ID, from: BOB.publicKey, seq: 0, prev: parseHash256(new Uint8Array(32)),
      round: 1, phase: "play", type: "SYNC_RESP", body: encodeSyncResponseBody({ envelopes: [historical] }),
    }, BOB.secretKey);
    await bobSync.attempts[0]!.context.send(outer.canonicalBytes);
    await historyStarted.promise;
    expect(chains.readRange(CAROL.publicKey, 0, 0).status).toBe("missing");
    expect(peers.alice.readyPeers).toEqual([]);
    durableCommit.resolve();
    await rangeReceived.promise;
    expect(result).toMatchObject({ status: "range_received", outerStatus: "accepted", receipts: ["accepted"] });
    expect(chains.readRange(CAROL.publicKey, 0, 0).status).toBe("complete");
    expect(records.size).toBe(2);
    expect(peers.alice.readyPeers).toEqual([]);
    expect(peers.aliceMessages).toEqual([]);
    await expect(peers.alice.send(BOB.publicKey, new Uint8Array([1]))).rejects.toThrow(/synchronization/);
    readinessDecision.resolve();
    bobSync.attempts[0]!.done.resolve();
    await Promise.all([peers.alice.readyFor(BOB.publicKey), peers.bob.readyFor(ALICE.publicKey)]);
    await peers.close();
  });

  it("reconnects the same identity through fresh HELLO and synchronization without resetting other peers", async () => {
    const aliceSync = synchronizer();
    const bobSync = synchronizer();
    const disconnected = vi.fn();
    const peers = pair(
      { synchronizePeer: aliceSync.run, onPeerDisconnected: disconnected },
      { synchronizePeer: bobSync.run },
    );
    await peers.start();
    aliceSync.attempts[0]!.done.resolve();
    bobSync.attempts[0]!.done.resolve();
    await Promise.all([peers.alice.readyFor(BOB.publicKey), peers.bob.readyFor(ALICE.publicKey)]);
    const previousWire = peers.aliceHarness.channel(BOB.publicKey);
    const unaffected = peers.aliceHarness.connection(CAROL.publicKey);

    await peers.alice.reconnectPeer(BOB.publicKey);
    expect(aliceSync.attempts[0]!.context.signal.aborted).toBe(true);
    expect(bobSync.attempts[0]!.context.signal.aborted).toBe(true);
    expect(previousWire.closed).toBe(true);
    expect(disconnected).toHaveBeenCalledExactlyOnceWith(BOB.publicKey, 1);
    expect(peers.aliceHarness.connection(CAROL.publicKey)).toBe(unaffected);
    expect(peers.alice.readyPeers).toEqual([]);
    await peers.authenticate();
    expect(aliceSync.attempts.map(({ context }) => context.generation)).toEqual([1, 2]);
    expect(bobSync.attempts.map(({ context }) => context.generation)).toEqual([1, 2]);
    expect(peers.aliceHarness.channel(BOB.publicKey)).not.toBe(previousWire);
    expect(peers.alice.authenticatedPeers).toEqual([BOB.publicKey]);
    expect(peers.alice.readyPeers).toEqual([]);

    aliceSync.attempts[1]!.done.resolve();
    bobSync.attempts[1]!.done.resolve();
    await Promise.all([peers.alice.readyFor(BOB.publicKey), peers.bob.readyFor(ALICE.publicKey)]);
    await peers.alice.send(BOB.publicKey, new Uint8Array([5]));
    await settleMeshes(peers.alice, peers.bob);
    expect(peers.bobMessages).toEqual([{ remote: ALICE.publicKey, payload: new Uint8Array([5]) }]);
    await peers.close();
  });

  it("ignores stale synchronization completions and receipts after peer replacement", async () => {
    const started = deferred();
    const receipt = deferred();
    const aliceSync = synchronizer(async () => {
      started.resolve();
      await receipt.promise;
    });
    const bobSync = synchronizer();
    const peers = pair({ synchronizePeer: aliceSync.run }, { synchronizePeer: bobSync.run });
    await peers.start();
    const oldReady = peers.alice.readyFor(BOB.publicKey);
    await bobSync.attempts[0]!.context.send(new Uint8Array([1]));
    await started.promise;
    await bobSync.attempts[0]!.context.send(new Uint8Array([2]));
    const waitingForOldReceipt = peers.alice.whenIdle();
    for (let pass = 0; pass < 16; pass += 1) {
      await Promise.resolve();
    }
    await peers.alice.reconnectPeer(BOB.publicKey);
    await waitingForOldReceipt;
    await expect(oldReady).rejects.toThrow(/disconnected/);
    await peers.authenticate();
    const previous = aliceSync.attempts[0]!;
    expect(previous.context.signal.aborted).toBe(true);
    await expect(previous.context.send(new Uint8Array([2]))).rejects.toThrow(/no longer active/);
    expect(() => previous.context.onMessage(() => undefined)).toThrow(/no longer active/);

    previous.done.resolve();
    receipt.reject(new Error("stale commit failure"));
    bobSync.attempts[0]!.done.reject(new Error("stale synchronization failure"));
    await settleMeshes(peers.alice, peers.bob);
    expect(peers.alice.readyPeers).toEqual([]);
    expect(peers.alice.authenticatedPeers).toEqual([BOB.publicKey]);
    expect(peers.alice.failures.some(({ error }) => /stale commit/.test(error.message))).toBe(false);
    aliceSync.attempts[1]!.done.resolve();
    bobSync.attempts[1]!.done.resolve();
    await Promise.all([peers.alice.readyFor(BOB.publicKey), peers.bob.readyFor(ALICE.publicKey)]);
    await peers.close();
  });

  it("retains obsolete synchronization errors without notifying observers after abort-triggered replacement", async () => {
    let reconnect = (): void => undefined;
    let reconnecting: Promise<void> | undefined;
    const aliceSync = synchronizer();
    const bobSync = synchronizer();
    const onError = vi.fn();
    const peers = pair({
      synchronizePeer: (context) => {
        if (context.generation === 1) {
          context.signal.addEventListener("abort", () => reconnect(), { once: true });
        }
        return aliceSync.run(context);
      },
      onError: (error) => {
        onError(error);
        void peers.alice.close();
      },
    }, { synchronizePeer: bobSync.run });
    reconnect = () => { reconnecting = peers.alice.reconnectPeer(BOB.publicKey); };
    await peers.start();
    const previousReady = peers.alice.readyFor(BOB.publicKey);
    aliceSync.attempts[0]!.done.reject(new Error("obsolete synchronization failed"));
    await expect(previousReady).rejects.toThrow(/obsolete synchronization failed/);
    expect(reconnecting).toBeDefined();
    await reconnecting;
    await peers.authenticate();
    expect(onError).not.toHaveBeenCalled();
    expect(peers.alice.failures.some(({ error }) => /obsolete synchronization failed/.test(error.message))).toBe(true);
    expect(peers.alice.peers.find(({ identity }) => identityKey(identity) === identityKey(BOB.publicKey))?.generation).toBe(2);
    aliceSync.attempts[1]!.done.resolve();
    bobSync.attempts[1]!.done.resolve();
    await Promise.all([peers.alice.readyFor(BOB.publicKey), peers.bob.readyFor(ALICE.publicKey)]);
    await peers.close();
  });

  it("does not forward a disconnect-observer error against its reentrant replacement", async () => {
    let reconnect = (): void => undefined;
    let reconnecting: Promise<void> | undefined;
    const onError = vi.fn();
    const peers = pair({
      onPeerDisconnected: (_remote, generation) => {
        if (generation === 1) {
          reconnect();
          throw new Error("obsolete disconnect observer failed");
        }
      },
      onError: (error) => {
        onError(error);
        void peers.alice.close();
      },
    });
    reconnect = () => { reconnecting = peers.alice.reconnectPeer(BOB.publicKey); };
    await peers.start();
    await Promise.all([peers.alice.readyFor(BOB.publicKey), peers.bob.readyFor(ALICE.publicKey)]);
    peers.aliceHarness.connection(BOB.publicKey).emitConnectionState("failed");
    expect(reconnecting).toBeDefined();
    await reconnecting;
    await peers.authenticate();
    await Promise.all([peers.alice.readyFor(BOB.publicKey), peers.bob.readyFor(ALICE.publicKey)]);
    expect(onError).not.toHaveBeenCalled();
    expect(peers.alice.failures.some(({ error }) => /obsolete disconnect observer failed/.test(error.message))).toBe(true);
    expect(peers.alice.readyPeers).toEqual([BOB.publicKey]);
    await peers.close();
  });

  it("revokes readiness on a failed connection and ignores saved old connection callbacks", async () => {
    const peers = pair();
    await peers.start();
    await Promise.all([peers.alice.readyFor(BOB.publicKey), peers.bob.readyFor(ALICE.publicKey)]);
    const oldConnection = peers.aliceHarness.connection(BOB.publicKey);
    const savedStateCallback = oldConnection.onconnectionstatechange;
    oldConnection.emitConnectionState("failed");
    expect(peers.alice.readyPeers).toEqual([]);
    expect(peers.bob.readyPeers).toEqual([]);
    await expect(peers.alice.send(BOB.publicKey, new Uint8Array([1]))).rejects.toThrow(/synchronization/);
    await peers.alice.reconnectPeer(BOB.publicKey);
    await peers.authenticate();
    await Promise.all([peers.alice.readyFor(BOB.publicKey), peers.bob.readyFor(ALICE.publicKey)]);
    savedStateCallback?.(new Event("connectionstatechange"));
    expect(peers.alice.readyPeers).toEqual([BOB.publicKey]);
    await peers.close();
  });

  it("accepts a unilateral same-identity restart even before the old connection reports failure", async () => {
    const aliceSync = synchronizer();
    const peers = pair({ synchronizePeer: aliceSync.run });
    await peers.start();
    aliceSync.attempts[0]!.done.resolve();
    await Promise.all([peers.alice.readyFor(BOB.publicKey), peers.bob.readyFor(ALICE.publicKey)]);
    const oldConnection = peers.aliceHarness.connection(BOB.publicKey);
    peers.bobHarness.channel(ALICE.publicKey).unlink();
    await peers.bob.close();
    expect(oldConnection.connectionState).toBe("connected");

    const restartedSync = synchronizer();
    const restartedHarness = harness("bob-restarted", BOB_FINGERPRINT, 100);
    const restarted = facade(peers.network, BOB, restartedHarness, [], [], {
      synchronizePeer: restartedSync.run,
    });
    await restarted.start();
    await restarted.requestNegotiation(ALICE.publicKey);
    await settleMeshes(peers.alice, restarted);
    expect(oldConnection.connectionState).toBe("closed");
    expect(peers.alice.readyPeers).toEqual([]);
    await authenticatePeers(peers.alice, restarted, peers.aliceHarness, restartedHarness);
    expect(aliceSync.attempts[1]!.context.generation).toBe(2);
    expect(restartedSync.attempts[0]!.context.generation).toBe(1);
    aliceSync.attempts[1]!.done.resolve();
    restartedSync.attempts[0]!.done.resolve();
    await Promise.all([peers.alice.readyFor(BOB.publicKey), restarted.readyFor(ALICE.publicKey)]);
    await Promise.all([peers.close(), restarted.close()]);
  });

  it("fails closed on synchronization rejection and asynchronous receipt failure", async () => {
    const started = deferred();
    const receipt = deferred();
    const aliceSync = synchronizer(async () => {
      started.resolve();
      await receipt.promise;
    });
    const bobSync = synchronizer();
    const peers = pair({ synchronizePeer: aliceSync.run }, { synchronizePeer: bobSync.run });
    await peers.start();
    const ready = peers.alice.readyFor(BOB.publicKey);
    await bobSync.attempts[0]!.context.send(new Uint8Array([1]));
    await started.promise;
    receipt.reject(new Error("durable synchronization commit failed"));
    await expect(ready).rejects.toThrow(/durable synchronization commit failed/);
    expect(peers.alice.readyPeers).toEqual([]);
    expect(aliceSync.attempts[0]!.context.signal.aborted).toBe(true);

    await peers.alice.reconnectPeer(BOB.publicKey);
    await peers.authenticate();
    const retryReady = peers.alice.readyFor(BOB.publicKey);
    aliceSync.attempts[1]!.done.reject(new Error("conflicting synchronization history"));
    await expect(retryReady).rejects.toThrow(/conflicting synchronization history/);
    expect(peers.alice.readyPeers).toEqual([]);
    await peers.close();
  });

  it("times out synchronization locally without declaring a game forfeiture", async () => {
    const aliceSync = synchronizer();
    const bobSync = synchronizer();
    const peers = pair(
      { synchronizePeer: aliceSync.run, synchronizationTimeoutMs: 50 },
      { synchronizePeer: bobSync.run },
    );
    vi.useFakeTimers();
    try {
      await peers.start();
      const ready = peers.alice.readyFor(BOB.publicKey);
      await vi.advanceTimersByTimeAsync(50);
      await expect(ready).rejects.toThrow(/synchronization timed out/);
      expect(peers.alice.readyPeers).toEqual([]);
      expect(peers.bob.readyPeers).toEqual([]);
      expect(aliceSync.attempts[0]!.context.signal.aborted).toBe(true);
      await peers.close();
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      await peers.close();
      vi.useRealTimers();
    }
  });

  it.each([
    { maxQueuedSynchronizationMessages: 1 },
    { maxQueuedSynchronizationBytes: 3 },
  ])("bounds queued synchronization traffic: %j", async (limit) => {
    const started = deferred();
    const receipt = deferred();
    const aliceSync = synchronizer(async () => {
      started.resolve();
      await receipt.promise;
    });
    const bobSync = synchronizer();
    const peers = pair({ synchronizePeer: aliceSync.run, ...limit }, { synchronizePeer: bobSync.run });
    await peers.start();
    const ready = peers.alice.readyFor(BOB.publicKey);
    await bobSync.attempts[0]!.context.send(new Uint8Array([1, 2]));
    await started.promise;
    await bobSync.attempts[0]!.context.send(new Uint8Array([3, 4])).catch(() => undefined);
    await expect(ready).rejects.toThrow(/message handler failed/);
    expect(peers.aliceMessages).toEqual([]);
    expect(peers.alice.readyPeers).toEqual([]);
    receipt.resolve();
    await peers.close();
  });

  it("rejects pre-ready traffic without a registered synchronization handler", async () => {
    const done = deferred();
    const bobSync = synchronizer();
    const peers = pair({ synchronizePeer: () => done.promise }, { synchronizePeer: bobSync.run });
    await peers.start();
    const ready = peers.alice.readyFor(BOB.publicKey);
    await bobSync.attempts[0]!.context.send(new Uint8Array([1])).catch(() => undefined);
    await expect(ready).rejects.toThrow(/message handler failed/);
    expect(peers.aliceMessages).toEqual([]);
    expect(peers.alice.readyPeers).toEqual([]);
    await peers.close();
  });

  it("rejects non-promise synchronization results and ready-observer failures", async () => {
    const peers = pair({
      synchronizePeer: () => undefined as unknown as Promise<void>,
    });
    await Promise.all([peers.alice.start(), peers.bob.start()]);
    const ready = peers.alice.readyFor(BOB.publicKey);
    await peers.authenticate().catch(() => undefined);
    await expect(ready).rejects.toThrow(/must return a promise/);
    await peers.close();

    const observed = pair({ onPeerReady: () => { throw new Error("ready observer failed"); } });
    await Promise.all([observed.alice.start(), observed.bob.start()]);
    const observedReady = observed.alice.readyFor(BOB.publicKey);
    await observed.authenticate().catch(() => undefined);
    await expect(observedReady).rejects.toThrow(/ready observer failed/);
    expect(observed.alice.readyPeers).toEqual([]);
    await observed.close();
  });

  it("invalidates pending readiness on shutdown and rejects reconnect after close", async () => {
    const aliceSync = synchronizer();
    const peers = pair({ synchronizePeer: aliceSync.run });
    await peers.start();
    const ready = peers.alice.readyFor(BOB.publicKey);
    await peers.close();
    await expect(ready).rejects.toThrow(/closed/);
    await expect(peers.alice.reconnectPeer(BOB.publicKey)).rejects.toThrow(/closed/);
    aliceSync.attempts[0]!.done.resolve();
    expect(aliceSync.attempts[0]!.context.signal.aborted).toBe(true);
    expect(peers.alice.readyPeers).toEqual([]);
  });
});

interface TestIdentity {
  readonly secretKey: Ed25519SecretKey;
  readonly publicKey: IdentityPublicKey;
}

interface PeerHarness {
  readonly factory: MeshPeerConnectionFactory;
  connection(remote: IdentityPublicKey): FacadePeerConnection;
  channel(remote: IdentityPublicKey): FacadeDataChannel;
}

function facade(
  network: InMemorySignalingNetwork,
  self: TestIdentity,
  peerHarness: PeerHarness,
  authenticated: IdentityPublicKey[],
  messages: Array<{ remote: IdentityPublicKey; payload: Uint8Array }>,
  options: Partial<AuthenticatedMeshTransportOptions> = {},
): AuthenticatedMeshTransport {
  return new AuthenticatedMeshTransport({
    roomId: ROOM,
    gameId: GAME_ID,
    self: self.publicKey,
    secretKey: self.secretKey,
    roster: ROSTER,
    signaling: network.createAdapter(),
    createPeerConnection: peerHarness.factory,
    // No session history in this transport-only fixture; real callers must supply a synchronizer.
    synchronizePeer: async () => undefined,
    onPeerAuthenticated: (remote) => authenticated.push(remote),
    onMessage: (remote, payload) => messages.push({ remote, payload }),
    ...options,
  });
}

function harness(name: string, fingerprint: string | null, initialOrigin = 1): PeerHarness {
  const connections = new Map<string, FacadePeerConnection>();
  let nextOrigin = initialOrigin;
  return {
    factory: (remote, configuration) => {
      const connection = new FacadePeerConnection(name, fingerprint, configuration, nextOrigin++);
      connections.set(identityKey(remote), connection);
      return connection;
    },
    connection: (remote) => {
      const connection = connections.get(identityKey(remote));
      if (connection === undefined) {
        throw new Error("Missing facade peer connection");
      }
      return connection;
    },
    channel: (remote) => {
      const channel = connections.get(identityKey(remote))?.channel;
      if (channel === undefined || channel === null) {
        throw new Error("Missing facade data channel");
      }
      return channel;
    },
  };
}

async function settleMeshes(
  ...meshes: readonly AuthenticatedMeshTransport[]
): Promise<void> {
  for (let pass = 0; pass < 6; pass += 1) {
    await Promise.all(meshes.map((mesh) => mesh.whenIdle()));
    await Promise.resolve();
  }
}

class FacadePeerConnection implements MeshPeerConnection {
  signalingState: RTCSignalingState = "stable";
  connectionState: RTCPeerConnectionState = "new";
  iceGatheringState: RTCIceGatheringState = "complete";
  localDescription: RTCSessionDescriptionInit | null = null;
  remoteDescription: RTCSessionDescriptionInit | null = null;
  onnegotiationneeded: ((event: Event) => void) | null = null;
  onicecandidate: ((event: RTCPeerConnectionIceEvent) => void) | null = null;
  ondatachannel: ((event: RTCDataChannelEvent) => void) | null = null;
  onconnectionstatechange: ((event: Event) => void) | null = null;
  readonly configuration: RTCConfiguration;
  readonly #name: string;
  readonly #fingerprint: string | null;
  readonly #origin: number;
  channel: FacadeDataChannel | null = null;
  #sequence = 0;

  constructor(name: string, fingerprint: string | null, configuration: RTCConfiguration, origin: number) {
    this.#name = name;
    this.#fingerprint = fingerprint;
    this.#origin = origin;
    this.configuration = configuration;
  }

  async setLocalDescription(): Promise<void> {
    if (this.signalingState === "closed") {
      throw new Error("Facade peer is closed");
    }
    this.#sequence += 1;
    const type = this.signalingState === "have-remote-offer" ? "answer" : "offer";
    this.localDescription = { type, sdp: this.#sdp() };
    this.signalingState = type === "offer" ? "have-local-offer" : "stable";
  }

  async setRemoteDescription(description: RTCSessionDescriptionInit): Promise<void> {
    if (this.signalingState === "closed") {
      throw new Error("Facade peer is closed");
    }
    this.remoteDescription = { ...description };
    if (description.type === "offer") {
      this.signalingState = "have-remote-offer";
    } else if (description.type === "answer") {
      this.signalingState = "stable";
    }
  }

  async addIceCandidate(): Promise<void> {}

  createDataChannel(label: string, options: RTCDataChannelInit = {}): RTCDataChannel {
    this.channel = new FacadeDataChannel(label, options);
    return this.channel as unknown as RTCDataChannel;
  }

  close(): void {
    this.signalingState = "closed";
    this.connectionState = "closed";
    this.channel?.close();
  }

  emitConnectionState(state: RTCPeerConnectionState): void {
    this.connectionState = state;
    this.onconnectionstatechange?.(new Event("connectionstatechange"));
  }

  #sdp(): string {
    return [
      "v=0",
      `o=- ${this.#origin} ${this.#sequence} IN IP4 0.0.0.0`,
      `a=ice-ufrag:${this.#name}-${this.#origin}`,
      ...(this.#fingerprint === null
        ? []
        : [`a=fingerprint:sha-256 ${this.#fingerprint}`]),
      `a=x-description:${this.#sequence}`,
      "",
    ].join("\r\n");
  }
}

class FacadeDataChannel extends EventTarget {
  readonly label: string;
  readonly id: number | null;
  readonly negotiated: boolean;
  readonly ordered: boolean;
  readonly maxPacketLifeTime: number | null;
  readonly maxRetransmits: number | null;
  binaryType: BinaryType = "blob";
  bufferedAmount = 0;
  bufferedAmountLowThreshold = 0;
  readyState: RTCDataChannelState = "connecting";
  #peer: FacadeDataChannel | null = null;

  constructor(label: string, options: RTCDataChannelInit) {
    super();
    this.label = label;
    this.id = options.id ?? null;
    this.negotiated = options.negotiated ?? false;
    this.ordered = options.ordered ?? true;
    this.maxPacketLifeTime = options.maxPacketLifeTime ?? null;
    this.maxRetransmits = options.maxRetransmits ?? null;
  }

  get closed(): boolean {
    return this.readyState === "closed";
  }

  link(peer: FacadeDataChannel): void {
    this.#peer = peer;
  }

  unlink(): void {
    this.#peer = null;
  }

  open(): void {
    if (this.readyState === "closed") {
      return;
    }
    this.readyState = "open";
    this.dispatchEvent(new Event("open"));
  }

  send(data: ArrayBuffer | ArrayBufferView | Blob | string): void {
    if (this.readyState !== "open" || !ArrayBuffer.isView(data)) {
      throw new Error("Facade channel accepts binary sends only while open");
    }
    const bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength).slice();
    queueMicrotask(() => {
      if (this.#peer !== null) {
        this.#peer.#receive(bytes);
      }
    });
  }

  close(): void {
    this.#close(true);
  }

  #receive(bytes: Uint8Array): void {
    if (this.readyState !== "open") {
      return;
    }
    const event = new Event("message");
    const snapshot = new Uint8Array(bytes.length);
    snapshot.set(bytes);
    Object.defineProperty(event, "data", { value: snapshot.buffer });
    this.dispatchEvent(event);
  }

  #close(propagate: boolean): void {
    if (this.readyState === "closed") {
      return;
    }
    this.readyState = "closed";
    this.dispatchEvent(new Event("close"));
    if (propagate && this.#peer !== null) {
      this.#peer.#close(false);
    }
  }
}

function identity(fill: number): TestIdentity {
  const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(fill));
  return {
    secretKey,
    publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)),
  };
}

function fingerprintText(fill: number): string {
  return new Array<string>(32)
    .fill(fill.toString(16).padStart(2, "0"))
    .join(":");
}

function identityKey(identity: Uint8Array): string {
  return Array.from(identity, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function deferred(): {
  promise: Promise<void>;
  resolve: () => void;
  reject: (error: Error) => void;
} {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((success, failure) => { resolve = success; reject = failure; });
  return { promise, resolve, reject };
}

function synchronizer(handler: (payload: Uint8Array) => void | Promise<void> = () => undefined) {
  const attempts: Array<{ context: PeerSynchronizationContext; done: ReturnType<typeof deferred> }> = [];
  return {
    attempts,
    run: (context: PeerSynchronizationContext): Promise<void> => {
      const done = deferred();
      context.onMessage(handler);
      attempts.push({ context, done });
      return done.promise;
    },
  };
}

function pair(
  aliceOptions: Partial<AuthenticatedMeshTransportOptions> = {},
  bobOptions: Partial<AuthenticatedMeshTransportOptions> = {},
) {
  const network = new InMemorySignalingNetwork();
  const aliceHarness = harness("alice", ALICE_FINGERPRINT);
  const bobHarness = harness("bob", BOB_FINGERPRINT);
  const aliceMessages: Array<{ remote: IdentityPublicKey; payload: Uint8Array }> = [];
  const bobMessages: Array<{ remote: IdentityPublicKey; payload: Uint8Array }> = [];
  const alice = facade(network, ALICE, aliceHarness, [], aliceMessages, aliceOptions);
  const bob = facade(network, BOB, bobHarness, [], bobMessages, bobOptions);
  const authenticate = (): Promise<void> => authenticatePeers(alice, bob, aliceHarness, bobHarness);
  return {
    network, alice, bob, aliceHarness, bobHarness, aliceMessages, bobMessages, authenticate,
    start: async (): Promise<void> => {
      await Promise.all([alice.start(), bob.start()]);
      await authenticate();
    },
    close: async (): Promise<void> => { await Promise.all([alice.close(), bob.close()]); },
  };
}

async function authenticatePeers(
  alice: AuthenticatedMeshTransport,
  bob: AuthenticatedMeshTransport,
  aliceHarness: PeerHarness,
  bobHarness: PeerHarness,
): Promise<void> {
  await settleMeshes(alice, bob);
  await alice.requestNegotiation(BOB.publicKey);
  await settleMeshes(alice, bob);
  const aliceWire = aliceHarness.channel(BOB.publicKey);
  const bobWire = bobHarness.channel(ALICE.publicKey);
  aliceWire.link(bobWire);
  bobWire.link(aliceWire);
  aliceWire.open();
  bobWire.open();
  aliceHarness.connection(BOB.publicKey).emitConnectionState("connected");
  bobHarness.connection(ALICE.publicKey).emitConnectionState("connected");
  await Promise.all([
    alice.authenticationFor(BOB.publicKey),
    bob.authenticationFor(ALICE.publicKey),
  ]);
}
