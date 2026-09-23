import {
  parseIdentityPublicKey,
  type IdentityPublicKey,
} from "@p2pcards/protocol";
import { describe, expect, it, vi } from "vitest";

import {
  DATA_CHANNEL_LABEL,
  FullMeshTransport,
  inspectIceConnectionPath,
  type FullMeshTransportOptions,
  type MeshPeerConnection,
  type MeshPeerConnectionFactory,
} from "./full-mesh";
import {
  decodePeerSignal,
  encodePeerSignal,
  type CandidateSignal,
  type DescriptionSignal,
} from "./signaling-message";
import {
  InMemorySignalingNetwork,
  type SignalingAdapter,
  type SignalingMessageHandler,
} from "./signaling";

const ROOM = "12".repeat(32);
const ALICE = identity(1);
const BOB = identity(2);
const CAROL = identity(3);
const MALLORY = identity(4);
const ROSTER = [ALICE, BOB, CAROL] as const;

describe("full-mesh WebRTC transport", () => {
  it("creates one peer per remote and one deterministic reliable channel per pair", async () => {
    const network = new InMemorySignalingNetwork();
    const aliceHarness = harness("alice");
    const bobHarness = harness("bob");
    const carolHarness = harness("carol");
    const observed: string[] = [];
    const alice = mesh(network, ALICE, aliceHarness, (remote) =>
      observed.push(`alice:${key(remote)}`),
    );
    const bob = mesh(network, BOB, bobHarness, (remote) =>
      observed.push(`bob:${key(remote)}`),
    );
    const carol = mesh(network, CAROL, carolHarness, (remote) =>
      observed.push(`carol:${key(remote)}`),
    );

    await Promise.all([alice.start(), bob.start(), carol.start()]);

    expect(alice.peers.map(({ role }) => role)).toEqual(["impolite", "impolite"]);
    expect(bob.peers.map(({ role }) => role)).toEqual(["polite", "impolite"]);
    expect(carol.peers.map(({ role }) => role)).toEqual(["polite", "polite"]);
    expect(aliceHarness.createdChannelCount()).toBe(2);
    expect(bobHarness.createdChannelCount()).toBe(2);
    expect(carolHarness.createdChannelCount()).toBe(2);
    for (const channel of [
      ...aliceHarness.createdChannels(),
      ...bobHarness.createdChannels(),
    ]) {
      expect(channel).toMatchObject({
        label: DATA_CHANNEL_LABEL,
        id: 0,
        negotiated: true,
        ordered: true,
        maxPacketLifeTime: null,
        maxRetransmits: null,
      });
    }
    expect(observed).toHaveLength(6);
    expect(alice.peers.every(({ hasDataChannel }) => hasDataChannel)).toBe(true);
    expect(alice.peers.every(({ generation, connectionState }) =>
      generation === 1 && connectionState === "new"
    )).toBe(true);
    expect(bob.peers.every(({ hasDataChannel }) => hasDataChannel)).toBe(true);
    expect(carol.peers.every(({ hasDataChannel }) => hasDataChannel)).toBe(true);
    expect(aliceHarness.connections()[0]?.configuration).toMatchObject({
      bundlePolicy: "max-bundle",
      iceTransportPolicy: "all",
      iceServers: [{ urls: expect.arrayContaining([expect.stringMatching(/^stun:/)]) }],
    });

    await Promise.all([alice.close(), bob.close(), carol.close()]);
  });

  it("resolves simultaneous offers in favor of the impolite smaller identity", async () => {
    const network = new InMemorySignalingNetwork();
    const aliceHarness = harness("alice");
    const bobHarness = harness("bob");
    const alice = mesh(network, ALICE, aliceHarness);
    const bob = mesh(network, BOB, bobHarness);
    await Promise.all([alice.start(), bob.start()]);
    const aliceToBob = aliceHarness.connection(BOB);
    const bobToAlice = bobHarness.connection(ALICE);

    aliceToBob.emitNegotiationNeeded();
    bobToAlice.emitNegotiationNeeded();
    await settle(alice, bob);

    expect(aliceToBob.signalingState).toBe("stable");
    expect(bobToAlice.signalingState).toBe("stable");
    expect(aliceToBob.remoteDescription?.type).toBe("answer");
    expect(bobToAlice.remoteDescription?.type).toBe("offer");
    expect(aliceToBob.remoteOffers).toBe(0);
    expect(bobToAlice.rollbacks).toBe(1);
    expect(alice.failures).toEqual([]);
    expect(bob.failures).toEqual([]);
    const fingerprints = alice.dtlsFingerprints(BOB);
    expect(fingerprints.localFingerprint).toHaveLength(32);
    expect(fingerprints.remoteFingerprint).toHaveLength(32);
    expect(fingerprints.localFingerprint).not.toEqual(fingerprints.remoteFingerprint);

    await Promise.all([alice.close(), bob.close()]);
  });

  it.each(["local offer", "remote offer"] as const)(
    "coalesces a native negotiation event queued behind a %s",
    async (first) => {
      const network = new InMemorySignalingNetwork();
      const peerHarness = harness("alice");
      const signaling = network.createAdapter();
      const alice = mesh(network, ALICE, peerHarness, undefined, { signaling });
      const bob = network.createAdapter();
      bob.onMessage(() => undefined);
      await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
      const connection = peerHarness.connection(BOB);
      const entered = deferred();
      const ack = deferred();
      const send = vi.spyOn(signaling, "send").mockImplementationOnce(async () => {
        entered.resolve();
        await ack.promise;
      });
      const local = vi.spyOn(connection, "setLocalDescription");
      connection.emitIceCandidate(null);
      await entered.promise;
      const requesting = first === "local offer" ? alice.requestNegotiation(BOB) : undefined;
      if (first === "remote offer") signaling.deliver(BOB, encodePeerSignal(offer("101")));
      // The browser is still stable; its event is delayed by the transport's ACK queue.
      connection.emitNegotiationNeeded();
      ack.resolve();
      await requesting;
      await alice.whenIdle();

      expect(local).toHaveBeenCalledTimes(1);
      expect(send.mock.calls.map(([, payload]) => decodePeerSignal(payload))).toEqual([
        expect.objectContaining({ kind: "candidate" }),
        expect.objectContaining({ descriptionType: first === "local offer" ? "offer" : "answer" }),
      ]);
      expect(alice.failures).toEqual([]);
      await Promise.all([alice.close(), bob.leave()]);
    },
  );

  it.each(["candidate", "end-of-candidates", "already-complete", "already-initialized", "retirement", "replacement", "remote-replacement", "full-queue"] as const)(
    "defers initial polite rollback until local ICE initializes, or cancels on %s",
    async (release) => {
      const network = new InMemorySignalingNetwork();
      const peerHarness = harness("bob");
      const signaling = network.createAdapter();
      const bob = mesh(network, BOB, peerHarness, undefined, {
        signaling, ...(release === "full-queue" ? { maxQueuedPeerOperations: 1 } : {}),
      });
      const alice = network.createAdapter();
      alice.onMessage(() => undefined);
      await Promise.all([bob.start(), alice.join(ROOM, ALICE)]);
      const connection = peerHarness.connection(ALICE);
      const oldIceCallback = connection.onicecandidate!;
      connection.iceGatheringState = release === "already-complete" ? "complete" : "gathering";
      await bob.requestNegotiation(ALICE);
      const candidate = {
        candidate: "candidate:1 1 UDP 1 192.0.2.1 5000 typ host",
        sdpMid: "0", sdpMLineIndex: 0, usernameFragment: "bob-1",
      };
      if (release === "already-initialized") {
        connection.emitIceCandidate(candidate);
        await bob.whenIdle();
      }
      const remote = vi.spyOn(connection, "setRemoteDescription");
      signaling.deliver(ALICE, encodePeerSignal(candidateMessage("winning-candidate", "winning")));
      signaling.deliver(ALICE, encodePeerSignal(offer("101", "alice", "winning")));
      const idle = bob.whenIdle();
      await Promise.resolve();
      if (release !== "already-complete" && release !== "already-initialized") {
        expect(remote).not.toHaveBeenCalled();
        expect(connection.signalingState).toBe("have-local-offer");
        expect(connection.addedCandidates).toEqual([]);
      }

      if (release === "retirement") bob.disconnectPeer(ALICE);
      else if (release === "replacement") await bob.reconnectPeer(ALICE);
      else if (release === "remote-replacement") {
        signaling.deliver(ALICE, encodePeerSignal(candidateMessage("fresh-candidate", "fresh")));
        signaling.deliver(ALICE, encodePeerSignal(offer("102", "alice", "fresh")));
      }
      else if (release === "candidate" || release === "full-queue") connection.emitIceCandidate(candidate);
      else if (release === "end-of-candidates") connection.emitIceCandidate(null);
      await idle;
      await bob.whenIdle();
      if (release === "retirement" || release === "replacement" || release === "remote-replacement") {
        expect(remote).not.toHaveBeenCalled();
        expect(connection.closed).toBe(true);
        expect(connection.addedCandidates).toEqual([]);
        if (release === "remote-replacement") {
          expect(peerHarness.connection(ALICE).addedCandidates).toEqual([
            expect.objectContaining({ candidate: "fresh-candidate", usernameFragment: "fresh" }),
          ]);
        }
        if (release === "replacement") {
          const replacement = peerHarness.connection(ALICE);
          replacement.iceGatheringState = "gathering";
          const freshRemote = vi.spyOn(replacement, "setRemoteDescription");
          signaling.deliver(ALICE, encodePeerSignal(offer("102", "alice", "fresh")));
          const replacing = bob.whenIdle();
          await Promise.resolve();
          oldIceCallback({ candidate: null } as RTCPeerConnectionIceEvent);
          await Promise.resolve();
          expect(freshRemote).not.toHaveBeenCalled();
          replacement.emitIceCandidate(null);
          await replacing;
          expect(replacement.signalingState).toBe("stable");
          expect(freshRemote).toHaveBeenCalledTimes(1);
        }
      } else {
        expect(remote).toHaveBeenCalledExactlyOnceWith({ type: "offer", sdp: offer("101", "alice", "winning").sdp });
        expect(connection.rollbacks).toBe(1);
        expect(connection.signalingState).toBe("stable");
        expect(connection.addedCandidates).toEqual([
          expect.objectContaining({ candidate: "winning-candidate", usernameFragment: "winning" }),
        ]);
      }
      expect(bob.failures.map(({ error }) => error.message)).toEqual(
        release === "full-queue" ? ["Queued peer operation limit exceeded"] : [],
      );
      await Promise.all([bob.close(), alice.leave()]);
    },
  );

  it("does not signal the rolled-back offer's end-of-candidates after its answer", async () => {
    const network = new InMemorySignalingNetwork();
    const aliceHarness = harness("alice");
    const bobHarness = harness("bob");
    const bobSignaling = network.createAdapter();
    const alice = mesh(network, ALICE, aliceHarness);
    const bob = mesh(network, BOB, bobHarness, undefined, { signaling: bobSignaling });
    await Promise.all([alice.start(), bob.start()]);
    const aliceToBob = aliceHarness.connection(BOB);
    const bobToAlice = bobHarness.connection(ALICE);
    bobToAlice.iceGatheringState = "gathering";
    // Delay the losing offer so the winning offer reaches an uninitialized polite PC.
    vi.spyOn(bobSignaling, "send").mockResolvedValueOnce(undefined);
    await bob.requestNegotiation(ALICE);
    await alice.requestNegotiation(BOB);
    expect(bobToAlice.remoteDescription).toBeNull();
    bobToAlice.emitIceCandidate(null);
    await settle(alice, bob);
    expect(aliceToBob.signalingState).toBe("stable");
    expect(bobToAlice.rollbacks).toBe(1);
    expect(aliceToBob.addedCandidates).toEqual([]);
    bobToAlice.emitIceCandidate(null);
    await settle(alice, bob);
    expect(aliceToBob.addedCandidates).toEqual([null]);
    expect(alice.failures).toEqual([]);
    expect(bob.failures).toEqual([]);
    await Promise.all([alice.close(), bob.close()]);
  });

  it("deduplicates candidate-expanded answers even while a newer local offer is pending", async () => {
    const network = new InMemorySignalingNetwork();
    const aliceHarness = harness("alice");
    const bobHarness = harness("bob");
    const signaling = network.createAdapter();
    const alice = mesh(network, ALICE, aliceHarness, undefined, { signaling });
    const bob = mesh(network, BOB, bobHarness);
    await Promise.all([alice.start(), bob.start()]);
    await alice.requestNegotiation(BOB);
    await settle(alice, bob);
    const aliceToBob = aliceHarness.connection(BOB);
    const bobToAlice = bobHarness.connection(ALICE);
    const answer = bobToAlice.localDescription!;
    const expanded = {
      kind: "description", descriptionType: "answer",
      sdp: answer.sdp! + "a=candidate:1 1 UDP 1 192.0.2.1 5000 typ host\r\na=end-of-candidates\r\n",
    } as const;
    const remote = vi.spyOn(aliceToBob, "setRemoteDescription");
    signaling.deliver(BOB, encodePeerSignal(expanded));
    await alice.whenIdle();
    expect(remote).not.toHaveBeenCalled();

    const send = vi.spyOn(signaling, "send").mockResolvedValue(undefined);
    await alice.requestNegotiation(BOB);
    signaling.deliver(BOB, encodePeerSignal(expanded));
    await alice.whenIdle();
    expect(aliceToBob.signalingState).toBe("have-local-offer");
    expect(remote).not.toHaveBeenCalled();
    expect(aliceToBob.remoteDescription).toEqual(answer);
    expect(alice.failures).toEqual([]);
    send.mockRestore();
    await alice.requestNegotiation(BOB);
    await settle(alice, bob);
    expect(aliceToBob.signalingState).toBe("stable");
    expect(remote).toHaveBeenCalledTimes(1);
    const latestAnswer = aliceToBob.remoteDescription;
    signaling.deliver(BOB, encodePeerSignal(expanded));
    await alice.whenIdle();
    expect(aliceToBob.remoteDescription).toEqual(latestAnswer);
    expect(remote).toHaveBeenCalledTimes(1);
    expect(alice.failures).toEqual([]);
    await Promise.all([alice.close(), bob.close()]);
  });

  it("does not learn replacement or ICE metadata from ignored colliding offers", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const signaling = network.createAdapter();
    const alice = mesh(network, ALICE, peerHarness, undefined, { signaling });
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    await alice.requestNegotiation(BOB);
    const connection = peerHarness.connection(BOB);
    for (const origin of ["101", "102"]) {
      signaling.deliver(BOB, encodePeerSignal(offer(origin, "bob", "ignored")));
      await alice.whenIdle();
      expect(peerHarness.connection(BOB)).toBe(connection);
      expect(connection.signalingState).toBe("have-local-offer");
      expect(connection.remoteDescription).toBeNull();
    }
    signaling.deliver(BOB, encodePeerSignal(candidateMessage("current", "answer")));
    signaling.deliver(BOB, encodePeerSignal({
      ...offer("102", "bob", "answer"), descriptionType: "answer",
    }));
    await alice.whenIdle();
    expect(connection.addedCandidates).toEqual([
      expect.objectContaining({ candidate: "current", usernameFragment: "answer" }),
    ]);
    expect(alice.peers[0]?.generation).toBe(1);
    expect(alice.failures).toEqual([]);
    await Promise.all([alice.close(), bob.leave()]);
  });

  it("orders SDP versions without losing 64-bit precision and still accepts a newer ICE restart", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const signaling = network.createAdapter();
    const alice = mesh(network, ALICE, peerHarness, undefined, { signaling });
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    const current = { ...offer("101"), sdp: offer("101").sdp.replace(" 1 IN", " 9007199254740993 IN") };
    signaling.deliver(BOB, encodePeerSignal(current));
    await alice.whenIdle();
    const connection = peerHarness.connection(BOB);
    signaling.deliver(BOB, encodePeerSignal({
      ...current, sdp: current.sdp.replace("9007199254740993", "9007199254740992"),
    }));
    await alice.whenIdle();
    expect(connection.remoteOffers).toBe(1);
    const restart = {
      ...current,
      sdp: current.sdp.replace("9007199254740993", "9007199254740994")
        .replace("ice-ufrag:ufrag", "ice-ufrag:restart"),
    };
    signaling.deliver(BOB, encodePeerSignal(candidateMessage("fresh", "restart")));
    signaling.deliver(BOB, encodePeerSignal(restart));
    await alice.whenIdle();
    expect(connection.remoteDescription?.sdp).toBe(restart.sdp);
    expect(connection.addedCandidates).toEqual([
      expect.objectContaining({ candidate: "fresh", usernameFragment: "restart" }),
    ]);
    expect(alice.peers[0]?.generation).toBe(1);
    expect(alice.failures).toEqual([]);
    await Promise.all([alice.close(), bob.leave()]);
  });

  it("reports direct, relayed, and incomplete selected ICE paths", async () => {
    expect(
      inspectIceConnectionPath(statsReport([
        { id: "transport", type: "transport", selectedCandidatePairId: "pair" },
        {
          id: "pair",
          type: "candidate-pair",
          state: "succeeded",
          localCandidateId: "local",
          remoteCandidateId: "remote",
        },
        { id: "local", type: "local-candidate", candidateType: "host" },
        { id: "remote", type: "remote-candidate", candidateType: "srflx" },
      ])),
    ).toEqual({
      path: "direct",
      selectedCandidatePairId: "pair",
      localCandidateType: "host",
      remoteCandidateType: "srflx",
    });
    expect(
      inspectIceConnectionPath(statsReport([
        {
          id: "fallback",
          type: "candidate-pair",
          state: "succeeded",
          nominated: true,
          localCandidateId: "local",
          remoteCandidateId: "remote",
        },
        { id: "local", type: "local-candidate", candidateType: "relay" },
        { id: "remote", type: "remote-candidate", candidateType: "host" },
      ])),
    ).toMatchObject({ path: "relayed", localCandidateType: "relay" });
    expect(inspectIceConnectionPath(statsReport([]))).toEqual({
      path: "unknown",
      selectedCandidatePairId: null,
      localCandidateType: null,
      remoteCandidateType: null,
    });
    expect(
      inspectIceConnectionPath(statsReport([
        { id: "pair-a", type: "candidate-pair", state: "succeeded", nominated: true },
        { id: "pair-b", type: "candidate-pair", state: "succeeded", nominated: true },
      ])).path,
    ).toBe("unknown");

    const network = new InMemorySignalingNetwork();
    const aliceHarness = harness("alice");
    const alice = mesh(network, ALICE, aliceHarness);
    await alice.start();
    aliceHarness.connection(BOB).stats = statsReport([
      { id: "transport", type: "transport", selectedCandidatePairId: "pair" },
      {
        id: "pair",
        type: "candidate-pair",
        state: "succeeded",
        localCandidateId: "local",
        remoteCandidateId: "remote",
      },
      { id: "local", type: "local-candidate", candidateType: "host" },
      { id: "remote", type: "remote-candidate", candidateType: "relay" },
    ]);
    await expect(alice.connectionPath(BOB)).resolves.toMatchObject({ path: "relayed" });
    await alice.close();
  });

  it("buffers reordered trickle candidates until the remote offer is installed", async () => {
    const network = new InMemorySignalingNetwork();
    const aliceHarness = harness("alice");
    const bobHarness = harness("bob");
    const alice = mesh(network, ALICE, aliceHarness);
    const bob = mesh(network, BOB, bobHarness);
    await Promise.all([alice.start(), bob.start()]);
    const aliceToBob = aliceHarness.connection(BOB);
    const bobToAlice = bobHarness.connection(ALICE);
    const candidate = {
      candidate: "candidate:1 1 UDP 1 192.0.2.1 5000 typ host",
      sdpMid: "0",
      sdpMLineIndex: 0,
      usernameFragment: "alice-2",
    };

    aliceToBob.emitIceCandidate(candidate);
    await settle(alice, bob);
    expect(bobToAlice.addedCandidates).toEqual([]);

    aliceToBob.emitNegotiationNeeded();
    await settle(alice, bob);
    expect(bobToAlice.addedCandidates).toEqual([candidate]);
    expect(aliceToBob.signalingState).toBe("stable");
    expect(bobToAlice.signalingState).toBe("stable");

    aliceToBob.emitIceCandidate(null);
    await settle(alice, bob);
    expect(bobToAlice.addedCandidates).toEqual([candidate, null]);

    await Promise.all([alice.close(), bob.close()]);
  });

  it("rejects unknown and malformed signals and bounds pre-description candidates", async () => {
    const network = new InMemorySignalingNetwork();
    const aliceHarness = harness("alice");
    const aliceAdapter = network.createAdapter();
    const alice = new FullMeshTransport({
      roomId: ROOM,
      self: ALICE,
      roster: ROSTER,
      signaling: aliceAdapter,
      createPeerConnection: aliceHarness.factory,
      maxPendingIceCandidates: 1,
    });
    await alice.start();
    const bobAdapter = network.createAdapter();
    const malloryAdapter = network.createAdapter();
    await bobAdapter.join(ROOM, BOB);
    await malloryAdapter.join(ROOM, MALLORY);

    await malloryAdapter.send(ALICE, encodePeerSignal(candidateMessage("mallory")));
    await bobAdapter.send(ALICE, new Uint8Array([0xff]));
    await bobAdapter.send(ALICE, encodePeerSignal(candidateMessage("first")));
    await alice.whenIdle();
    expect(aliceHarness.connection(BOB).addedCandidates).toEqual([]);
    await bobAdapter.send(ALICE, encodePeerSignal(candidateMessage("second")));
    await alice.whenIdle();

    expect(alice.failures.map(({ error }) => error.message)).toEqual([
      "Received signaling from an identity outside the roster",
      expect.stringMatching(/CBOR|decode|canonical/i),
      "Pending ICE candidate limit exceeded",
    ]);

    await Promise.all([alice.close(), bobAdapter.leave(), malloryAdapter.leave()]);
  });

  it("bounds accepted ICE candidates for each remote description", async () => {
    const network = new InMemorySignalingNetwork();
    const aliceHarness = harness("alice");
    const alice = new FullMeshTransport({
      roomId: ROOM,
      self: ALICE,
      roster: ROSTER,
      signaling: network.createAdapter(),
      createPeerConnection: aliceHarness.factory,
      maxAcceptedIceCandidates: 1,
    });
    const bobAdapter = network.createAdapter();
    bobAdapter.onMessage(() => undefined);
    await Promise.all([alice.start(), bobAdapter.join(ROOM, BOB)]);
    await bobAdapter.send(ALICE, encodePeerSignal({
      kind: "description",
      descriptionType: "offer",
      sdp: "v=0\r\na=ice-ufrag:ufrag\r\n",
    }));
    await alice.whenIdle();

    await bobAdapter.send(ALICE, encodePeerSignal(candidateMessage("first")));
    await bobAdapter.send(ALICE, encodePeerSignal({
      kind: "candidate",
      candidate: null,
      sdpMid: null,
      sdpMLineIndex: null,
      usernameFragment: null,
    }));
    await bobAdapter.send(ALICE, encodePeerSignal({
      kind: "description",
      descriptionType: "offer",
      sdp: "v=0\r\na=ice-ufrag:ufrag\r\na=x-renegotiation:2\r\n",
    }));
    await bobAdapter.send(ALICE, encodePeerSignal(candidateMessage("second")));
    await alice.whenIdle();

    expect(aliceHarness.connection(BOB).addedCandidates).toEqual([
      expect.objectContaining({ candidate: "first" }),
      null,
    ]);
    expect(alice.failures.at(-1)?.error.message).toBe(
      "Accepted ICE candidate limit exceeded",
    );

    await bobAdapter.send(ALICE, encodePeerSignal({
      kind: "description",
      descriptionType: "offer",
      sdp: "v=0\r\na=ice-ufrag:new-generation\r\n",
    }));
    await bobAdapter.send(ALICE, encodePeerSignal(candidateMessage("third", "new-generation")));
    await alice.whenIdle();
    expect(aliceHarness.connection(BOB).addedCandidates.at(-1)).toMatchObject({
      candidate: "third",
    });
    await Promise.all([alice.close(), bobAdapter.leave()]);
  });

  it("rejects unexpected in-band channels and an unreliable negotiated channel", async () => {
    const network = new InMemorySignalingNetwork();
    const aliceHarness = harness("alice");
    const carolHarness = harness("carol");
    const alice = mesh(network, ALICE, aliceHarness);
    const carol = mesh(network, CAROL, carolHarness);
    await Promise.all([alice.start(), carol.start()]);

    const unexpected = new FakeDataChannel(DATA_CHANNEL_LABEL);
    aliceHarness.connection(BOB).emitDataChannel(unexpected);
    expect(unexpected.closed).toBe(true);

    const unreliable = new FakeDataChannel(DATA_CHANNEL_LABEL, {
      maxRetransmits: 1,
    });
    carolHarness.connection(BOB).emitDataChannel(unreliable);

    expect(unreliable.closed).toBe(true);
    expect(alice.failures[0]?.error.message).toMatch(/unexpected in-band/);
    expect(carol.failures[0]?.error.message).toMatch(/unexpected in-band/);

    await Promise.all([alice.close(), carol.close()]);

    const badNetwork = new InMemorySignalingNetwork();
    const badHarness = harness("bad", { maxRetransmits: 1 });
    const bad = mesh(badNetwork, ALICE, badHarness);
    await expect(bad.start()).rejects.toThrow(/did not satisfy/);
  });

  it("recovers its peer queue and resends an offer after transient signaling failure", async () => {
    const network = new InMemorySignalingNetwork();
    const aliceHarness = harness("alice");
    const alice = mesh(network, ALICE, aliceHarness);
    await alice.start();

    await expect(alice.requestNegotiation(BOB)).rejects.toThrow(/not present/);
    expect(aliceHarness.connection(BOB).signalingState).toBe("have-local-offer");

    const bobAdapter = network.createAdapter();
    const received: Uint8Array[] = [];
    bobAdapter.onMessage((_from, payload) => received.push(payload));
    await bobAdapter.join(ROOM, BOB);
    await alice.requestNegotiation(BOB);
    expect(received).toHaveLength(1);
    expect(alice.failures).toHaveLength(1);

    await Promise.all([alice.close(), bobAdapter.leave()]);
  });

  it("converges when the channel creator offers before the remote peer joins", async () => {
    const network = new InMemorySignalingNetwork();
    const aliceHarness = harness("alice");
    const bobHarness = harness("bob");
    const alice = mesh(network, ALICE, aliceHarness);
    const bob = mesh(network, BOB, bobHarness);
    await alice.start();
    const aliceToBob = aliceHarness.connection(BOB);
    aliceToBob.emitNegotiationNeeded();
    await alice.whenIdle();
    expect(aliceToBob.signalingState).toBe("have-local-offer");

    await bob.start();
    const bobToAlice = bobHarness.connection(ALICE);
    bobToAlice.emitNegotiationNeeded();
    await settle(alice, bob);

    expect(aliceToBob.signalingState).toBe("stable");
    expect(bobToAlice.signalingState).toBe("stable");
    expect(bobToAlice.rollbacks).toBe(1);
    expect(alice.failures).toHaveLength(1);
    expect(bob.failures).toEqual([]);

    await Promise.all([alice.close(), bob.close()]);
  });

  it("does not revive peers when close races an unresolved join", async () => {
    const signaling = new DelayedJoinSignalingAdapter();
    const peerHarness = harness("alice");
    const transport = new FullMeshTransport({
      roomId: ROOM,
      self: ALICE,
      roster: ROSTER,
      signaling,
      createPeerConnection: peerHarness.factory,
    });

    const starting = transport.start();
    await Promise.resolve();
    const closing = transport.close();
    signaling.releaseJoin();

    await expect(starting).rejects.toThrow(/cancelled/);
    await closing;
    expect(transport.started).toBe(false);
    expect(transport.peers).toEqual([]);
    expect(peerHarness.connections()).toEqual([]);
    expect(signaling.leaveCalls).toBeGreaterThanOrEqual(1);
  });

  it("does not leave replacement signaling when cancelled startup settles late", async () => {
    const signaling = new DelayedJoinSignalingAdapter();
    const old = new FullMeshTransport({
      roomId: ROOM,
      self: ALICE,
      roster: ROSTER,
      signaling,
      createPeerConnection: harness("old").factory,
    });
    const starting = old.start();
    await old.close();
    const replacement = new FullMeshTransport({
      roomId: ROOM,
      self: ALICE,
      roster: ROSTER,
      signaling,
      createPeerConnection: harness("replacement").factory,
    });
    await replacement.start();
    signaling.releaseJoin();
    await expect(starting).rejects.toThrow(/cancelled/);
    expect(replacement.started).toBe(true);
    expect(signaling.leaveCalls).toBe(1);
    await replacement.close();
  });

  it("buffers bounded known-peer signaling delivered before join resolves", async () => {
    const signaling = new EarlyMessageSignalingAdapter(
      BOB,
      encodePeerSignal(candidateMessage("first")),
    );
    const peerHarness = harness("alice");
    const transport = new FullMeshTransport({
      roomId: ROOM,
      self: ALICE,
      roster: ROSTER,
      signaling,
      createPeerConnection: peerHarness.factory,
      maxPendingIceCandidates: 1,
    });

    await transport.start();
    await transport.whenIdle();
    signaling.emit(BOB, encodePeerSignal(candidateMessage("second")));
    await transport.whenIdle();

    expect(transport.failures[0]?.error.message).toBe(
      "Pending ICE candidate limit exceeded",
    );
    await transport.close();
  });

  it("validates roster membership and releases identities and peers on close", async () => {
    const network = new InMemorySignalingNetwork();
    const aliceHarness = harness("alice");
    expect(
      () =>
        new FullMeshTransport({
          roomId: ROOM,
          self: ALICE,
          roster: [ALICE, BOB],
          signaling: network.createAdapter(),
          createPeerConnection: aliceHarness.factory,
        }),
    ).toThrow(/between 3 and 8/);
    expect(
      () =>
        new FullMeshTransport({
          roomId: ROOM,
          self: ALICE,
          roster: [ALICE, BOB, BOB],
          signaling: network.createAdapter(),
          createPeerConnection: aliceHarness.factory,
        }),
    ).toThrow(/duplicate/);
    expect(
      () =>
        new FullMeshTransport({
          roomId: ROOM,
          self: MALLORY,
          roster: ROSTER,
          signaling: network.createAdapter(),
          createPeerConnection: aliceHarness.factory,
        }),
    ).toThrow(/local identity/);
    expect(
      () =>
        new FullMeshTransport({
          roomId: ROOM,
          self: ALICE,
          roster: ROSTER,
          signaling: network.createAdapter(),
          rtcConfiguration: {
            iceServers: [{ urls: "turn:turn.example.test" }],
          },
          createPeerConnection: aliceHarness.factory,
        }),
    ).toThrow(/STUN/);

    const alice = mesh(network, ALICE, aliceHarness);
    await alice.start();
    await alice.close();
    expect(alice.peers).toEqual([]);
    expect(aliceHarness.connections().every(({ closed }) => closed)).toBe(true);

    const replacement = network.createAdapter();
    await replacement.join(ROOM, ALICE);
    await replacement.leave();
  });

  it("replaces just one roster peer without leaving the room or waiting for HELLO", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const signaling = network.createAdapter();
    const leave = vi.spyOn(signaling, "leave");
    const disconnected = vi.fn();
    const channels = vi.fn();
    const alice = mesh(network, ALICE, peerHarness, channels, {
      signaling,
      onPeerDisconnected: disconnected,
    });
    const bob = network.createAdapter();
    const received: Uint8Array[] = [];
    bob.onMessage((_from, payload) => received.push(payload));
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    const old = peerHarness.connection(BOB);
    const unaffected = peerHarness.connection(CAROL);
    const oldChannel = old.createdChannels[0]!;

    await alice.reconnectPeer(BOB);
    const replacement = peerHarness.connection(BOB);
    expect(replacement).not.toBe(old);
    expect(old.closed).toBe(true);
    expect(oldChannel.closed).toBe(true);
    expect(replacement.createdChannels[0]).toMatchObject({
      label: DATA_CHANNEL_LABEL,
      id: 0,
      negotiated: true,
      ordered: true,
      maxPacketLifeTime: null,
      maxRetransmits: null,
      readyState: "connecting",
    });
    expect(replacement.signalingState).toBe("have-local-offer");
    expect(received.map(decodePeerSignal)).toEqual([
      expect.objectContaining({ kind: "description", descriptionType: "offer" }),
    ]);
    expect(alice.peers.map(({ generation }) => generation)).toEqual([2, 1]);
    expect(channels.mock.calls.map(([remote, , generation]) => [key(remote), generation]))
      .toEqual([[key(BOB), 1], [key(CAROL), 1], [key(BOB), 2]]);
    expect(disconnected).toHaveBeenCalledExactlyOnceWith(BOB, 1);
    expect(peerHarness.connection(CAROL)).toBe(unaffected);
    expect(unaffected.closed).toBe(false);
    expect(leave).not.toHaveBeenCalled();
    expect(signaling.isJoinedAs(ROOM, ALICE)).toBe(true);

    alice.disconnectPeer(BOB, 1);
    expect(replacement.closed).toBe(false);
    alice.disconnectPeer(BOB, 2);
    alice.disconnectPeer(BOB, 2);
    await alice.reconnectPeer(BOB);
    expect(alice.peers.map(({ generation }) => generation)).toEqual([3, 1]);
    expect(disconnected.mock.calls).toEqual([[BOB, 1], [BOB, 2]]);
    await Promise.all([alice.close(), bob.leave()]);
  });

  it("revokes a generation before notifying or closing and retires it exactly once", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const errors = vi.fn(() => { throw new Error("error observer failed"); });
    const disconnected = vi.fn((remote: IdentityPublicKey, generation: number) => {
      const peer = peerHarness.connection(remote);
      expect(peer.closed).toBe(false);
      expect(peer.createdChannels[0]?.closed).toBe(false);
      expect(alice.peers.find(({ identity }) => key(identity) === key(remote))).toMatchObject({
        generation,
        hasDataChannel: false,
        signalingState: "closed",
        connectionState: "closed",
      });
      expect(() => alice.dtlsFingerprints(remote)).toThrow(/retired|active/);
      alice.disconnectPeer(remote, generation);
      throw new Error("disconnect observer failed");
    });
    const alice = mesh(network, ALICE, peerHarness, undefined, {
      onPeerDisconnected: disconnected,
      onError: errors,
    });
    await alice.start();
    const old = peerHarness.connection(BOB);
    const closeChannel = vi.spyOn(old.createdChannels[0]!, "close");
    alice.disconnectPeer(BOB, 1);
    alice.disconnectPeer(BOB);
    old.emitConnectionState("failed");
    old.createdChannels[0]!.dispatchEvent(new Event("close"));
    await alice.close();
    await alice.close();
    alice.disconnectPeer(BOB, 1);

    expect(old.closeCalls).toBe(1);
    expect(closeChannel).toHaveBeenCalledTimes(1);
    expect(disconnected.mock.calls).toEqual([[BOB, 1], [CAROL, 1]]);
    expect(alice.failures.map(({ error }) => error.message)).toEqual([
      "disconnect observer failed", "error observer failed",
      "disconnect observer failed", "error observer failed",
    ]);
  });

  it.each(["disconnected", "failed", "closed", "channel-close", "channel-closing"] as const)(
    "retires unavailable peers on %s and accepts a fresh remote offer",
    async (state) => {
      const network = new InMemorySignalingNetwork();
      const peerHarness = harness("alice");
      const disconnected = vi.fn();
      const alice = mesh(network, ALICE, peerHarness, undefined, {
        onPeerDisconnected: disconnected,
      });
      const bob = network.createAdapter();
      bob.onMessage(() => undefined);
      await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
      const old = peerHarness.connection(BOB);
      old.emitConnectionState("connecting");
      old.emitConnectionState("connected");
      expect(alice.peers[0]?.connectionState).toBe("connected");
      await bob.send(ALICE, encodePeerSignal(offer("101")));
      await alice.whenIdle();
      if (state === "channel-close") {
        old.createdChannels[0]!.close();
      } else if (state === "channel-closing") {
        old.createdChannels[0]!.readyState = "closing";
      } else {
        old.emitConnectionState(state);
      }
      await bob.send(ALICE, encodePeerSignal(offer("102")));
      await alice.whenIdle();

      expect(old.closed).toBe(true);
      expect(disconnected).toHaveBeenCalledExactlyOnceWith(BOB, 1);
      expect(alice.peers[0]).toMatchObject({ generation: 2, hasDataChannel: true });
      expect(peerHarness.connection(BOB).remoteDescription?.sdp).toBe(offer("102").sdp);
      expect(peerHarness.connection(BOB).signalingState).toBe("stable");
      expect(alice.failures).toEqual([]);
      await Promise.all([alice.close(), bob.leave()]);
    },
  );

  it("does not revive a retired peer on candidates, answers, or known old offers", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const channels = vi.fn();
    const alice = mesh(network, ALICE, peerHarness, channels);
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    await bob.send(ALICE, encodePeerSignal(offer("101")));
    await alice.whenIdle();
    alice.disconnectPeer(BOB);
    await bob.send(ALICE, encodePeerSignal(candidateMessage("late")));
    await bob.send(ALICE, encodePeerSignal({ ...offer("102"), descriptionType: "answer" }));
    await bob.send(ALICE, encodePeerSignal(offer("101")));
    await alice.whenIdle();
    expect(alice.peers[0]).toMatchObject({ generation: 1, hasDataChannel: false });
    expect(peerHarness.connections()).toHaveLength(2);
    expect(channels).toHaveBeenCalledTimes(2);
    await expect(alice.requestNegotiation(BOB)).rejects.toThrow(/retired/);
    await expect(alice.connectionPath(BOB)).rejects.toThrow(/retired/);
    await Promise.all([alice.close(), bob.leave()]);
  });

  it.each(["before retirement", "while retired"] as const)(
    "retains bounded matching pre-offer candidates received %s",
    async (timing) => {
      const network = new InMemorySignalingNetwork();
      const peerHarness = harness("alice");
      const signaling = network.createAdapter();
      const alice = mesh(network, ALICE, peerHarness, undefined, {
        signaling, maxPendingIceCandidates: 2,
      });
      const bob = network.createAdapter();
      bob.onMessage(() => undefined);
      await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
      await bob.send(ALICE, encodePeerSignal(offer("101", "bob", "old")));
      await alice.whenIdle();
      const old = peerHarness.connection(BOB);
      if (timing === "while retired") alice.disconnectPeer(BOB);
      signaling.deliver(BOB, encodePeerSignal(candidateMessage("fresh", "new")));
      signaling.deliver(BOB, encodePeerSignal(candidateMessage("other", "other")));
      if (timing === "before retirement") alice.disconnectPeer(BOB);
      signaling.deliver(BOB, encodePeerSignal(candidateMessage("fresh", "new")));
      signaling.deliver(BOB, encodePeerSignal(candidateMessage("stale", "old")));
      signaling.deliver(BOB, encodePeerSignal(candidateMessage("ambiguous", null)));
      signaling.deliver(BOB, encodePeerSignal({
        kind: "candidate", candidate: null, sdpMid: null,
        sdpMLineIndex: null, usernameFragment: null,
      }));
      signaling.deliver(BOB, encodePeerSignal(candidateMessage("over-limit", "new")));
      expect(alice.peers[0]).toMatchObject({ generation: 1, hasDataChannel: false });
      expect(peerHarness.connections()).toHaveLength(2);
      signaling.deliver(BOB, encodePeerSignal(offer("102", "bob", "new")));
      await alice.whenIdle();

      const replacement = peerHarness.connection(BOB);
      expect(old.addedCandidates).toEqual([]);
      expect(replacement.addedCandidates).toEqual([
        expect.objectContaining({ candidate: "fresh", usernameFragment: "new" }),
      ]);
      expect(alice.failures.map(({ error }) => error.message)).toEqual([
        "Pending ICE candidate limit exceeded",
      ]);
      expect(alice.peers[0]?.generation).toBe(2);
      // Nonmatching buffered candidates must not leak into a subsequent replacement.
      signaling.deliver(BOB, encodePeerSignal(offer("103", "bob", "other")));
      await alice.whenIdle();
      expect(peerHarness.connection(BOB).addedCandidates).toEqual([]);
      await Promise.all([alice.close(), bob.leave()]);
    },
  );

  it.each(["setLocalDescription", "setRemoteDescription"] as const)(
    "captures a candidate immediately ahead of a restart offer while %s fills the old queue",
    async (method) => {
      const network = new InMemorySignalingNetwork();
      const peerHarness = harness("alice");
      const signaling = network.createAdapter();
      const alice = mesh(network, ALICE, peerHarness, undefined, {
        signaling, maxQueuedPeerOperations: 1, maxPendingIceCandidates: 1,
      });
      const bob = network.createAdapter();
      bob.onMessage(() => undefined);
      await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
      await bob.send(ALICE, encodePeerSignal(offer("101", "bob", "old")));
      await alice.whenIdle();
      const old = peerHarness.connection(BOB);
      const entered = deferred();
      const pending = deferred();
      const operation = vi.spyOn(old, method).mockImplementationOnce(async () => {
        entered.resolve();
        await pending.promise;
        throw new Error("retired SDP operation failed late");
      });
      let negotiating: Promise<unknown> | undefined;
      if (method === "setLocalDescription") {
        negotiating = expect(alice.requestNegotiation(BOB)).rejects.toThrow(/superseded/);
      } else {
        signaling.deliver(BOB, encodePeerSignal({
          ...offer("101", "bob", "old"),
          sdp: offer("101", "bob", "old").sdp.replace(" 1 IN", " 2 IN"),
        }));
      }
      await entered.promise;
      signaling.deliver(BOB, encodePeerSignal(candidateMessage("fresh", "new")));
      signaling.deliver(BOB, encodePeerSignal(offer("102", "bob", "new")));
      expect(peerHarness.connection(BOB)).not.toBe(old);
      await alice.whenIdle();
      await negotiating;
      const replacement = peerHarness.connection(BOB);
      expect(replacement.addedCandidates).toEqual([
        expect.objectContaining({ candidate: "fresh", usernameFragment: "new" }),
      ]);
      expect(operation).toHaveBeenCalledTimes(1);
      pending.resolve();
      await settle(alice);
      expect(replacement.addedCandidates).toHaveLength(1);
      expect(replacement.closed).toBe(false);
      expect(old.addedCandidates).toEqual([]);
      expect(alice.failures).toEqual([]);
      await Promise.all([alice.close(), bob.leave()]);
    },
  );

  it("keeps future candidates visible and bounded while an old candidate flush is stalled", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const signaling = network.createAdapter();
    const alice = mesh(network, ALICE, peerHarness, undefined, {
      signaling, maxPendingIceCandidates: 2,
    });
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    const old = peerHarness.connection(BOB);
    const entered = deferred();
    const pending = deferred();
    const addIce = vi.spyOn(old, "addIceCandidate").mockImplementationOnce(async () => {
      entered.resolve();
      await pending.promise;
    });
    signaling.deliver(BOB, encodePeerSignal(candidateMessage("old-first", "old")));
    signaling.deliver(BOB, encodePeerSignal(candidateMessage("fresh", "new")));
    signaling.deliver(BOB, encodePeerSignal(offer("101", "bob", "old")));
    await entered.promise;
    signaling.deliver(BOB, encodePeerSignal(candidateMessage("over-limit", "new")));
    signaling.deliver(BOB, encodePeerSignal(offer("102", "bob", "new")));
    await alice.whenIdle();
    const replacement = peerHarness.connection(BOB);
    expect(replacement.addedCandidates).toEqual([
      expect.objectContaining({ candidate: "fresh", usernameFragment: "new" }),
    ]);
    expect(alice.failures.map(({ error }) => error.message)).toEqual([
      "Pending ICE candidate limit exceeded",
    ]);
    pending.resolve();
    await settle(alice);
    expect(addIce).toHaveBeenCalledTimes(1);
    expect(replacement.addedCandidates).toHaveLength(1);
    await Promise.all([alice.close(), bob.leave()]);
  });

  it("does not migrate candidates without a matching non-null offer ufrag", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const signaling = network.createAdapter();
    const alice = mesh(network, ALICE, peerHarness, undefined, { signaling });
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    signaling.deliver(BOB, encodePeerSignal(candidateMessage("fresh", "new")));
    signaling.deliver(BOB, encodePeerSignal(candidateMessage("ambiguous", null)));
    alice.disconnectPeer(BOB);
    signaling.deliver(BOB, encodePeerSignal({
      ...offer("102"), sdp: offer("102").sdp.replace("a=ice-ufrag:ufrag\r\n", ""),
    }));
    await alice.whenIdle();
    expect(alice.peers[0]?.generation).toBe(2);
    expect(peerHarness.connection(BOB).addedCandidates).toEqual([]);
    await Promise.all([alice.close(), bob.leave()]);
  });

  it("does not apply queued candidates when processing them discovers native failure", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const signaling = network.createAdapter();
    const alice = mesh(network, ALICE, peerHarness, undefined, { signaling });
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    signaling.deliver(BOB, encodePeerSignal(offer("101", "bob", "old")));
    await alice.whenIdle();
    const old = peerHarness.connection(BOB);
    signaling.deliver(BOB, encodePeerSignal(candidateMessage("fresh", "new")));
    signaling.deliver(BOB, encodePeerSignal(candidateMessage("queued-old", "old")));
    old.connectionState = "failed";
    await alice.whenIdle();
    expect(old.closed).toBe(true);
    expect(old.addedCandidates).toEqual([]);
    signaling.deliver(BOB, encodePeerSignal(offer("102", "bob", "new")));
    await alice.whenIdle();
    expect(peerHarness.connection(BOB).addedCandidates).toEqual([
      expect.objectContaining({ candidate: "fresh", usernameFragment: "new" }),
    ]);
    expect(alice.failures).toEqual([]);
    await Promise.all([alice.close(), bob.leave()]);
  });

  it("commits successful answer metadata and flushes its buffered ICE generation", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const signaling = network.createAdapter();
    const alice = mesh(network, ALICE, peerHarness, undefined, { signaling });
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    await alice.requestNegotiation(BOB);
    const original = peerHarness.connection(BOB);
    signaling.deliver(BOB, encodePeerSignal(candidateMessage("answer-candidate", "answer")));
    signaling.deliver(BOB, encodePeerSignal({
      ...offer("101", "bob", "answer"), descriptionType: "answer",
    }));
    await alice.whenIdle();
    expect(original.signalingState).toBe("stable");
    expect(original.addedCandidates).toEqual([
      expect.objectContaining({ candidate: "answer-candidate", usernameFragment: "answer" }),
    ]);
    signaling.deliver(BOB, encodePeerSignal(offer("102", "bob", "new")));
    await alice.whenIdle();
    expect(alice.peers[0]?.generation).toBe(2);
    expect(original.closed).toBe(true);
    expect(peerHarness.connection(BOB).remoteDescription?.sdp).toBe(offer("102", "bob", "new").sdp);
    expect(alice.failures).toEqual([]);
    await Promise.all([alice.close(), bob.leave()]);
  });

  it.each(["unsolicited", "rejected"] as const)("keeps healthy session metadata after an answer is %s", async (mode) => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const signaling = network.createAdapter();
    const disconnected = vi.fn();
    const alice = mesh(network, ALICE, peerHarness, undefined, {
      signaling, onPeerDisconnected: disconnected,
    });
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    signaling.deliver(BOB, encodePeerSignal(offer("101")));
    await alice.whenIdle();
    const healthy = peerHarness.connection(BOB);
    healthy.emitConnectionState("connected");
    const remote = vi.spyOn(healthy, "setRemoteDescription");
    if (mode === "rejected") {
      await alice.requestNegotiation(BOB);
      remote.mockRejectedValueOnce(new Error("Invalid remote answer SDP"));
    }
    signaling.deliver(BOB, encodePeerSignal({
      ...offer("102", "carol"), descriptionType: "answer",
    }));
    await alice.whenIdle();
    if (mode === "rejected") {
      expect(alice.failures.map(({ error }) => error.message)).toEqual(["Invalid remote answer SDP"]);
      expect(healthy.signalingState).toBe("have-local-offer");
      signaling.deliver(BOB, encodePeerSignal({
        ...offer("101"), descriptionType: "answer", sdp: offer("101").sdp.replace(" 1 IN", " 2 IN"),
      }));
      await alice.whenIdle();
    } else {
      expect(remote).not.toHaveBeenCalled();
      expect(alice.failures).toEqual([]);
    }
    const renegotiation = {
      ...offer("101"), sdp: offer("101").sdp.replace(" 1 IN", " 3 IN"),
    };
    signaling.deliver(BOB, encodePeerSignal(renegotiation));
    await alice.whenIdle();
    expect(peerHarness.connection(BOB)).toBe(healthy);
    expect(healthy.remoteDescription?.sdp).toBe(renegotiation.sdp);
    expect(alice.peers[0]?.generation).toBe(1);
    expect(disconnected).not.toHaveBeenCalled();
    // The unused answer must not become a retired-session replay tombstone either.
    signaling.deliver(BOB, encodePeerSignal(offer("102", "carol")));
    await alice.whenIdle();
    expect(alice.peers[0]?.generation).toBe(2);
    expect(peerHarness.connection(BOB).remoteDescription?.sdp).toBe(offer("102", "carol").sdp);
    await Promise.all([alice.close(), bob.leave()]);
  });

  it("does not observe answer session metadata until SDP succeeds in the current generation", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const signaling = network.createAdapter();
    const alice = mesh(network, ALICE, peerHarness, undefined, { signaling });
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    signaling.deliver(BOB, encodePeerSignal(offer("101")));
    await alice.whenIdle();
    await alice.requestNegotiation(BOB);
    const old = peerHarness.connection(BOB);
    const entered = deferred();
    const pending = deferred();
    vi.spyOn(old, "setRemoteDescription").mockImplementationOnce(async (description) => {
      entered.resolve();
      await pending.promise;
      old.remoteDescription = description;
    });
    signaling.deliver(BOB, encodePeerSignal({ ...offer("102"), descriptionType: "answer" }));
    await entered.promise;
    signaling.deliver(BOB, encodePeerSignal(offer("101")));
    expect(peerHarness.connection(BOB)).toBe(old);
    signaling.deliver(BOB, encodePeerSignal(offer("103")));
    await alice.whenIdle();
    pending.resolve();
    await settle(alice);
    expect(alice.peers[0]?.generation).toBe(2);
    signaling.deliver(BOB, encodePeerSignal(offer("102")));
    await alice.whenIdle();
    expect(alice.peers[0]?.generation).toBe(3);
    expect(peerHarness.connection(BOB).remoteDescription?.sdp).toBe(offer("102").sdp);
    expect(alice.failures).toEqual([]);
    await Promise.all([alice.close(), bob.leave()]);
  });

  it("rejects unknown reconnect identities without changing roster peers", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const alice = mesh(network, ALICE, peerHarness);
    await expect(alice.reconnectPeer(BOB)).rejects.toThrow(/not active/);
    await alice.start();
    for (const unknown of [ALICE, MALLORY]) {
      alice.disconnectPeer(unknown);
      await expect(alice.reconnectPeer(unknown)).rejects.toThrow(/not a remote peer/);
    }
    expect(() => alice.disconnectPeer(new Uint8Array(1))).toThrow();
    expect(() => alice.disconnectPeer(BOB, Number.NaN)).toThrow(/safe integer/);
    const mallory = network.createAdapter();
    await mallory.join(ROOM, MALLORY);
    await mallory.send(ALICE, encodePeerSignal(offer("999")));
    await alice.whenIdle();
    expect(alice.failures[0]?.error.message).toMatch(/outside the roster/);
    expect(peerHarness.connections()).toHaveLength(2);
    expect(alice.peers.map(({ generation }) => generation)).toEqual([1, 1]);
    await Promise.all([alice.close(), mallory.leave()]);
    await expect(alice.reconnectPeer(BOB)).rejects.toThrow(/not active/);
  });

  it("accepts a unilateral browser restart even while the old connection looks connected", async () => {
    const network = new InMemorySignalingNetwork();
    const aliceHarness = harness("alice");
    const bobHarness = harness("bob");
    const channels = vi.fn();
    const alice = mesh(network, ALICE, aliceHarness, channels);
    const bob = mesh(network, BOB, bobHarness);
    await Promise.all([alice.start(), bob.start()]);
    await bob.requestNegotiation(ALICE);
    await settle(alice, bob);
    const old = aliceHarness.connection(BOB);
    const oldOffer = bobHarness.connection(ALICE).localDescription!;
    old.emitConnectionState("connected");
    await bob.close();
    expect(old.connectionState).toBe("connected");
    const restartedHarness = harness("bob-restarted");
    const restartedSignaling = network.createAdapter();
    const restarted = mesh(network, BOB, restartedHarness, undefined, {
      signaling: restartedSignaling,
    });
    await restarted.start();
    await restarted.requestNegotiation(ALICE);
    await settle(alice, restarted);

    const replacement = aliceHarness.connection(BOB);
    expect(replacement).not.toBe(old);
    expect(old.closed).toBe(true);
    expect(alice.peers.map(({ generation }) => generation)).toEqual([2, 1]);
    expect(replacement.signalingState).toBe("stable");
    expect(restartedHarness.connection(ALICE).signalingState).toBe("stable");
    expect(channels.mock.calls.at(-1)?.[2]).toBe(2);
    await restartedSignaling.send(ALICE, encodePeerSignal({
      kind: "description", descriptionType: "offer", sdp: oldOffer.sdp!,
    }));
    await settle(alice, restarted);
    expect(aliceHarness.connection(BOB)).toBe(replacement);
    expect(alice.failures).toEqual([]);
    expect(restarted.failures).toEqual([]);
    await Promise.all([alice.close(), restarted.close()]);
  });

  it.each(["same-origin", "missing-origin"] as const)(
    "uses a validated changed fingerprint for %s restarts, not SDP versions or ICE restarts",
    async (mode) => {
      const network = new InMemorySignalingNetwork();
      const peerHarness = harness("alice");
      const alice = mesh(network, ALICE, peerHarness);
      const bob = network.createAdapter();
      bob.onMessage(() => undefined);
      await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
      const origin = mode === "same-origin" ? "101" : null;
      const first = offer(origin, "bob");
      await bob.send(ALICE, encodePeerSignal(first));
      await alice.whenIdle();
      const old = peerHarness.connection(BOB);
      old.emitConnectionState("connected");
      await bob.send(ALICE, encodePeerSignal({
        ...first,
        sdp: first.sdp.replace(" 1 IN", " 2 IN").replace("ice-ufrag:ufrag", "ice-ufrag:restart"),
      }));
      await alice.whenIdle();
      expect(peerHarness.connection(BOB)).toBe(old);
      await bob.send(ALICE, encodePeerSignal({
        ...first, sdp: first.sdp.replace(fakeFingerprint("bob"), "malformed"),
      }));
      await alice.whenIdle();
      expect(peerHarness.connection(BOB)).toBe(old);
      const fresh = offer(origin, "carol");
      await bob.send(ALICE, encodePeerSignal(fresh));
      await alice.whenIdle();
      const replacement = peerHarness.connection(BOB);
      expect(replacement).not.toBe(old);
      expect(alice.peers[0]?.generation).toBe(2);
      await bob.send(ALICE, encodePeerSignal(first));
      await alice.whenIdle();
      expect(peerHarness.connection(BOB)).toBe(replacement);
      expect(replacement.remoteDescription?.sdp).toBe(fresh.sdp);
      await Promise.all([alice.close(), bob.leave()]);
    },
  );

  it("bounds retired remote-session memory and rejects recent retired offers and answers", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const alice = mesh(network, ALICE, peerHarness);
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    for (let session = 1; session <= 10; session += 1) {
      await bob.send(ALICE, encodePeerSignal(offer(String(session))));
      await alice.whenIdle();
    }
    const current = peerHarness.connection(BOB);
    for (const session of ["2", "9"]) {
      await bob.send(ALICE, encodePeerSignal(offer(session)));
      await bob.send(ALICE, encodePeerSignal({ ...offer(session), descriptionType: "answer" }));
    }
    await alice.whenIdle();
    expect(peerHarness.connection(BOB)).toBe(current);
    expect(alice.peers[0]?.generation).toBe(10);
    // Once evicted, old untrusted SDP is indistinguishable from an unseen restart.
    await bob.send(ALICE, encodePeerSignal(offer("1")));
    await alice.whenIdle();
    expect(alice.peers[0]?.generation).toBe(11);
    expect(alice.failures).toEqual([]);
    await Promise.all([alice.close(), bob.leave()]);
  });

  it("preserves perfect negotiation during simultaneous same-identity replacements", async () => {
    const network = new InMemorySignalingNetwork();
    const aliceHarness = harness("alice");
    const bobHarness = harness("bob");
    const alice = mesh(network, ALICE, aliceHarness);
    const bob = mesh(network, BOB, bobHarness);
    await Promise.all([alice.start(), bob.start()]);
    await alice.requestNegotiation(BOB);
    await settle(alice, bob);
    const oldAlice = aliceHarness.connection(BOB);
    const oldBob = bobHarness.connection(ALICE);

    await Promise.all([alice.reconnectPeer(BOB), bob.reconnectPeer(ALICE)]);
    await settle(alice, bob);
    const newAlice = aliceHarness.connection(BOB);
    const newBob = bobHarness.connection(ALICE);
    expect(oldAlice.closed && oldBob.closed).toBe(true);
    expect(alice.peers[0]?.generation).toBe(2);
    expect(bob.peers[0]?.generation).toBe(2);
    expect(newAlice.signalingState).toBe("stable");
    expect(newBob.signalingState).toBe("stable");
    expect(newAlice.remoteOffers).toBe(0);
    expect(newBob.rollbacks).toBe(1);
    expect(alice.failures).toEqual([]);
    expect(bob.failures).toEqual([]);
    await Promise.all([alice.close(), bob.close()]);
  });

  it("automatically replaces the other endpoint after a unilateral local reconnect", async () => {
    const network = new InMemorySignalingNetwork();
    const aliceHarness = harness("alice");
    const bobHarness = harness("bob");
    const alice = mesh(network, ALICE, aliceHarness);
    const bob = mesh(network, BOB, bobHarness);
    await Promise.all([alice.start(), bob.start()]);
    await alice.requestNegotiation(BOB);
    await settle(alice, bob);
    const oldBob = bobHarness.connection(ALICE);
    const unaffected = bobHarness.connection(CAROL);
    oldBob.emitConnectionState("connected");

    await alice.reconnectPeer(BOB);
    await settle(alice, bob);
    expect(oldBob.closed).toBe(true);
    expect(bob.peers.map(({ generation }) => generation)).toEqual([2, 1]);
    expect(bobHarness.connection(CAROL)).toBe(unaffected);
    expect(unaffected.closed).toBe(false);
    expect(aliceHarness.connection(BOB).signalingState).toBe("stable");
    expect(bobHarness.connection(ALICE).signalingState).toBe("stable");
    expect(alice.failures).toEqual([]);
    expect(bob.failures).toEqual([]);
    await Promise.all([alice.close(), bob.close()]);
  });

  it("rechecks queued offers against the remote session learned by preceding work", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const signaling = network.createAdapter();
    const alice = mesh(network, ALICE, peerHarness, undefined, { signaling });
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    signaling.deliver(BOB, encodePeerSignal(offer("101")));
    signaling.deliver(BOB, encodePeerSignal(offer("102")));
    signaling.deliver(BOB, encodePeerSignal(candidateMessage("queued-for-retired-peer")));
    await alice.whenIdle();
    expect(alice.peers[0]?.generation).toBe(2);
    expect(peerHarness.connection(BOB).remoteDescription?.sdp).toBe(offer("102").sdp);
    expect(peerHarness.connection(BOB).addedCandidates).toEqual([]);
    expect(alice.failures).toEqual([]);
    await Promise.all([alice.close(), bob.leave()]);
  });

  it("ignores saved native callbacks, including callbacks handed a replacement channel", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const signaling = network.createAdapter();
    const send = vi.spyOn(signaling, "send");
    const listenerSpy = vi.spyOn(FakeDataChannel.prototype, "addEventListener");
    const alice = mesh(network, ALICE, peerHarness, undefined, { signaling });
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    const old = peerHarness.connection(BOB);
    const onNegotiation = old.onnegotiationneeded!;
    const onIce = old.onicecandidate!;
    const onData = old.ondatachannel!;
    const onState = old.onconnectionstatechange!;
    const onClose = listenerSpy.mock.calls[0]![1] as EventListener;
    listenerSpy.mockRestore();
    await alice.reconnectPeer(BOB);
    const replacement = peerHarness.connection(BOB);
    const channel = replacement.createdChannels[0]!;
    send.mockClear();
    onNegotiation(new Event("negotiationneeded"));
    onIce({ candidate: null } as RTCPeerConnectionIceEvent);
    onData({ channel } as unknown as RTCDataChannelEvent);
    onState(new Event("connectionstatechange"));
    onClose(new Event("close"));
    old.createdChannels[0]!.dispatchEvent(new Event("close"));
    await alice.whenIdle();

    expect(send).not.toHaveBeenCalled();
    expect(alice.failures).toEqual([]);
    expect(replacement.closed).toBe(false);
    expect(channel.closed).toBe(false);
    expect(alice.peers[0]?.generation).toBe(2);
    await Promise.all([alice.close(), bob.leave()]);
  });

  it.each(["resolve", "reject"] as const)(
    "isolates a late setLocalDescription %s and discards queued old-generation work",
    async (outcome) => {
      const network = new InMemorySignalingNetwork();
      const peerHarness = harness("alice");
      const signaling = network.createAdapter();
      const send = vi.spyOn(signaling, "send");
      const errors = vi.fn();
      const alice = mesh(network, ALICE, peerHarness, undefined, { signaling, onError: errors });
      const bob = network.createAdapter();
      bob.onMessage(() => undefined);
      await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
      const old = peerHarness.connection(BOB);
      const entered = deferred();
      const pending = deferred();
      const local = vi.spyOn(old, "setLocalDescription").mockImplementationOnce(async () => {
        entered.resolve();
        await pending.promise;
        old.localDescription = { type: "offer", sdp: offer("901").sdp };
      });
      const negotiating = expect(alice.requestNegotiation(BOB)).rejects.toThrow(/superseded/);
      await entered.promise;
      old.emitNegotiationNeeded();
      old.emitIceCandidate(null);
      const idle = alice.whenIdle();
      await alice.reconnectPeer(BOB);
      await negotiating;
      await idle;
      expect(local).toHaveBeenCalledTimes(1);
      expect(send).toHaveBeenCalledTimes(1);
      if (outcome === "resolve") pending.resolve();
      else pending.reject(new Error("late local failure"));
      await settle(alice);
      expect(send).toHaveBeenCalledTimes(1);
      expect(errors).not.toHaveBeenCalled();
      expect(alice.failures).toEqual([]);
      expect(peerHarness.connection(BOB).closed).toBe(false);
      await Promise.all([alice.close(), bob.leave()]);
    },
  );

  it.each(["resolve", "reject"] as const)(
    "replaces an in-flight remote offer without waiting for its late %s",
    async (outcome) => {
      const network = new InMemorySignalingNetwork();
      const peerHarness = harness("alice");
      const signaling = network.createAdapter();
      const send = vi.spyOn(signaling, "send");
      const alice = mesh(network, ALICE, peerHarness, undefined, { signaling });
      const bob = network.createAdapter();
      bob.onMessage(() => undefined);
      await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
      const old = peerHarness.connection(BOB);
      const entered = deferred();
      const pending = deferred();
      vi.spyOn(old, "setRemoteDescription").mockImplementationOnce(async (description) => {
        entered.resolve();
        await pending.promise;
        old.remoteDescription = description;
      });
      const local = vi.spyOn(old, "setLocalDescription");
      await bob.send(ALICE, encodePeerSignal(candidateMessage("old-candidate")));
      await bob.send(ALICE, encodePeerSignal(offer("101")));
      await entered.promise;
      const idle = alice.whenIdle();
      await bob.send(ALICE, encodePeerSignal(offer("102")));
      await idle;
      const replacement = peerHarness.connection(BOB);
      expect(replacement).not.toBe(old);
      expect(replacement.remoteDescription?.sdp).toBe(offer("102").sdp);
      expect(send).toHaveBeenCalledTimes(1);
      expect(local).not.toHaveBeenCalled();
      if (outcome === "resolve") pending.resolve();
      else pending.reject(new Error("late remote failure"));
      await settle(alice);
      expect(local).not.toHaveBeenCalled();
      expect(send).toHaveBeenCalledTimes(1);
      expect(old.addedCandidates).toEqual([]);
      expect(replacement.addedCandidates).toEqual([]);
      expect(replacement.closed).toBe(false);
      expect(alice.failures).toEqual([]);
      await Promise.all([alice.close(), bob.leave()]);
    },
  );

  it("does not send a retired answer when setLocalDescription settles after replacement", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const signaling = network.createAdapter();
    const send = vi.spyOn(signaling, "send");
    const alice = mesh(network, ALICE, peerHarness, undefined, { signaling });
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    const old = peerHarness.connection(BOB);
    const entered = deferred();
    const pending = deferred();
    vi.spyOn(old, "setLocalDescription").mockImplementationOnce(async () => {
      entered.resolve();
      await pending.promise;
      old.localDescription = { type: "answer", sdp: offer("901").sdp };
    });
    await bob.send(ALICE, encodePeerSignal(offer("101")));
    await entered.promise;
    await alice.reconnectPeer(BOB);
    pending.resolve();
    await settle(alice);
    expect(send).toHaveBeenCalledTimes(1);
    expect(decodePeerSignal(send.mock.calls[0]![1])).toMatchObject({ descriptionType: "offer" });
    expect(alice.failures).toEqual([]);
    await Promise.all([alice.close(), bob.leave()]);
  });

  it("stops a retired candidate flush and gives the replacement fresh bounded ICE accounting", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const alice = mesh(network, ALICE, peerHarness, undefined, {
      maxPendingIceCandidates: 2, maxAcceptedIceCandidates: 1,
    });
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    const old = peerHarness.connection(BOB);
    const entered = deferred();
    const pending = deferred();
    const addIce = vi.spyOn(old, "addIceCandidate").mockImplementationOnce(async () => {
      entered.resolve();
      await pending.promise;
    });
    const local = vi.spyOn(old, "setLocalDescription");
    await bob.send(ALICE, encodePeerSignal(candidateMessage("first")));
    await bob.send(ALICE, encodePeerSignal(candidateMessage("second")));
    await bob.send(ALICE, encodePeerSignal(offer("101")));
    await entered.promise;
    await bob.send(ALICE, encodePeerSignal(offer("102")));
    await alice.whenIdle();
    pending.resolve();
    await settle(alice);
    expect(addIce).toHaveBeenCalledTimes(1);
    expect(local).not.toHaveBeenCalled();
    await bob.send(ALICE, encodePeerSignal(candidateMessage("first")));
    await bob.send(ALICE, encodePeerSignal(candidateMessage("first")));
    await bob.send(ALICE, encodePeerSignal(candidateMessage("second")));
    await alice.whenIdle();
    expect(peerHarness.connection(BOB).addedCandidates).toEqual([
      expect.objectContaining({ candidate: "first" }),
    ]);
    expect(alice.failures.map(({ error }) => error.message)).toEqual([
      "Accepted ICE candidate limit exceeded",
    ]);
    await Promise.all([alice.close(), bob.leave()]);
  });

  it("suppresses failures of already-submitted old signaling and rejects stale stats", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const signaling = network.createAdapter();
    const entered = deferred();
    const pending = deferred();
    vi.spyOn(signaling, "send").mockImplementationOnce(async () => {
      entered.resolve();
      await pending.promise;
    });
    const errors = vi.fn();
    const alice = mesh(network, ALICE, peerHarness, undefined, { signaling, onError: errors });
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    const old = peerHarness.connection(BOB);
    const stats = deferred();
    vi.spyOn(old, "getStats").mockImplementationOnce(async () => {
      await stats.promise;
      return statsReport([]);
    });
    const inspecting = expect(alice.connectionPath(BOB)).rejects.toThrow(/superseded/);
    const negotiating = expect(alice.requestNegotiation(BOB)).rejects.toThrow(/superseded/);
    await entered.promise;
    await alice.reconnectPeer(BOB);
    await negotiating;
    pending.reject(new Error("late send failed"));
    stats.resolve();
    await inspecting;
    await settle(alice);
    expect(errors).not.toHaveBeenCalled();
    expect(peerHarness.connection(BOB).closed).toBe(false);
    await Promise.all([alice.close(), bob.leave()]);
  });

  it("bounds queued work independently for each replacement generation", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const alice = mesh(network, ALICE, peerHarness, undefined, { maxQueuedPeerOperations: 1 });
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    const entered = deferred();
    const pending = deferred();
    vi.spyOn(peerHarness.connection(BOB), "setLocalDescription").mockImplementationOnce(async () => {
      entered.resolve();
      await pending.promise;
    });
    const negotiating = expect(alice.requestNegotiation(BOB)).rejects.toThrow(/superseded/);
    await entered.promise;
    await expect(alice.requestNegotiation(BOB)).rejects.toThrow(/operation limit/);
    await alice.reconnectPeer(BOB);
    await negotiating;
    expect(peerHarness.connection(BOB).signalingState).toBe("have-local-offer");
    pending.resolve();
    await settle(alice);
    expect(alice.failures.map(({ error }) => error.message)).toEqual([
      "Queued peer operation limit exceeded",
    ]);
    await Promise.all([alice.close(), bob.leave()]);
  });

  it("still closes the peer connection when native channel closure throws", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const disconnected = vi.fn();
    const alice = mesh(network, ALICE, peerHarness, undefined, {
      onPeerDisconnected: disconnected,
    });
    await alice.start();
    const old = peerHarness.connection(BOB);
    vi.spyOn(old.createdChannels[0]!, "close").mockImplementationOnce(() => {
      throw new Error("native channel close failed");
    });
    alice.disconnectPeer(BOB);
    alice.disconnectPeer(BOB);
    expect(old.closed).toBe(true);
    expect(old.closeCalls).toBe(1);
    expect(alice.peers[0]?.hasDataChannel).toBe(false);
    expect(disconnected).toHaveBeenCalledExactlyOnceWith(BOB, 1);
    expect(alice.failures[0]?.error.message).toBe("native channel close failed");
    await alice.close();
  });

  it("keeps the retired slot after a replacement factory fails, without retrying", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const factory = vi.fn(peerHarness.factory);
    const alice = mesh(network, ALICE, peerHarness, undefined, { createPeerConnection: factory });
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    factory.mockImplementationOnce(() => { throw new Error("native creation failed"); });
    await expect(alice.reconnectPeer(BOB)).rejects.toThrow(/native creation failed/);
    await alice.whenIdle();
    expect(factory).toHaveBeenCalledTimes(3);
    expect(alice.peers[0]).toMatchObject({ generation: 1, hasDataChannel: false });
    await bob.send(ALICE, encodePeerSignal(offer("101")));
    await alice.whenIdle();
    expect(alice.peers[0]).toMatchObject({ generation: 2, hasDataChannel: true });
    expect(peerHarness.connection(BOB).signalingState).toBe("stable");
    await Promise.all([alice.close(), bob.leave()]);
  });

  it("reports a failed incoming replacement channel and does not retry its replayed offer", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const factory = vi.fn(peerHarness.factory);
    const disconnected = vi.fn();
    const alice = mesh(network, ALICE, peerHarness, undefined, {
      createPeerConnection: factory, onPeerDisconnected: disconnected,
    });
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    await bob.send(ALICE, encodePeerSignal(offer("101")));
    await alice.whenIdle();
    factory.mockImplementationOnce((remote, configuration) => {
      const connection = peerHarness.factory(remote, configuration);
      vi.spyOn(connection, "createDataChannel").mockImplementationOnce(() => {
        throw new Error("native channel creation failed");
      });
      return connection;
    });
    await bob.send(ALICE, encodePeerSignal(offer("102")));
    await alice.whenIdle();
    expect(alice.peers[0]).toMatchObject({ generation: 2, hasDataChannel: false });
    expect(peerHarness.connection(BOB).closed).toBe(true);
    expect(alice.failures.map(({ error }) => error.message)).toEqual([
      "native channel creation failed",
    ]);
    expect(disconnected.mock.calls).toEqual([[BOB, 1], [BOB, 2]]);
    await bob.send(ALICE, encodePeerSignal(offer("102")));
    await alice.whenIdle();
    expect(factory).toHaveBeenCalledTimes(3);
    await bob.send(ALICE, encodePeerSignal(offer("103")));
    await alice.whenIdle();
    expect(alice.peers[0]).toMatchObject({ generation: 3, hasDataChannel: true });
    await Promise.all([alice.close(), bob.leave()]);
  });

  it("does not overwrite a replacement installed by a retirement observer", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const errors = vi.fn(() => alice.disconnectPeer(BOB));
    let reentrant: Promise<void> | undefined;
    const alice = mesh(network, ALICE, peerHarness, undefined, {
      onPeerDisconnected: (remote, generation) => {
        if (key(remote) === key(BOB) && generation === 1) {
          reentrant = alice.reconnectPeer(remote);
          throw new Error("retired observer failed after replacement");
        }
      },
      onError: errors,
    });
    const bob = network.createAdapter();
    bob.onMessage(() => undefined);
    await Promise.all([alice.start(), bob.join(ROOM, BOB)]);
    const old = peerHarness.connection(BOB);
    await expect(alice.reconnectPeer(BOB)).rejects.toThrow(/superseded/);
    await reentrant;
    expect(peerHarness.connections()).toHaveLength(3);
    expect(old.closed).toBe(true);
    expect(peerHarness.connection(BOB).closed).toBe(false);
    expect(alice.peers[0]?.generation).toBe(2);
    expect(errors).not.toHaveBeenCalled();
    expect(alice.failures[0]?.error.message).toMatch(/retired observer failed/);
    await Promise.all([alice.close(), bob.leave()]);
  });

  it("allows channel observers to retire new generations without automatic retries", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const channels = vi.fn((remote: IdentityPublicKey, _channel: RTCDataChannel, generation: number) => {
      if (key(remote) === key(BOB)) {
        alice.disconnectPeer(remote, generation);
        throw new Error("authentication observer failed after retirement");
      }
    });
    const errors = vi.fn();
    const alice = mesh(network, ALICE, peerHarness, channels, { onError: errors });
    await alice.start();
    await expect(alice.reconnectPeer(BOB)).rejects.toThrow(/superseded/);
    await alice.whenIdle();
    expect(channels).toHaveBeenCalledTimes(3);
    expect(alice.peers[0]).toMatchObject({ generation: 2, hasDataChannel: false });
    expect(errors).not.toHaveBeenCalled();
    expect(peerHarness.connections()).toHaveLength(3);
    await alice.close();
  });

  it("fails closed when the next peer generation cannot be represented safely", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    const alice = mesh(network, ALICE, peerHarness);
    await alice.start();
    const old = peerHarness.connection(BOB);
    // Exercise the overflow branch without allocating 2^53 peer generations.
    const safeInteger = vi.spyOn(Number, "isSafeInteger").mockReturnValueOnce(false);
    try {
      await expect(alice.reconnectPeer(BOB)).rejects.toThrow(/generation limit/);
      expect(safeInteger).toHaveBeenCalledWith(2);
    } finally {
      safeInteger.mockRestore();
    }
    expect(old.closed).toBe(true);
    expect(alice.peers[0]).toMatchObject({ generation: 1, hasDataChannel: false });
    expect(peerHarness.connections()).toHaveLength(2);
    await alice.close();
  });

  it("does not resurrect startup when a channel observer closes during peer creation", async () => {
    const network = new InMemorySignalingNetwork();
    const peerHarness = harness("alice");
    let closing: Promise<void> | undefined;
    const alice = mesh(network, ALICE, peerHarness, () => { closing = alice.close(); });
    await expect(alice.start()).rejects.toThrow(/cancelled/);
    await closing;
    expect(alice.started).toBe(false);
    expect(alice.peers).toEqual([]);
    expect(peerHarness.connections()).toHaveLength(1);
    expect(peerHarness.connections()[0]?.closed).toBe(true);
  });
});

describe("explicit dynamic lobby membership", () => {
  it("starts with a host alone and admits an authorized offer without placeholder peers", async () => {
    const network = new InMemorySignalingNetwork();
    const hostHarness = harness("host");
    const guestHarness = harness("guest");
    const admission = vi.fn((remote: IdentityPublicKey) => { remote.fill(0xff); return true; });
    const host = mesh(network, ALICE, hostHarness, undefined, { membership: "lobby", roster: [ALICE], onUnknownPeer: admission });
    const guest = mesh(network, BOB, guestHarness, undefined, { membership: "lobby", roster: [BOB, ALICE] });
    await host.start();
    expect(host.peers).toEqual([]);
    await guest.start();
    await guest.requestNegotiation(ALICE);
    await settle(host, guest);
    expect(admission).toHaveBeenCalledTimes(1);
    expect(host.peers).toMatchObject([{ identity: BOB, signalingState: "stable" }]);
    expect(guest.peers).toMatchObject([{ identity: ALICE, signalingState: "stable" }]);
    await Promise.all([host.close(), guest.close()]);
  });

  it.each(["before glare", "after answer"] as const)(
    "keeps late guests on the winning ICE generation when the losing offer first arrives %s",
    async (delivery) => {
      const network = new InMemorySignalingNetwork();
      const bobHarness = harness("bob");
      const carolHarness = harness("carol");
      const bobSignaling = network.createAdapter();
      const carolSignaling = network.createAdapter();
      const bob = mesh(network, BOB, bobHarness, undefined, {
        membership: "lobby", roster: [BOB, ALICE], signaling: bobSignaling,
      });
      const carol = mesh(network, CAROL, carolHarness, undefined, {
        membership: "lobby", roster: [CAROL, ALICE], signaling: carolSignaling,
      });
      await Promise.all([bob.start(), carol.start()]);
      const bobSent: Uint8Array[] = [];
      const carolSent: Uint8Array[] = [];
      const bobEntered = deferred();
      const carolEntered = deferred();
      const ack = deferred();
      vi.spyOn(bobSignaling, "send").mockImplementation(async (_to, payload) => {
        bobSent.push(payload);
        bobEntered.resolve();
        await ack.promise;
      });
      vi.spyOn(carolSignaling, "send").mockImplementation(async (_to, payload) => {
        carolSent.push(payload);
        carolEntered.resolve();
        await ack.promise;
      });
      const admittingBob = bob.admitPeer(CAROL);
      const admittingCarol = carol.admitPeer(BOB);
      const bobToCarol = bobHarness.connection(CAROL);
      const carolToBob = carolHarness.connection(BOB);
      bobToCarol.emitNegotiationNeeded();
      carolToBob.emitNegotiationNeeded();
      await Promise.all([bobEntered.promise, carolEntered.promise]);
      const candidate = {
        candidate: "candidate:1 1 UDP 1 192.0.2.1 5000 typ host",
        sdpMid: "0", sdpMLineIndex: 0, usernameFragment: "carol-2",
      };
      carolToBob.emitIceCandidate(candidate);
      const losingOffer = {
        kind: "description", descriptionType: "offer", sdp: carolToBob.localDescription!.sdp!,
      } as const;
      expect(losingOffer.sdp).not.toBe((decodePeerSignal(carolSent[0]!) as DescriptionSignal).sdp);
      if (delivery === "before glare") bobSignaling.deliver(CAROL, carolSent[0]!);
      carolSignaling.deliver(BOB, bobSent[0]!);
      ack.resolve();
      await Promise.all([admittingBob, admittingCarol]);
      await settle(bob, carol);
      expect(carolToBob.rollbacks).toBe(1);
      const answer = carolToBob.localDescription!;
      expect(answer.type).toBe("answer");
      expect(answer.sdp).not.toContain("a=ice-ufrag:carol-2\r\n");
      const answerSignal = carolSent.find((payload) => {
        const signal = decodePeerSignal(payload);
        return signal.kind === "description" && signal.descriptionType === "answer";
      })!;
      const answerCandidate = { ...candidate, usernameFragment: "carol-2-rollback-1" };
      bobSignaling.deliver(CAROL, encodePeerSignal(candidateMessage(
        answerCandidate.candidate, answerCandidate.usernameFragment,
      )));
      bobSignaling.deliver(CAROL, answerSignal);
      await bob.whenIdle();
      expect(bobToCarol.remoteDescription).toEqual(answer);

      // A retransmission of the rolled-back offer is not a new negotiation, even in stable.
      const bobBeforeReplay = bobSent.length;
      const carolBeforeReplay = carolSent.length;
      bobSignaling.deliver(CAROL, encodePeerSignal(losingOffer));
      bobSignaling.deliver(CAROL, carolSent[0]!);
      const winningOffer = decodePeerSignal(bobSent[0]!) as DescriptionSignal;
      const winningReplay = {
        ...winningOffer,
        sdp: winningOffer.sdp + `a=${candidate.candidate}\r\na=end-of-candidates\r\n`,
      };
      carolSignaling.deliver(BOB, encodePeerSignal(winningReplay));
      await settle(bob, carol);
      for (const payload of bobSent.slice(bobBeforeReplay)) carolSignaling.deliver(BOB, payload);
      for (const payload of carolSent.slice(carolBeforeReplay)) bobSignaling.deliver(CAROL, payload);
      await settle(bob, carol);
      expect(bobToCarol.remoteOffers).toBe(0);
      expect(carolToBob.remoteOffers).toBe(1);
      expect(carolToBob.localDescription).toEqual(answer);
      expect(bobToCarol.remoteDescription).toEqual(answer);
      expect(bobToCarol.addedCandidates).toEqual([answerCandidate]);
      expect(bobToCarol.signalingState).toBe("stable");
      expect(carolToBob.signalingState).toBe("stable");

      carolToBob.emitNegotiationNeeded();
      await carol.whenIdle();
      const nextOffer = carolSent.at(-1)!;
      carolSignaling.deliver(BOB, encodePeerSignal(winningReplay));
      await carol.whenIdle();
      expect(carolToBob.signalingState).toBe("have-local-offer");
      expect(carolToBob.rollbacks).toBe(1);
      bobSignaling.deliver(CAROL, nextOffer);
      await bob.whenIdle();
      carolSignaling.deliver(BOB, bobSent.at(-1)!);
      await carol.whenIdle();
      expect(bobToCarol.signalingState).toBe("stable");
      expect(carolToBob.signalingState).toBe("stable");
      expect(bobHarness.connections()).toHaveLength(2);
      expect(carolHarness.connections()).toHaveLength(2);
      expect(bob.failures).toEqual([]);
      expect(carol.failures).toEqual([]);
      await Promise.all([bob.close(), carol.close()]);
    },
  );

  it.each([false, "throw", "promise"] as const)("does not allocate resources without literal authorization: %s", async (decision) => {
    const network = new InMemorySignalingNetwork();
    const hostHarness = harness("host");
    const admission = vi.fn(() => {
      if (decision === "throw") { throw new Error("admission failed"); }
      return decision === "promise" ? Promise.resolve(true) as unknown as boolean : false;
    });
    const host = mesh(network, ALICE, hostHarness, undefined, { membership: "lobby", roster: [ALICE], onUnknownPeer: admission });
    const sender = network.createAdapter();
    sender.onMessage(() => undefined);
    await Promise.all([host.start(), sender.join(ROOM, BOB)]);
    await sender.send(ALICE, encodePeerSignal(candidateMessage("unknown ICE")));
    await sender.send(ALICE, encodePeerSignal({ kind: "description", descriptionType: "answer", sdp: "v=0\r\n" }));
    expect(admission).not.toHaveBeenCalled();
    await sender.send(ALICE, encodePeerSignal({ kind: "description", descriptionType: "offer", sdp: "v=0\r\n" }));
    await host.whenIdle();
    expect(admission).toHaveBeenCalledTimes(1);
    expect(hostHarness.connections()).toEqual([]);
    await Promise.all([host.close(), sender.leave()]);
  });

  it("removes members, frees capacity, and does not revive them from saved callbacks", async () => {
    const network = new InMemorySignalingNetwork();
    const hostHarness = harness("host");
    const host = mesh(network, ALICE, hostHarness, undefined, { membership: "lobby", roster: [ALICE, BOB] });
    const guest = network.createAdapter();
    guest.onMessage(() => undefined);
    await Promise.all([host.start(), guest.join(ROOM, BOB)]);
    const old = hostHarness.connection(BOB);
    const callback = old.onconnectionstatechange;
    const generation = host.peers[0]!.generation;
    host.removePeer(BOB);
    expect(host.peers).toEqual([]);
    expect(old.closed).toBe(true);
    await host.admitPeer(BOB);
    expect(host.peers[0]!.generation).toBeGreaterThan(generation);
    callback?.(new Event("connectionstatechange"));
    host.disconnectPeer(BOB, generation);
    expect(host.peers[0]!.connectionState).not.toBe("closed");
    expect(() => host.removePeer(ALICE)).toThrow(/local identity/);
    await Promise.all([host.close(), guest.leave()]);
  });

  it("bounds dynamic admission and preserves finalized membership invariants", async () => {
    const network = new InMemorySignalingNetwork();
    const lobby = mesh(network, ALICE, harness("lobby"), undefined, { membership: "lobby", roster: [ALICE] });
    await lobby.start();
    for (let fill = 2; fill <= 8; fill += 1) { await lobby.admitPeer(identity(fill)).catch(() => undefined); }
    expect(lobby.peers).toHaveLength(7);
    await expect(lobby.admitPeer(identity(9))).rejects.toThrow(/member limit/);
    lobby.removePeer(identity(8));
    await lobby.admitPeer(identity(9)).catch(() => undefined);
    expect(lobby.peers).toHaveLength(7);
    await lobby.close();
    const fixed = mesh(network, ALICE, harness("fixed"));
    await fixed.start();
    await expect(fixed.admitPeer(MALLORY)).rejects.toThrow(/lobby mesh/);
    expect(() => fixed.removePeer(BOB)).toThrow(/lobby mesh/);
    await fixed.close();
    expect(() => mesh(network, ALICE, harness("invalid"), undefined, { roster: [ALICE] })).toThrow(/between 3 and 8/);
  });

  it("does not admit after the authorization callback closes the mesh", async () => {
    const network = new InMemorySignalingNetwork();
    const hostHarness = harness("host");
    let closed: Promise<void> | undefined;
    const host = mesh(network, ALICE, hostHarness, undefined, {
      membership: "lobby", roster: [ALICE], onUnknownPeer: () => { closed = host.close(); return true; },
    });
    const sender = network.createAdapter();
    sender.onMessage(() => undefined);
    await Promise.all([host.start(), sender.join(ROOM, BOB)]);
    await sender.send(ALICE, encodePeerSignal({ kind: "description", descriptionType: "offer", sdp: "v=0\r\n" }));
    await closed;
    expect(hostHarness.connections()).toEqual([]);
    await sender.leave();
  });
});

interface Harness {
  readonly factory: MeshPeerConnectionFactory;
  connection(remote: IdentityPublicKey): FakePeerConnection;
  connections(): readonly FakePeerConnection[];
  createdChannels(): readonly FakeDataChannel[];
  createdChannelCount(): number;
}

function harness(
  localName: string,
  channelOverrides: RTCDataChannelInit = {},
): Harness {
  const peers = new Map<string, FakePeerConnection>();
  const connections: FakePeerConnection[] = [];
  return {
    factory: (remote, configuration) => {
      const connection = new FakePeerConnection(
        `${localName}-${remote[0]}${peers.has(key(remote)) ? `-${connections.length}` : ""}`,
        configuration,
        channelOverrides,
      );
      peers.set(key(remote), connection);
      connections.push(connection);
      return connection;
    },
    connection: (remote) => {
      const connection = peers.get(key(remote));
      if (connection === undefined) {
        throw new Error("Missing fake peer connection");
      }
      return connection;
    },
    connections: () => [...connections],
    createdChannels: () => connections.flatMap(({ createdChannels }) => createdChannels),
    createdChannelCount: () =>
      connections.reduce(
        (total, { createdChannels }) => total + createdChannels.length,
        0,
      ),
  };
}

function mesh(
  network: InMemorySignalingNetwork,
  self: IdentityPublicKey,
  peerHarness: Harness,
  onDataChannel?: FullMeshTransportOptions["onUnauthenticatedDataChannel"],
  options: Partial<FullMeshTransportOptions> = {},
): FullMeshTransport {
  return new FullMeshTransport({
    roomId: ROOM,
    self,
    roster: ROSTER,
    signaling: network.createAdapter(),
    createPeerConnection: peerHarness.factory,
    ...(onDataChannel === undefined
      ? {}
      : { onUnauthenticatedDataChannel: onDataChannel }),
    ...options,
  });
}

async function settle(...meshes: readonly FullMeshTransport[]): Promise<void> {
  for (let pass = 0; pass < 8; pass += 1) {
    await Promise.all(meshes.map((mesh) => mesh.whenIdle()));
    await Promise.resolve();
  }
}

function candidateMessage(candidate: string, usernameFragment: string | null = "ufrag"): CandidateSignal {
  return {
    kind: "candidate",
    candidate,
    sdpMid: "0",
    sdpMLineIndex: 0,
    usernameFragment,
  };
}

function offer(origin: string | null, fingerprintName = "bob", usernameFragment = "ufrag"): DescriptionSignal {
  return {
    kind: "description",
    descriptionType: "offer",
    sdp: "v=0\r\n" +
      (origin === null ? "" : `o=- ${origin} 1 IN IP4 0.0.0.0\r\n`) +
      `a=ice-ufrag:${usernameFragment}\r\na=fingerprint:sha-256 ${fakeFingerprint(fingerprintName)}\r\n`,
  };
}

function deferred(): { promise: Promise<void>; resolve: () => void; reject: (error: Error) => void } {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

class FakePeerConnection implements MeshPeerConnection {
  signalingState: RTCSignalingState = "stable";
  connectionState: RTCPeerConnectionState = "new";
  iceGatheringState: RTCIceGatheringState = "complete";
  localDescription: RTCSessionDescriptionInit | null = null;
  remoteDescription: RTCSessionDescriptionInit | null = null;
  onnegotiationneeded: ((event: Event) => void) | null = null;
  onicecandidate: ((event: RTCPeerConnectionIceEvent) => void) | null = null;
  ondatachannel: ((event: RTCDataChannelEvent) => void) | null = null;
  onconnectionstatechange: ((event: Event) => void) | null = null;
  readonly addedCandidates: Array<RTCIceCandidateInit | null> = [];
  readonly createdChannels: FakeDataChannel[] = [];
  readonly configuration: RTCConfiguration;
  closed = false;
  closeCalls = 0;
  rollbacks = 0;
  remoteOffers = 0;
  stats = statsReport([]);
  #descriptionSequence = 0;
  #currentLocalDescription: RTCSessionDescriptionInit | null = null;
  #iceGeneration = 0;
  static #nextSession = 1;
  readonly #session = FakePeerConnection.#nextSession++;
  readonly #name: string;
  readonly #channelOverrides: RTCDataChannelInit;

  constructor(
    name: string,
    configuration: RTCConfiguration,
    channelOverrides: RTCDataChannelInit,
  ) {
    this.#name = name;
    this.configuration = configuration;
    this.#channelOverrides = { ...channelOverrides };
  }

  async setLocalDescription(description?: RTCSessionDescriptionInit): Promise<void> {
    if (this.closed) {
      throw new Error("Fake peer is closed");
    }
    const selected = description ?? this.#automaticLocalDescription();
    if (selected.type === "offer") {
      if (this.signalingState !== "stable" && this.signalingState !== "have-local-offer") {
        throw new Error(`Unexpected local offer in ${this.signalingState}`);
      }
      this.signalingState = "have-local-offer";
    } else if (selected.type === "answer") {
      if (this.signalingState !== "have-remote-offer") {
        throw new Error("Cannot answer without a remote offer");
      }
      this.signalingState = "stable";
      this.#currentLocalDescription = { ...selected };
    } else {
      throw new Error(`Unsupported local ${selected.type}`);
    }
    this.localDescription = { ...selected };
  }

  async setRemoteDescription(description: RTCSessionDescriptionInit): Promise<void> {
    if (this.closed) {
      throw new Error("Fake peer is closed");
    }
    if (description.type === "offer") {
      if (this.signalingState === "have-local-offer") {
        this.rollbacks += 1;
        this.localDescription = this.#currentLocalDescription;
        // Chromium discards the initial offer's ICE credentials on implicit rollback.
        if (this.#currentLocalDescription === null) this.#iceGeneration += 1;
      } else if (this.signalingState !== "stable" && this.signalingState !== "have-remote-offer") {
        throw new Error(`Unexpected remote offer in ${this.signalingState}`);
      }
      this.remoteOffers += 1;
      this.remoteDescription = { ...description };
      this.signalingState = "have-remote-offer";
      return;
    }
    if (description.type === "answer" && this.signalingState === "have-local-offer") {
      this.remoteDescription = { ...description };
      this.#currentLocalDescription = this.localDescription;
      this.signalingState = "stable";
      return;
    }
    throw new Error(`Unexpected remote ${description.type} in ${this.signalingState}`);
  }

  async addIceCandidate(candidate?: RTCIceCandidateInit | null): Promise<void> {
    if (this.closed || this.remoteDescription === null) {
      throw new Error("Cannot add ICE without an active remote description");
    }
    if (candidate?.usernameFragment &&
        !this.remoteDescription.sdp?.includes(`a=ice-ufrag:${candidate.usernameFragment}\r\n`)) {
      throw new Error("ICE candidate belongs to a different remote generation");
    }
    this.addedCandidates.push(candidate ?? null);
  }

  createDataChannel(label: string, options: RTCDataChannelInit = {}): RTCDataChannel {
    const channel = new FakeDataChannel(label, { ...options, ...this.#channelOverrides });
    this.createdChannels.push(channel);
    return channel as unknown as RTCDataChannel;
  }

  async getStats(): Promise<RTCStatsReport> {
    return this.stats;
  }

  close(): void {
    this.closeCalls += 1;
    this.closed = true;
    this.signalingState = "closed";
    this.emitConnectionState("closed");
  }

  emitConnectionState(state: RTCPeerConnectionState): void {
    this.connectionState = state;
    this.onconnectionstatechange?.(new Event("connectionstatechange"));
  }

  emitNegotiationNeeded(): void {
    if (this.signalingState !== "stable") throw new Error("negotiationneeded requires stable");
    this.onnegotiationneeded?.(new Event("negotiationneeded"));
  }

  emitIceCandidate(candidate: RTCIceCandidateInit | null): void {
    if (this.localDescription !== null) {
      this.localDescription = {
        ...this.localDescription,
        sdp: this.localDescription.sdp +
          (candidate === null ? "a=end-of-candidates\r\n" : `a=${candidate.candidate}\r\n`),
      };
      if (this.signalingState === "stable") this.#currentLocalDescription = this.localDescription;
    }
    const browserCandidate =
      candidate === null
        ? null
        : ({ toJSON: () => ({ ...candidate }) } as RTCIceCandidate);
    this.onicecandidate?.({ candidate: browserCandidate } as RTCPeerConnectionIceEvent);
  }

  emitDataChannel(channel: FakeDataChannel): void {
    this.ondatachannel?.({ channel: channel as unknown as RTCDataChannel } as RTCDataChannelEvent);
  }

  #automaticLocalDescription(): RTCSessionDescriptionInit {
    this.#descriptionSequence += 1;
    const sdp =
      `v=0\r\no=- ${this.#session} ${this.#descriptionSequence} IN IP4 0.0.0.0\r\n` +
      `a=ice-ufrag:${this.#name}${this.#iceGeneration === 0 ? "" : `-rollback-${this.#iceGeneration}`}\r\n` +
      `a=fingerprint:sha-256 ${fakeFingerprint(this.#name)}\r\n` +
      `a=x-description:${this.#descriptionSequence}\r\n`;
    if (this.signalingState === "have-remote-offer") {
      return { type: "answer", sdp };
    }
    if (this.signalingState === "stable" || this.signalingState === "have-local-offer") {
      return { type: "offer", sdp };
    }
    throw new Error(`Cannot create a local description in ${this.signalingState}`);
  }
}

class FakeDataChannel extends EventTarget {
  readonly label: string;
  readonly id: number | null;
  readonly negotiated: boolean;
  readonly ordered: boolean;
  readonly maxPacketLifeTime: number | null;
  readonly maxRetransmits: number | null;
  closed = false;
  readyState: RTCDataChannelState = "connecting";

  constructor(label: string, options: RTCDataChannelInit = {}) {
    super();
    this.label = label;
    this.id = options.id ?? null;
    this.negotiated = options.negotiated ?? false;
    this.ordered = options.ordered ?? true;
    this.maxPacketLifeTime = options.maxPacketLifeTime ?? null;
    this.maxRetransmits = options.maxRetransmits ?? null;
  }

  close(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.readyState = "closed";
    this.dispatchEvent(new Event("close"));
  }
}

class DelayedJoinSignalingAdapter implements SignalingAdapter {
  leaveCalls = 0;
  #joinCalls = 0;
  #handler: SignalingMessageHandler | null = null;
  #releaseJoin: (() => void) | null = null;

  async join(): Promise<void> {
    this.#joinCalls += 1;
    if (this.#joinCalls > 1) {
      return;
    }
    await new Promise<void>((resolve) => {
      this.#releaseJoin = resolve;
    });
  }

  async send(): Promise<void> {
    throw new Error("Delayed signaling does not send");
  }

  onMessage(callback: SignalingMessageHandler): void {
    this.#handler = callback;
  }

  async leave(): Promise<void> {
    this.leaveCalls += 1;
  }

  releaseJoin(): void {
    const release = this.#releaseJoin;
    if (release === null) {
      throw new Error("Join has not started");
    }
    release();
  }
}

class EarlyMessageSignalingAdapter implements SignalingAdapter {
  readonly #from: IdentityPublicKey;
  readonly #payload: Uint8Array;
  #handler: SignalingMessageHandler | null = null;

  constructor(from: IdentityPublicKey, payload: Uint8Array) {
    this.#from = parseIdentityPublicKey(from);
    this.#payload = payload.slice();
  }

  async join(): Promise<void> {
    this.emit(this.#from, this.#payload);
  }

  async send(): Promise<void> {}

  onMessage(callback: SignalingMessageHandler): void {
    this.#handler = callback;
  }

  async leave(): Promise<void> {}

  emit(from: Uint8Array, payload: Uint8Array): void {
    if (this.#handler === null) {
      throw new Error("No early signaling handler");
    }
    this.#handler(parseIdentityPublicKey(from), payload.slice());
  }
}

function identity(fill: number): IdentityPublicKey {
  return parseIdentityPublicKey(new Uint8Array(32).fill(fill));
}

function statsReport(records: readonly Record<string, unknown>[]): RTCStatsReport {
  return new Map(records.map((record) => [String(record["id"]), record])) as unknown as RTCStatsReport;
}

function key(identity: Uint8Array): string {
  return Array.from(identity, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fakeFingerprint(name: string): string {
  const fill = name.charCodeAt(0) & 0xff;
  return new Array<string>(32).fill(fill.toString(16).padStart(2, "0")).join(":");
}
