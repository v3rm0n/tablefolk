import { bytesToHex, hexToBytes } from "@p2pcards/crypto";
import { encodeCanonical } from "@p2pcards/encoding";
import {
  parseIdentityPublicKey,
  type IdentityPublicKey,
} from "@p2pcards/protocol";
import { describe, expect, it, vi } from "vitest";

import { encodeDataFrame, MAX_FRAME_PAYLOAD_BYTES, type DataFrame } from "./frame";
import {
  deriveNostrSignalingTopic,
  MAX_NOSTR_RELAY_MESSAGE_CHARS,
  TrysteroNostrSignalingAdapter,
  type NostrRelaySocket,
  type NostrRelaySocketEvent,
  type TrysteroNostrSignalingAdapterOptions,
} from "./nostr-signaling";
import { MAX_SIGNALING_MESSAGE_BYTES } from "./signaling-message";

const ROOM = "12".repeat(32);
const OTHER_ROOM = "34".repeat(32);
const RELAYS = ["wss://relay-one.example/", "wss://relay-two.example/"] as const;
const THIRD_RELAY = "wss://relay-three.example/";
const ALICE = identity(1);
const BOB = identity(2);
const CAROL = identity(3);
// Independent CBOR encoder + Node createCipheriv("aes-256-gcm"), not Web Crypto.
const FIXTURE_KEY = "1f119e3bb3c8b67c2eaa75a95fa8ad4f1f6f8e619d7d35cbe51c6fee9202814b";
const FIXTURE_AAD = "2ff3f8f1dff56ebfcc181e7fe81aaadd776d1b0010ab83f5b40b831dab2fbf3e";
const FIXTURE_CONTENT =
  "AQQFBgcICQoLDA0OD5Oqzx01V3qouyQECdtoP74dFW31Du5RHVXjQlZ_mZKrVWhC3q2L5yuLsk2eREG6" +
  "daiDkAoNDjrgDeb1tjZYfcgmcL4QHabT7IEvRaKwBurUSMpjyZPkK2HkvOuNPgSoPI7kaK5641KRYEX-8" +
  "JOT0r6oFiEfl1s-viv93X9K299_bJAvyCMx";

describe("Trystero Nostr signaling adapter", () => {
  it("matches independent key, AAD, canonical packet and AES-GCM envelope bytes", async () => {
    const network = new FakeNostrRelayNetwork();
    let nextByte = 0;
    const alice = adapter(network, [RELAYS[0]], {
      randomSource: { fill: (target) => {
        for (let index = 0; index < target.length; index += 1) {
          target[index] = nextByte++;
        }
      } },
    });
    const bob = adapter(network, [RELAYS[0]]);
    const receive = vi.fn();
    bob.onMessage(receive);
    await Promise.all([alice.join(ROOM, ALICE), bob.join(ROOM, BOB)]);
    await alice.send(BOB, new Uint8Array([1, 2, 3]));
    const event = JSON.parse(network.publishedEvents[0]!) as [string, { content: string }];
    expect(event[1].content).toBe(FIXTURE_CONTENT);
    await settle(alice, bob);
    expect(receive).toHaveBeenCalledWith(ALICE, new Uint8Array([1, 2, 3]));
    await Promise.all([alice.leave(), bob.leave()]);
  });

  it("rejects changes to the fixture version, nonce, ciphertext and authentication tag", async () => {
    const network = new FakeNostrRelayNetwork();
    const bob = adapter(network, [RELAYS[0]]);
    const receive = vi.fn();
    bob.onMessage(receive);
    await bob.join(ROOM, BOB);
    const envelope = Uint8Array.from(
      atob(FIXTURE_CONTENT.replace(/-/g, "+").replace(/_/g, "/")),
      (character) => character.charCodeAt(0),
    );
    for (const index of [0, 1, 13, envelope.length - 1]) {
      const altered = envelope.slice();
      altered[index] = altered[index]! ^ 1;
      network.injectContent(btoa(String.fromCharCode(...altered))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
    }
    await bob.whenIdle();
    expect(receive).not.toHaveBeenCalled();
    expect(bob.failures).toHaveLength(4);
    await bob.leave();
  });

  it("encrypts, chunks, reorders, and defensively delivers directed signaling", async () => {
    const network = new FakeNostrRelayNetwork();
    network.holdEvents = true;
    const alice = adapter(network, [RELAYS[0]]);
    const bob = adapter(network, [RELAYS[0]]);
    const received: Array<{ from: Uint8Array; payload: Uint8Array }> = [];
    bob.onMessage((from, payload) => received.push({ from, payload }));
    await Promise.all([alice.join(ROOM, ALICE), bob.join(ROOM, BOB)]);

    const recipient = BOB.slice();
    const payload = new Uint8Array(MAX_FRAME_PAYLOAD_BYTES + 257);
    payload.forEach((_value, index) => {
      payload[index] = index & 0xff;
    });
    const expected = payload.slice();
    const sending = alice.send(recipient, payload);
    recipient.fill(0xff);
    payload.fill(0xff);
    await sending;

    expect(network.publishedEvents).toHaveLength(2);
    for (const encoded of network.publishedEvents) {
      const event = JSON.parse(encoded) as [string, { content: string }];
      expect(event[1].content).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(event[1].content).not.toContain(bytesToHex(ALICE));
    }
    expect(received).toEqual([]);
    network.flushHeldEventsInReverse();
    await settle(alice, bob);

    expect(received).toEqual([{ from: ALICE, payload: expected }]);
    await Promise.all([alice.leave(), bob.leave()]);
  });

  it("isolates rooms, filters non-recipients, and derives stable opaque topics", async () => {
    const network = new FakeNostrRelayNetwork();
    const alice = adapter(network, [RELAYS[0]]);
    const bob = adapter(network, [RELAYS[0]]);
    const carol = adapter(network, [RELAYS[0]]);
    const otherRoom = adapter(network, [RELAYS[0]]);
    const bobHandler = vi.fn();
    const carolHandler = vi.fn();
    const otherHandler = vi.fn();
    bob.onMessage(bobHandler);
    carol.onMessage(carolHandler);
    otherRoom.onMessage(otherHandler);
    await Promise.all([
      alice.join(ROOM, ALICE),
      bob.join(ROOM, BOB),
      carol.join(ROOM, CAROL),
      otherRoom.join(OTHER_ROOM, BOB),
    ]);

    await alice.send(BOB, new Uint8Array([7, 8, 9]));
    await settle(alice, bob, carol, otherRoom);

    expect(bobHandler).toHaveBeenCalledOnce();
    expect(bobHandler).toHaveBeenCalledWith(ALICE, new Uint8Array([7, 8, 9]));
    expect(carolHandler).not.toHaveBeenCalled();
    expect(otherHandler).not.toHaveBeenCalled();
    expect(deriveNostrSignalingTopic("p2pcards/v1", ROOM)).toMatch(/^[0-9a-f]{64}$/);
    expect(deriveNostrSignalingTopic("p2pcards/v1", ROOM)).toBe(
      "4239fdd4ec1963ebed95618c2c3c6591ea5e55a88c9bb56d2ed1e4a8743822b9",
    );
    expect(deriveNostrSignalingTopic("p2pcards/v1", ROOM)).not.toBe(
      deriveNostrSignalingTopic("p2pcards/v1", OTHER_ROOM),
    );

    await Promise.all([alice.leave(), bob.leave(), carol.leave(), otherRoom.leave()]);
  });

  it("deduplicates redundant relays and continues through a surviving relay", async () => {
    const network = new FakeNostrRelayNetwork();
    const alice = adapter(network, RELAYS, {
      reconnectBaseDelayMs: 1,
      reconnectMaxDelayMs: 1,
    });
    const bob = adapter(network, RELAYS, {
      reconnectBaseDelayMs: 1,
      reconnectMaxDelayMs: 1,
    });
    const received: Uint8Array[] = [];
    bob.onMessage((_from, payload) => received.push(payload));
    await Promise.all([alice.join(ROOM, ALICE), bob.join(ROOM, BOB)]);

    await alice.send(BOB, new Uint8Array([1]));
    await settle(alice, bob);
    expect(received).toEqual([new Uint8Array([1])]);
    expect(alice.relayDiagnostics.map(({ state }) => state)).toEqual([
      "connected",
      "connected",
    ]);
    network.replayLastEvent(RELAYS[0], "bb".repeat(32));
    await settle(alice, bob);
    expect(received).toEqual([new Uint8Array([1])]);

    network.failNextPublisherSend(RELAYS[0]);
    await alice.send(BOB, new Uint8Array([2]));
    await settle(alice, bob);
    expect(received).toEqual([new Uint8Array([1]), new Uint8Array([2])]);
    await waitUntil(
      () => alice.relayDiagnostics.every(({ state }) => state === "connected"),
    );

    network.closeRelay(RELAYS[0]);
    await alice.send(BOB, new Uint8Array([3]));
    await settle(alice, bob);
    expect(received).toEqual([
      new Uint8Array([1]),
      new Uint8Array([2]),
      new Uint8Array([3]),
    ]);
    await waitUntil(
      () => alice.relayDiagnostics.every(({ state }) => state === "connected"),
    );

    await Promise.all([alice.leave(), bob.leave()]);
  });

  it("replays recent ephemeral signaling when temporarily disjoint relays recover", async () => {
    const network = new FakeNostrRelayNetwork();
    const alice = adapter(network, RELAYS, {
      reconnectBaseDelayMs: 50,
      reconnectMaxDelayMs: 50,
    });
    const bob = adapter(network, RELAYS, {
      reconnectBaseDelayMs: 50,
      reconnectMaxDelayMs: 50,
    });
    const received: Uint8Array[] = [];
    bob.onMessage((_from, payload) => received.push(payload));
    await alice.join(ROOM, ALICE);
    await bob.join(ROOM, BOB);

    network.closeSocket(RELAYS[0], 1);
    network.closeSocket(RELAYS[1], 0);
    await alice.send(BOB, new Uint8Array([9]));
    await settle(alice, bob);
    expect(received).toEqual([]);

    await waitUntil(() => received.length === 1);
    expect(received).toEqual([new Uint8Array([9])]);
    await Promise.all([alice.leave(), bob.leave()]);
  });

  it("bounds malformed relay traffic and reports observer failures without delivery", async () => {
    const network = new FakeNostrRelayNetwork();
    const observed = vi.fn(() => {
      throw new Error("observer failed");
    });
    const bob = adapter(network, [RELAYS[0]], { onError: observed, maxRetainedFailures: 2 });
    const handler = vi.fn();
    bob.onMessage(handler);
    await bob.join(ROOM, BOB);
    const topic = deriveNostrSignalingTopic("p2pcards/v1", ROOM);

    network.injectEvent(RELAYS[0], {
      id: "aa".repeat(32),
      tags: [["x", topic]],
      content: "not_base64url!",
    });
    network.injectRaw(RELAYS[0], JSON.stringify(["NOTICE", "rate limited"]));
    network.injectRaw(RELAYS[0], "not json");
    network.injectRaw(RELAYS[0], "x".repeat(MAX_NOSTR_RELAY_MESSAGE_CHARS + 1));
    await settle(bob);

    expect(handler).not.toHaveBeenCalled();
    expect(observed).toHaveBeenCalledTimes(4);
    expect(bob.failures).toHaveLength(2);
    expect(bob.failures.some(({ error }) => error.message === "observer failed")).toBe(true);
    await bob.leave();
  });

  it("rejects ciphertext tampering and signaling encrypted for another room", async () => {
    const network = new FakeNostrRelayNetwork();
    const alice = adapter(network, [RELAYS[0]]);
    const bob = adapter(network, [RELAYS[0]]);
    const otherRoom = adapter(network, [RELAYS[0]]);
    const received: Uint8Array[] = [];
    bob.onMessage((_from, payload) => received.push(payload));
    await Promise.all([
      alice.join(ROOM, ALICE),
      bob.join(ROOM, BOB),
      otherRoom.join(OTHER_ROOM, CAROL),
    ]);

    await alice.send(BOB, new Uint8Array([1]));
    await settle(alice, bob, otherRoom);
    expect(received).toEqual([new Uint8Array([1])]);
    network.injectTamperedLastEvent(RELAYS[0], "cc".repeat(32));

    await otherRoom.send(BOB, new Uint8Array([2]));
    network.injectLastEventForTopic(
      RELAYS[0],
      "dd".repeat(32),
      deriveNostrSignalingTopic("p2pcards/v1", ROOM),
    );
    await settle(alice, bob, otherRoom);

    expect(received).toEqual([new Uint8Array([1])]);
    expect(bob.failures.length).toBeGreaterThanOrEqual(2);
    await Promise.all([alice.leave(), bob.leave(), otherRoom.leave()]);
  });

  it("validates lifecycle, bounds, relay URLs, and failed connections", async () => {
    expect(
      () => new TrysteroNostrSignalingAdapter({ relayUrls: [] }),
    ).toThrow(/1 to 64/);
    expect(
      () => new TrysteroNostrSignalingAdapter({ relayUrls: ["ws://relay.example/"] }),
    ).toThrow(/must use wss/);

    const unavailable = new FakeNostrRelayNetwork();
    unavailable.unavailable.add(RELAYS[0]);
    const failed = adapter(unavailable, [RELAYS[0]]);
    await expect(failed.join(ROOM, ALICE)).rejects.toThrow(/connect to any Nostr relay/);
    expect(failed.joined).toBe(false);

    const network = new FakeNostrRelayNetwork();
    const alice = adapter(network, [RELAYS[0]]);
    await expect(alice.send(BOB, new Uint8Array())).rejects.toThrow(/not joined/);
    await expect(alice.join("room", ALICE)).rejects.toThrow(/64 lowercase/);
    await expect(alice.join(ROOM, new Uint8Array(31))).rejects.toThrow(/exactly 32/);
    await alice.join(ROOM, ALICE);
    await expect(alice.join(ROOM, ALICE)).rejects.toThrow(/already joined/);
    await expect(alice.send(ALICE, new Uint8Array())).rejects.toThrow(/cannot send to itself/);
    await expect(
      alice.send(BOB, new Uint8Array(MAX_SIGNALING_MESSAGE_BYTES + 1)),
    ).rejects.toThrow(/must not exceed/);
    network.rejectPublications = true;
    await expect(alice.send(BOB, new Uint8Array([1]))).rejects.toThrow(
      /rejected publication/,
    );
    network.rejectPublications = false;
    await alice.leave();
    await alice.leave();
    await alice.join(ROOM, ALICE);
    await alice.leave();

    const connectingNetwork = new FakeNostrRelayNetwork();
    connectingNetwork.holdOpen = true;
    const connecting = adapter(connectingNetwork, [RELAYS[0]], {
      connectTimeoutMs: 1_000,
    });
    const joining = connecting.join(ROOM, ALICE);
    await waitUntil(() => connecting.relayDiagnostics.length === 1);
    await connecting.leave();
    await expect(joining).rejects.toThrow(/cancelled/);
  });

  it("waits for every selected relay subscription to reach EOSE", async () => {
    const network = new FakeNostrRelayNetwork();
    network.holdEose = true;
    const alice = adapter(network, RELAYS, { connectTimeoutMs: 1_000 });
    const joining = alice.join(ROOM, ALICE);
    await waitUntil(
      () => alice.relayDiagnostics.length === 2 &&
        alice.relayDiagnostics.every(({ state }) => state === "subscribing"),
    );
    expect(alice.joined).toBe(false);

    network.flushEose();
    await joining;
    expect(alice.joined).toBe(true);
    expect(alice.relayDiagnostics.every(({ state }) => state === "connected")).toBe(true);
    await alice.leave();
  });

  it("selects a deterministic room-specific relay subset", async () => {
    const network = new FakeNostrRelayNetwork();
    const alice = adapter(network, [...RELAYS, THIRD_RELAY], { relayRedundancy: 1 });
    await alice.join(ROOM, ALICE);
    expect(alice.relayDiagnostics.map(({ url }) => url)).toEqual([THIRD_RELAY]);
    await alice.leave();
  });

  it("does not let a cancelled key import corrupt a replacement room", async () => {
    const network = new FakeNostrRelayNetwork();
    const gate = deferred();
    const original = crypto.subtle.importKey.bind(crypto.subtle);
    const spy = vi.spyOn(crypto.subtle, "importKey").mockImplementationOnce(async (...args) => {
      await gate.promise;
      return original(...args);
    });
    const alice = adapter(network, [RELAYS[0]]);
    const bob = adapter(network, [RELAYS[0]]);
    const receive = vi.fn();
    bob.onMessage(receive);
    try {
      const cancelled = alice.join(ROOM, ALICE).catch((error: unknown) => error);
      await alice.leave();
      await Promise.all([alice.join(OTHER_ROOM, ALICE), bob.join(OTHER_ROOM, BOB)]);
      gate.resolve();
      expect(await cancelled).toMatchObject({ message: expect.stringMatching(/cancelled/) });
      await alice.send(BOB, new Uint8Array([7]));
      await settle(alice, bob);
      expect(receive).toHaveBeenCalledWith(ALICE, new Uint8Array([7]));
    } finally {
      gate.resolve();
      spy.mockRestore();
      await Promise.all([alice.leave(), bob.leave()]);
    }
  });

  it("retries a ciphertext dropped at queue admission after capacity is available", async () => {
    const network = new FakeNostrRelayNetwork();
    const bob = adapter(network, [RELAYS[0]], { maxPendingEvents: 1 });
    const receive = vi.fn();
    bob.onMessage(receive);
    await bob.join(ROOM, BOB);
    const second = await sealPacket(ALICE, { id: 2, index: 0, count: 1, bytes: new Uint8Array([2]) });
    network.injectContent(FIXTURE_CONTENT);
    network.injectContent(second);
    await bob.whenIdle();
    expect(receive).toHaveBeenCalledTimes(1);
    network.injectContent(second);
    await bob.whenIdle();
    expect(receive).toHaveBeenCalledTimes(2);
    expect(receive).toHaveBeenLastCalledWith(ALICE, new Uint8Array([2]));
    await bob.leave();
  });

  it("keeps delayed receive work out of a rejoined membership's queue budget", async () => {
    const network = new FakeNostrRelayNetwork();
    const bob = adapter(network, [RELAYS[0]], { maxPendingEvents: 1 });
    const receive = vi.fn();
    bob.onMessage(receive);
    const gate = deferred();
    const original = crypto.subtle.decrypt.bind(crypto.subtle);
    const spy = vi.spyOn(crypto.subtle, "decrypt").mockImplementationOnce(async (...args) => {
      await gate.promise;
      return original(...args);
    });
    try {
      await bob.join(ROOM, BOB);
      network.injectContent(FIXTURE_CONTENT);
      await waitUntil(() => spy.mock.calls.length === 1);
      const oldQueue = bob.whenIdle();
      await bob.leave();
      await bob.join(ROOM, BOB);
      gate.resolve();
      await oldQueue;
      const second = await sealPacket(ALICE, { id: 3, index: 0, count: 1, bytes: new Uint8Array([3]) });
      network.injectContent(FIXTURE_CONTENT);
      network.injectContent(second);
      await bob.whenIdle();
      expect(receive).toHaveBeenCalledTimes(1);
    } finally {
      gate.resolve();
      spy.mockRestore();
      await bob.leave();
    }
  });

  it("bounds concurrent sends while pipelining all fragments ahead of slow ACKs", async () => {
    const network = new FakeNostrRelayNetwork();
    network.holdAcks = true;
    const alice = adapter(network, [RELAYS[0]], { maxConcurrentSends: 1 });
    const bob = adapter(network, [RELAYS[0]]);
    const receive = vi.fn();
    bob.onMessage(receive);
    await Promise.all([alice.join(ROOM, ALICE), bob.join(ROOM, BOB)]);
    const payload = new Uint8Array(MAX_SIGNALING_MESSAGE_BYTES).fill(0x42);
    const sending = alice.send(BOB, payload);
    await expect(alice.send(BOB, payload)).rejects.toThrow(/Concurrent Nostr send limit/);
    await waitUntil(() => network.publishedEvents.length === 17);
    await settle(alice, bob);
    expect(receive).toHaveBeenCalledWith(ALICE, payload);
    network.flushAcks();
    await sending;
    await Promise.all([alice.leave(), bob.leave()]);
  });

  it("lets a newly ready relay ACK complete the original send", async () => {
    const network = new FakeNostrRelayNetwork();
    network.unavailable.add(RELAYS[1]);
    network.mutedAckRelays.add(RELAYS[0]);
    const alice = adapter(network, RELAYS, { reconnectBaseDelayMs: 5, reconnectMaxDelayMs: 5 });
    await alice.join(ROOM, ALICE);
    const sending = alice.send(BOB, new Uint8Array([1]));
    await waitUntil(() => network.publishedEvents.length === 1);
    network.unavailable.clear();
    await sending;
    expect(network.publishedEvents.length).toBeGreaterThanOrEqual(2);
    await alice.leave();
  });

  it("rejects missing publication ACKs and cancels pending sends on leave", async () => {
    const network = new FakeNostrRelayNetwork();
    network.holdAcks = true;
    const alice = adapter(network, [RELAYS[0]], { publicationAckTimeoutMs: 10 });
    await alice.join(ROOM, ALICE);
    await expect(alice.send(BOB, new Uint8Array([1]))).rejects.toThrow(/Timed out/);
    const pending = alice.send(BOB, new Uint8Array([2])).catch((error: unknown) => error);
    await waitUntil(() => network.publishedEvents.length === 2);
    await alice.leave();
    expect(await pending).toMatchObject({ message: expect.stringMatching(/membership changed/) });
    network.flushAcks();
  });

  it("rejects CLOSED subscriptions instead of treating the socket as ready", async () => {
    const network = new FakeNostrRelayNetwork();
    network.rejectSubscriptions = true;
    const alice = adapter(network, [RELAYS[0]]);
    await expect(alice.join(ROOM, ALICE)).rejects.toThrow(/connect to any Nostr relay/);
    expect(alice.joined).toBe(false);
    expect(alice.failures.some(({ error }) => /closed subscription/.test(error.message))).toBe(true);
  });

  it("ignores delayed close events from sockets replaced after a subscription timeout", async () => {
    const network = new FakeNostrRelayNetwork();
    network.withheldEoseRelays.add(RELAYS[1]);
    network.holdClose = true;
    const alice = adapter(network, RELAYS, {
      connectTimeoutMs: 5,
      reconnectBaseDelayMs: 5,
      reconnectMaxDelayMs: 5,
    });
    await alice.join(ROOM, ALICE);
    network.withheldEoseRelays.clear();
    await waitUntil(() => alice.relayDiagnostics.every(({ state }) => state === "connected"));
    network.unavailable.add(RELAYS[0]);
    network.closeRelay(RELAYS[0]);
    network.flushCloses(RELAYS[0]);
    network.holdAcks = true;
    const sending = alice.send(BOB, new Uint8Array([1]));
    await waitUntil(() => network.publishedEvents.length >= 1);
    network.flushCloses(RELAYS[1]);
    network.flushAcks();
    await sending;
    expect(alice.relayDiagnostics.find(({ url }) => url === RELAYS[1])?.state).toBe("connected");
    await alice.leave();
    network.flushCloses();
  });

  it("bounds aggregate sender reassembly and releases it at exact expiry", async () => {
    const network = new FakeNostrRelayNetwork();
    const bob = adapter(network, [RELAYS[0]], {
      maxReassemblySenders: 1,
      maxPendingFrameBytes: 2,
    });
    bob.onMessage(vi.fn());
    await bob.join(ROOM, BOB);
    const partial = { id: 1, index: 0, count: 2, bytes: new Uint8Array([1, 2]) };
    const first = await sealPacket(ALICE, partial);
    const duplicate = await sealPacket(ALICE, partial);
    const other = await sealPacket(CAROL, partial);
    const overflow = await sealPacket(ALICE, { ...partial, id: 2 });
    vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
    try {
      network.injectContent(first);
      await bob.whenIdle();
      network.injectContent(duplicate);
      await bob.whenIdle();
      expect(bob.failures).toEqual([]);
      network.injectContent(other);
      network.injectContent(overflow);
      await bob.whenIdle();
      expect(bob.failures.map(({ error }) => error.message)).toEqual([
        "Nostr reassembly sender limit exceeded",
        "Nostr reassembly capacity exceeded",
      ]);
      await vi.advanceTimersByTimeAsync(30_000);
      network.injectContent(other);
      await bob.whenIdle();
      expect(bob.failures).toHaveLength(2);
      await vi.advanceTimersByTimeAsync(30_000);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      await bob.leave();
      vi.useRealTimers();
    }
  });
});

function adapter(
  network: FakeNostrRelayNetwork,
  relayUrls: readonly string[],
  overrides: TrysteroNostrSignalingAdapterOptions = {},
): TrysteroNostrSignalingAdapter {
  return new TrysteroNostrSignalingAdapter({
    relayUrls,
    relayRedundancy: relayUrls.length,
    connectTimeoutMs: 100,
    createSocket: network.createSocket,
    ...overrides,
  });
}

async function settle(
  ...adapters: readonly TrysteroNostrSignalingAdapter[]
): Promise<void> {
  for (let pass = 0; pass < 6; pass += 1) {
    await Promise.resolve();
    await Promise.all(adapters.map((candidate) => candidate.whenIdle()));
  }
}

async function waitUntil(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) {
      return;
    }
    await new Promise<void>((resolve) => globalThis.setTimeout(resolve, 0));
  }
  throw new Error("Timed out waiting for fake Nostr state");
}

class FakeNostrRelayNetwork {
  readonly unavailable = new Set<string>();
  readonly publishedEvents: string[] = [];
  holdEvents = false;
  holdEose = false;
  holdOpen = false;
  rejectPublications = false;
  rejectSubscriptions = false;
  holdAcks = false;
  holdClose = false;
  readonly mutedAckRelays = new Set<string>();
  readonly withheldEoseRelays = new Set<string>();
  readonly #sockets = new Set<FakeNostrRelaySocket>();
  readonly #heldDeliveries: Array<() => void> = [];
  readonly #heldEose: Array<() => void> = [];
  readonly #heldAcks: Array<() => void> = [];
  readonly #heldCloses: Array<{ url: string; complete: () => void }> = [];

  readonly createSocket = (url: string): NostrRelaySocket => {
    const socket = new FakeNostrRelaySocket(this, url);
    this.#sockets.add(socket);
    queueMicrotask(() => {
      if (this.holdOpen) {
        return;
      }
      if (this.unavailable.has(url)) {
        socket.fail();
      } else {
        socket.open();
      }
    });
    return socket;
  };

  accept(socket: FakeNostrRelaySocket, encoded: string): void {
    const message = JSON.parse(encoded) as unknown[];
    if (message[0] === "REQ") {
      const filter = message[2];
      if (
        !isRecord(filter) ||
        !Array.isArray(filter["#x"]) ||
        typeof filter["#x"][0] !== "string" ||
        !Array.isArray(filter["kinds"]) ||
        typeof filter["kinds"][0] !== "number"
      ) {
        throw new Error("Malformed fake Nostr subscription");
      }
      socket.subscriptionId = String(message[1]);
      socket.topic = filter["#x"][0];
      socket.kind = filter["kinds"][0];
      if (this.rejectSubscriptions) {
        queueMicrotask(() => socket.message(JSON.stringify([
          "CLOSED", socket.subscriptionId, "blocked: test rejection",
        ])));
        return;
      }
      const eose = (): void => {
        if (socket.readyState === 1 && socket.subscriptionId !== null) {
          socket.message(JSON.stringify(["EOSE", socket.subscriptionId]));
        }
      };
      if (this.holdEose || this.withheldEoseRelays.has(socket.url)) {
        this.#heldEose.push(eose);
      } else {
        queueMicrotask(eose);
      }
      return;
    }
    if (message[0] !== "EVENT" || !isRecord(message[1])) {
      throw new Error("Malformed fake Nostr event");
    }
    this.publishedEvents.push(encoded);
    const event = message[1];
    const ack = (): void => socket.message(JSON.stringify([
      "OK",
      event["id"],
      !this.rejectPublications,
      this.rejectPublications ? "blocked: test rejection" : "accepted",
    ]));
    if (!this.mutedAckRelays.has(socket.url)) {
      if (this.holdAcks) {
        this.#heldAcks.push(ack);
      } else {
        queueMicrotask(ack);
      }
    }
    if (this.rejectPublications) {
      return;
    }
    const topic = eventTopic(event);
    for (const target of this.#sockets) {
      if (
        target.readyState !== 1 ||
        target.url !== socket.url ||
        target.topic !== topic ||
        target.kind !== event["kind"] ||
        target.subscriptionId === null
      ) {
        continue;
      }
      const delivery = (): void => target.message(
        JSON.stringify(["EVENT", target.subscriptionId, event]),
      );
      if (this.holdEvents) {
        this.#heldDeliveries.push(delivery);
      } else {
        queueMicrotask(delivery);
      }
    }
  }

  flushEose(): void {
    for (const eose of this.#heldEose.splice(0)) {
      eose();
    }
  }

  flushAcks(): void {
    for (const ack of this.#heldAcks.splice(0)) {
      ack();
    }
  }

  closeEvent(url: string, complete: () => void): void {
    if (this.holdClose) {
      this.#heldCloses.push({ url, complete });
    } else {
      complete();
    }
  }

  flushCloses(url?: string): void {
    for (const closing of this.#heldCloses.splice(0)) {
      if (url === undefined || closing.url === url) {
        closing.complete();
      } else {
        this.#heldCloses.push(closing);
      }
    }
  }

  injectContent(content: string): void {
    this.injectEvent(RELAYS[0], {
      id: "ef".repeat(32),
      content,
      tags: [["x", deriveNostrSignalingTopic("p2pcards/v1", ROOM)]],
    });
  }

  replayLastEvent(url: string, id: string): void {
    const encoded = this.publishedEvents.at(-1);
    if (encoded === undefined) {
      throw new Error("No fake Nostr event to replay");
    }
    const message = JSON.parse(encoded) as unknown[];
    if (!isRecord(message[1])) {
      throw new Error("Malformed saved fake Nostr event");
    }
    this.injectEvent(url, { ...message[1], id } as {
      id: string;
      tags: readonly unknown[];
      content: string;
    });
  }

  injectTamperedLastEvent(url: string, id: string): void {
    const event = this.#lastPublishedEvent();
    const content = String(event["content"]);
    const index = Math.floor(content.length / 2);
    const replacement = content[index] === "A" ? "B" : "A";
    this.injectEvent(url, {
      id,
      tags: event["tags"] as readonly unknown[],
      content: `${content.slice(0, index)}${replacement}${content.slice(index + 1)}`,
    });
  }

  injectLastEventForTopic(url: string, id: string, topic: string): void {
    const event = this.#lastPublishedEvent();
    this.injectEvent(url, {
      id,
      tags: [["x", topic]],
      content: String(event["content"]),
    });
  }

  remove(socket: FakeNostrRelaySocket): void {
    this.#sockets.delete(socket);
  }

  flushHeldEventsInReverse(): void {
    for (const delivery of this.#heldDeliveries.splice(0).reverse()) {
      delivery();
    }
  }

  closeRelay(url: string): void {
    const matches = [...this.#sockets].filter((socket) => socket.url === url);
    if (matches.length === 0) {
      throw new Error("Missing fake relay socket");
    }
    for (const socket of matches) {
      socket.remoteClose();
    }
  }

  closeSocket(url: string, index: number): void {
    const socket = [...this.#sockets].filter((candidate) => candidate.url === url)[index];
    if (socket === undefined) {
      throw new Error("Missing indexed fake relay socket");
    }
    socket.remoteClose();
  }

  failNextPublisherSend(url: string): void {
    const socket = [...this.#sockets].find(
      (candidate) => candidate.url === url && candidate.eventSendCount > 0,
    );
    if (socket === undefined) {
      throw new Error("Missing fake Nostr publisher socket");
    }
    socket.failNextEventSend = true;
  }

  injectEvent(
    url: string,
    event: { readonly id: string; readonly tags: readonly unknown[]; readonly content: string },
  ): void {
    const topic = eventTopic(event as Record<string, unknown>);
    for (const socket of this.#sockets) {
      if (
        socket.url === url &&
        socket.readyState === 1 &&
        socket.subscriptionId !== null &&
        socket.topic === topic
      ) {
        socket.message(JSON.stringify(["EVENT", socket.subscriptionId, event]));
      }
    }
  }

  injectRaw(url: string, message: string): void {
    for (const socket of this.#sockets) {
      if (socket.url === url && socket.readyState === 1) {
        socket.message(message);
      }
    }
  }

  #lastPublishedEvent(): Record<string, unknown> {
    const encoded = this.publishedEvents.at(-1);
    if (encoded === undefined) {
      throw new Error("No fake Nostr event was published");
    }
    const message = JSON.parse(encoded) as unknown[];
    if (!isRecord(message[1])) {
      throw new Error("Malformed saved fake Nostr event");
    }
    return message[1];
  }
}

class FakeNostrRelaySocket implements NostrRelaySocket {
  readyState = 0;
  subscriptionId: string | null = null;
  topic: string | null = null;
  kind: number | null = null;
  eventSendCount = 0;
  failNextEventSend = false;
  readonly url: string;
  readonly #network: FakeNostrRelayNetwork;
  readonly #listeners = new Map<string, Array<(event: NostrRelaySocketEvent) => void>>();

  constructor(network: FakeNostrRelayNetwork, url: string) {
    this.#network = network;
    this.url = url;
  }

  addEventListener(
    type: "open" | "message" | "error" | "close",
    listener: (event: NostrRelaySocketEvent) => void,
  ): void {
    const listeners = this.#listeners.get(type) ?? [];
    listeners.push(listener);
    this.#listeners.set(type, listeners);
  }

  send(data: string): void {
    if (this.readyState !== 1) {
      throw new Error("Fake relay socket is not open");
    }
    const message = JSON.parse(data) as unknown[];
    if (message[0] === "EVENT") {
      if (this.failNextEventSend) {
        this.failNextEventSend = false;
        throw new Error("Injected fake relay send failure");
      }
      this.eventSendCount += 1;
    }
    this.#network.accept(this, data);
  }

  close(): void {
    if (this.readyState >= 2) {
      return;
    }
    this.readyState = 2;
    this.#network.remove(this);
    this.#network.closeEvent(this.url, () => {
      this.readyState = 3;
      this.#emit({ type: "close" });
    });
  }

  open(): void {
    if (this.readyState !== 0) {
      return;
    }
    this.readyState = 1;
    this.#emit({ type: "open" });
  }

  fail(): void {
    if (this.readyState !== 0) {
      return;
    }
    this.#emit({ type: "error" });
    this.close();
  }

  remoteClose(): void {
    this.close();
  }

  message(data: string): void {
    if (this.readyState === 1) {
      this.#emit({ type: "message", data });
    }
  }

  #emit(event: NostrRelaySocketEvent): void {
    for (const listener of this.#listeners.get(event.type) ?? []) {
      listener(event);
    }
  }
}

function eventTopic(event: Record<string, unknown>): string {
  const tags = event["tags"];
  if (!Array.isArray(tags)) {
    throw new Error("Fake Nostr event has no tags");
  }
  for (const tag of tags) {
    if (Array.isArray(tag) && tag[0] === "x" && typeof tag[1] === "string") {
      return tag[1];
    }
  }
  throw new Error("Fake Nostr event has no topic");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function identity(fill: number): IdentityPublicKey {
  return parseIdentityPublicKey(new Uint8Array(32).fill(fill));
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((complete) => { resolve = complete; });
  return { promise, resolve };
}

async function sealPacket(from: Uint8Array, frame: DataFrame): Promise<string> {
  const key = await crypto.subtle.importKey("raw", hexToBytes(FIXTURE_KEY).slice(), "AES-GCM", false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: hexToBytes(FIXTURE_AAD).slice() },
    key,
    encodeCanonical({ from, to: BOB, frame: encodeDataFrame(frame) }).slice(),
  );
  const envelope = new Uint8Array([1, ...nonce, ...new Uint8Array(ciphertext)]);
  return btoa(String.fromCharCode(...envelope)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
