import {
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  type Ed25519SecretKey,
} from "@p2pcards/crypto";
import {
  parseDtlsFingerprint,
  parseGameId,
  parseIdentityPublicKey,
  signHello,
  type DtlsFingerprint,
  type IdentityPublicKey,
} from "@p2pcards/protocol";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  AuthenticatedPeerChannel,
  type ChannelAuthenticationError,
} from "./authenticated-channel";
import { decodeDataFrame, encodeDataFrame, MAX_FRAME_PAYLOAD_BYTES } from "./frame";

const GAME_ID = parseGameId(new Uint8Array(16).fill(7));
const OTHER_GAME_ID = parseGameId(new Uint8Array(16).fill(8));
const ALICE = identity(11);
const BOB = identity(12);
const MALLORY = identity(13);
const ALICE_FP = fingerprint(0x11);
const BOB_FP = fingerprint(0x22);

describe("authenticated peer data channel", () => {
  afterEach(() => vi.useRealTimers());

  it("exchanges reciprocal HELLO messages before carrying framed application payloads", async () => {
    const [aliceWire, bobWire] = linkedChannels();
    const aliceMessages: Uint8Array[] = [];
    const bobMessages: Uint8Array[] = [];
    const authenticated: IdentityPublicKey[] = [];
    const alice = authenticatedChannel(
      aliceWire,
      ALICE,
      BOB,
      ALICE_FP,
      BOB_FP,
      aliceMessages,
      (remote) => authenticated.push(remote),
    );
    const bob = authenticatedChannel(
      bobWire,
      BOB,
      ALICE,
      BOB_FP,
      ALICE_FP,
      bobMessages,
      (remote) => authenticated.push(remote),
    );

    await expect(alice.send(new Uint8Array([1]))).rejects.toMatchObject({
      code: "EXPECTED_HELLO",
    });
    const aliceStarted = alice.start();
    const bobStarted = bob.start();
    aliceWire.open();
    bobWire.open();
    await Promise.all([aliceStarted, bobStarted]);

    expect(alice.authenticated).toBe(true);
    expect(bob.authenticated).toBe(true);
    expect(authenticated).toEqual([BOB.publicKey, ALICE.publicKey]);
    expect(decodeDataFrame(aliceWire.sent[0]!)).toMatchObject({
      id: 0,
      index: 0,
      count: 1,
    });
    expect(decodeDataFrame(bobWire.sent[0]!)).toMatchObject({
      id: 0,
      index: 0,
      count: 1,
    });

    const payload = Uint8Array.from(
      { length: MAX_FRAME_PAYLOAD_BYTES + 1 },
      (_, index) => index & 0xff,
    );
    const sending = alice.send(payload);
    payload.fill(0xff);
    await sending;
    await settleChannel(bob);

    expect(bobMessages).toEqual([
      Uint8Array.from(
        { length: MAX_FRAME_PAYLOAD_BYTES + 1 },
        (_, index) => index & 0xff,
      ),
    ]);
    expect(aliceMessages).toEqual([]);
    expect(aliceWire.sent.slice(1).map(decodeDataFrame)).toMatchObject([
      { id: 1, index: 0, count: 2 },
      { id: 1, index: 1, count: 2 },
    ]);

    alice.close();
    bob.close();
  });

  it("closes when the signed identity is not the expected roster peer", async () => {
    const [aliceWire, bobWire] = linkedChannels();
    const alice = authenticatedChannel(
      aliceWire,
      ALICE,
      BOB,
      ALICE_FP,
      BOB_FP,
      [],
    );
    const bob = authenticatedChannel(
      bobWire,
      BOB,
      MALLORY,
      BOB_FP,
      ALICE_FP,
      [],
    );
    const aliceResult = alice.start().catch((error: unknown) => error);
    const bobStarted = bob.start();
    aliceWire.open();
    bobWire.open();

    await expect(bobStarted).rejects.toMatchObject({ code: "IDENTITY_MISMATCH" });
    await aliceResult;
    expect(bobWire.closed).toBe(true);
    expect(bob.authenticated).toBe(false);
  });

  it("rejects mismatched fingerprints and signatures for another game", async () => {
    const wrongFingerprint = fingerprint(0x33);
    const fingerprintHarness = standaloneAuthentication(BOB, ALICE, BOB_FP, ALICE_FP);
    const fingerprintStarted = fingerprintHarness.authenticator.start();
    fingerprintHarness.channel.open();
    const wrongHello = signHello(
      GAME_ID,
      wrongFingerprint,
      BOB_FP,
      ALICE.secretKey,
    );
    fingerprintHarness.channel.receive(helloFrame(wrongHello.canonicalBytes));
    await expect(fingerprintStarted).rejects.toMatchObject({
      code: "FINGERPRINT_MISMATCH",
    });
    expect(fingerprintHarness.channel.closed).toBe(true);

    const gameHarness = standaloneAuthentication(BOB, ALICE, BOB_FP, ALICE_FP);
    const gameStarted = gameHarness.authenticator.start();
    gameHarness.channel.open();
    const wrongGameHello = signHello(
      OTHER_GAME_ID,
      ALICE_FP,
      BOB_FP,
      ALICE.secretKey,
    );
    gameHarness.channel.receive(helloFrame(wrongGameHello.canonicalBytes));
    await expect(gameStarted).rejects.toMatchObject({ code: "INVALID_HELLO" });
  });

  it("rejects every non-HELLO, fragmented HELLO, and non-binary first message", async () => {
    const applicationFirst = standaloneAuthentication(BOB, ALICE, BOB_FP, ALICE_FP);
    const applicationStarted = applicationFirst.authenticator.start();
    applicationFirst.channel.open();
    applicationFirst.channel.receive(
      encodeDataFrame({ id: 1, index: 0, count: 1, bytes: new Uint8Array([1]) }),
    );
    await expect(applicationStarted).rejects.toMatchObject({ code: "EXPECTED_HELLO" });

    const fragmented = standaloneAuthentication(BOB, ALICE, BOB_FP, ALICE_FP);
    const fragmentedStarted = fragmented.authenticator.start();
    fragmented.channel.open();
    fragmented.channel.receive(
      encodeDataFrame({ id: 0, index: 0, count: 2, bytes: new Uint8Array([1]) }),
    );
    await expect(fragmentedStarted).rejects.toMatchObject({ code: "EXPECTED_HELLO" });

    const text = standaloneAuthentication(BOB, ALICE, BOB_FP, ALICE_FP);
    const textStarted = text.authenticator.start();
    text.channel.open();
    text.channel.receive("not binary");
    await expect(textStarted).rejects.toMatchObject({ code: "INVALID_FRAME" });
  });

  it("reserves frame zero after authentication and closes on conflicting frame groups", async () => {
    const [aliceWire, bobWire] = linkedChannels();
    const bobMessages: Uint8Array[] = [];
    const alice = authenticatedChannel(
      aliceWire,
      ALICE,
      BOB,
      ALICE_FP,
      BOB_FP,
      [],
    );
    const bob = authenticatedChannel(
      bobWire,
      BOB,
      ALICE,
      BOB_FP,
      ALICE_FP,
      bobMessages,
    );
    const aliceStarted = alice.start();
    const bobStarted = bob.start();
    aliceWire.open();
    bobWire.open();
    await Promise.all([aliceStarted, bobStarted]);

    aliceWire.send(
      encodeDataFrame({ id: 0, index: 0, count: 1, bytes: new Uint8Array([1]) }),
    );
    aliceWire.send(
      encodeDataFrame({ id: 2, index: 0, count: 1, bytes: new Uint8Array([2]) }),
    );
    await settleChannel(bob);
    expect((bob.failure as ChannelAuthenticationError | null)?.code).toBe("EXPECTED_HELLO");
    expect(bobWire.closed).toBe(true);
    expect(bobMessages).toEqual([]);
  });

  it("requires the negotiated reliable channel profile", () => {
    const invalid = new LinkedDataChannel({ negotiated: false });
    expect(
      () =>
        new AuthenticatedPeerChannel({
          channel: invalid as unknown as RTCDataChannel,
          gameId: GAME_ID,
          secretKey: ALICE.secretKey,
          remoteIdentity: BOB.publicKey,
          localFingerprint: ALICE_FP,
          remoteFingerprint: BOB_FP,
          onMessage: () => undefined,
        }),
    ).toThrow(/reliable data-channel profile/);
  });

  it("closes a channel that does not complete HELLO authentication in time", async () => {
    vi.useFakeTimers();
    const harness = standaloneAuthentication(BOB, ALICE, BOB_FP, ALICE_FP);
    const started = harness.authenticator.start();
    const rejection = expect(started).rejects.toMatchObject({
      code: "AUTHENTICATION_TIMEOUT",
    });

    await vi.advanceTimersByTimeAsync(30_000);

    await rejection;
    expect(harness.channel.closed).toBe(true);
  });
});

interface TestIdentity {
  readonly secretKey: Ed25519SecretKey;
  readonly publicKey: IdentityPublicKey;
}

function authenticatedChannel(
  channel: LinkedDataChannel,
  local: TestIdentity,
  remote: TestIdentity,
  localFingerprint: DtlsFingerprint,
  remoteFingerprint: DtlsFingerprint,
  messages: Uint8Array[],
  onAuthenticated?: (remote: IdentityPublicKey) => void,
): AuthenticatedPeerChannel {
  return new AuthenticatedPeerChannel({
    channel: channel as unknown as RTCDataChannel,
    gameId: GAME_ID,
    secretKey: local.secretKey,
    remoteIdentity: remote.publicKey,
    localFingerprint,
    remoteFingerprint,
    onMessage: (payload) => messages.push(payload),
    ...(onAuthenticated === undefined ? {} : { onAuthenticated }),
  });
}

function standaloneAuthentication(
  local: TestIdentity,
  remote: TestIdentity,
  localFingerprint: DtlsFingerprint,
  remoteFingerprint: DtlsFingerprint,
): { readonly channel: LinkedDataChannel; readonly authenticator: AuthenticatedPeerChannel } {
  const channel = new LinkedDataChannel();
  return {
    channel,
    authenticator: authenticatedChannel(
      channel,
      local,
      remote,
      localFingerprint,
      remoteFingerprint,
      [],
    ),
  };
}

function linkedChannels(): readonly [LinkedDataChannel, LinkedDataChannel] {
  const left = new LinkedDataChannel();
  const right = new LinkedDataChannel();
  left.link(right);
  right.link(left);
  return [left, right];
}

async function settleChannel(channel: AuthenticatedPeerChannel): Promise<void> {
  for (let pass = 0; pass < 4; pass += 1) {
    await Promise.resolve();
    await channel.whenIdle();
  }
}

function helloFrame(bytes: Uint8Array): Uint8Array {
  return encodeDataFrame({ id: 0, index: 0, count: 1, bytes });
}

class LinkedDataChannel extends EventTarget {
  readonly label = "p2pcards";
  readonly id = 0;
  readonly ordered = true;
  readonly maxPacketLifeTime: number | null = null;
  readonly maxRetransmits: number | null = null;
  readonly negotiated: boolean;
  binaryType: BinaryType = "blob";
  bufferedAmount = 0;
  bufferedAmountLowThreshold = 0;
  readyState: RTCDataChannelState = "connecting";
  readonly sent: Uint8Array[] = [];
  #peer: LinkedDataChannel | null = null;

  constructor(options: { readonly negotiated?: boolean } = {}) {
    super();
    this.negotiated = options.negotiated ?? true;
  }

  get closed(): boolean {
    return this.readyState === "closed";
  }

  link(peer: LinkedDataChannel): void {
    this.#peer = peer;
  }

  open(): void {
    this.readyState = "open";
    this.dispatchEvent(new Event("open"));
  }

  send(data: ArrayBuffer | ArrayBufferView | Blob | string): void {
    if (this.readyState !== "open") {
      throw new Error("Linked data channel is not open");
    }
    const bytes = binaryBytes(data);
    this.sent.push(bytes);
    const peer = this.#peer;
    if (peer !== null) {
      queueMicrotask(() => peer.receive(bytes));
    }
  }

  receive(data: Uint8Array | string): void {
    if (this.readyState !== "open") {
      return;
    }
    const event = new Event("message");
    const value = typeof data === "string" ? data : arrayBuffer(data);
    Object.defineProperty(event, "data", { value });
    this.dispatchEvent(event);
  }

  close(): void {
    this.#close(true);
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

function binaryBytes(data: ArrayBuffer | ArrayBufferView | Blob | string): Uint8Array {
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data.slice(0));
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength).slice();
  }
  throw new TypeError("Test channel accepts binary data only");
}

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const snapshot = new Uint8Array(bytes.length);
  snapshot.set(bytes);
  return snapshot.buffer;
}

function identity(fill: number): TestIdentity {
  const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(fill));
  return {
    secretKey,
    publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)),
  };
}

function fingerprint(fill: number): DtlsFingerprint {
  return parseDtlsFingerprint(new Uint8Array(32).fill(fill));
}
