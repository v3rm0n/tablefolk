import {
  parseIdentityPublicKey,
  type IdentityPublicKey,
} from "@p2pcards/protocol";
import { describe, expect, it, vi } from "vitest";

import { InMemorySignalingNetwork } from "./signaling";
import { MAX_SIGNALING_MESSAGE_BYTES } from "./signaling-message";

const ROOM = "ab".repeat(32);
const OTHER_ROOM = "cd".repeat(32);
const ALICE = identity(1);
const BOB = identity(2);

describe("in-memory signaling adapter", () => {
  it("delivers directed messages asynchronously with defensive byte snapshots", async () => {
    const network = new InMemorySignalingNetwork();
    const alice = network.createAdapter();
    const bob = network.createAdapter();
    const received: Array<{ from: Uint8Array; payload: Uint8Array }> = [];
    bob.onMessage((from, payload) => received.push({ from, payload }));
    await alice.join(ROOM, ALICE);
    await bob.join(ROOM, BOB);

    const recipient = BOB.slice();
    const payload = new Uint8Array([3, 4, 5]);
    const delivery = alice.send(recipient, payload);
    recipient.fill(0xff);
    payload.fill(0xff);
    expect(received).toEqual([]);
    await delivery;

    expect(received).toEqual([{ from: ALICE, payload: new Uint8Array([3, 4, 5]) }]);
  });

  it("isolates rooms and rejects absent recipients", async () => {
    const network = new InMemorySignalingNetwork();
    const alice = network.createAdapter();
    const bob = network.createAdapter();
    bob.onMessage(vi.fn());
    await alice.join(ROOM, ALICE);
    await bob.join(OTHER_ROOM, BOB);

    await expect(alice.send(BOB, new Uint8Array([1]))).rejects.toThrow(/not present/);
  });

  it("rejects duplicate active identities and permits rejoining after leave", async () => {
    const network = new InMemorySignalingNetwork();
    const first = network.createAdapter();
    const duplicate = network.createAdapter();
    await first.join(ROOM, ALICE);

    await expect(duplicate.join(ROOM, ALICE)).rejects.toThrow(/already present/);
    await first.leave();
    await first.leave();
    await duplicate.join(ROOM, ALICE);
    await duplicate.leave();
  });

  it("rejects invalid lifecycle operations, self-send, and malformed input", async () => {
    const network = new InMemorySignalingNetwork();
    const alice = network.createAdapter();

    await expect(alice.send(BOB, new Uint8Array())).rejects.toThrow(/not joined/);
    await expect(alice.join("room", ALICE)).rejects.toThrow(/64 lowercase hexadecimal/);
    await expect(alice.join(ROOM, new Uint8Array(31))).rejects.toThrow(/exactly 32/);
    await alice.join(ROOM, ALICE);
    await expect(alice.join(ROOM, ALICE)).rejects.toThrow(/already joined/);
    await expect(alice.send(ALICE, new Uint8Array())).rejects.toThrow(/cannot send to itself/);
    await expect(
      alice.send(BOB, new Uint8Array([1])),
    ).rejects.toThrow(/not present/);
    await expect(
      alice.send(BOB, new Uint8Array(MAX_SIGNALING_MESSAGE_BYTES + 1)),
    ).rejects.toThrow(/must not exceed/);
  });

  it("rejects delivery without a handler and propagates handler failures", async () => {
    const network = new InMemorySignalingNetwork();
    const alice = network.createAdapter();
    const bob = network.createAdapter();
    await alice.join(ROOM, ALICE);
    await bob.join(ROOM, BOB);

    await expect(alice.send(BOB, new Uint8Array([1]))).rejects.toThrow(/no message handler/);
    bob.onMessage(() => {
      throw new Error("handler failed");
    });
    await expect(alice.send(BOB, new Uint8Array([1]))).rejects.toThrow("handler failed");
  });

  it("cancels queued delivery if either participant leaves", async () => {
    const network = new InMemorySignalingNetwork();
    const alice = network.createAdapter();
    const bob = network.createAdapter();
    bob.onMessage(vi.fn());
    await alice.join(ROOM, ALICE);
    await bob.join(ROOM, BOB);

    const delivery = alice.send(BOB, new Uint8Array([1]));
    await bob.leave();
    await expect(delivery).rejects.toThrow(/membership changed/);
  });
});

function identity(fill: number): IdentityPublicKey {
  return parseIdentityPublicKey(new Uint8Array(32).fill(fill));
}
