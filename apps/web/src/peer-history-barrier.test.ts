import { expect, it } from "vitest";
import { generateEd25519KeyPair } from "@p2pcards/crypto";
import { parseGameId, parseHash256, parseIdentityPublicKey, signEnvelope } from "@p2pcards/protocol";
import { PeerHistoryBarrier } from "./peer-history-barrier";

function artifact(seq = 0) {
  const id = generateEd25519KeyPair();
  return signEnvelope({ v: 1, game: parseGameId(new Uint8Array(16)), from: parseIdentityPublicKey(id.publicKey), seq,
    prev: parseHash256(new Uint8Array(32)), round: 0, phase: "lobby", type: "READY", body: {} }, id.secretKey);
}
it("requires both a durable incoming prefix and acknowledgement of its own prefix", () => {
  const a = new PeerHistoryBarrier(), b = new PeerHistoryBarrier(), first = artifact(), second = artifact();
  b.receive(a.announce(first)); a.receive(b.announce(second));
  expect(a.ready).toBe(false); expect(b.ready).toBe(false);
  expect(b.acknowledge(() => undefined)).toBeNull();
  a.receive(b.acknowledge(() => first)!);
  expect(a.ready).toBe(false);
  b.receive(a.acknowledge(() => second)!);
  expect(a.ready).toBe(true); expect(b.ready).toBe(true);
  a.announce(first); b.announce(second);
  expect(a.ready).toBe(true); expect(b.ready).toBe(true);
  expect(a.acknowledge(() => second)).toBeNull();
});
it("ignores acknowledgements from replaced generations and older outgoing prefixes", () => {
  const old = new PeerHistoryBarrier(), current = new PeerHistoryBarrier(), peer = new PeerHistoryBarrier();
  const first = artifact(), next = artifact(1), remote = artifact();
  peer.receive(old.announce(first)); const stale = peer.acknowledge(() => first)!;
  current.receive(peer.announce(remote)); current.acknowledge(() => remote);
  peer.receive(current.announce(first)); current.receive(stale); expect(current.ready).toBe(false);
  const ack = peer.acknowledge(() => first)!;
  current.announce(next); current.receive(ack); expect(current.ready).toBe(false);
  peer.receive(current.announce(next)); current.receive(peer.acknowledge(() => next)!); expect(current.ready).toBe(true);
});
it("rejects conflicting admitted heads and malformed or oversized markers", () => {
  const a = new PeerHistoryBarrier(), b = new PeerHistoryBarrier();
  b.receive(a.announce(artifact()));
  expect(() => b.acknowledge(() => artifact())).toThrow(/conflicts/);
  for (const bytes of [new Uint8Array(513), new Uint8Array([1]), new Uint8Array([0, 123, 125])]) expect(() => b.receive(bytes)).toThrow();
});
