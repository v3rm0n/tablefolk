import { deriveEd25519PublicKey, importEd25519SecretKey } from "@p2pcards/crypto";
import {
  decodeChannelControl, encodeChannelControl, parseGameId, parseHash256, parseIdentityPublicKey, signEnvelope,
  type EnvelopeArtifact,
} from "@p2pcards/protocol";
import { createEquivocationViolation, SessionChainRegistry } from "@p2pcards/session";
import { describe, expect, it } from "vitest";

import { HistorySync } from "./history-sync";

const key = importEd25519SecretKey(new Uint8Array(32).fill(1));
const from = parseIdentityPublicKey(deriveEd25519PublicKey(key));
const others = [2, 3].map(fill => parseIdentityPublicKey(deriveEd25519PublicKey(importEd25519SecretKey(new Uint8Array(32).fill(fill)))));
const game = parseGameId(new Uint8Array(16));
const zero = parseHash256(new Uint8Array(32));

function sign(seq: number, prev = zero, marker = "original") {
  return signEnvelope({ v: 1, from, game, seq, prev, round: 1, phase: "round.1.play.0", type: "ACTION", body: { marker } }, key);
}

function fixture() {
  const registry = new SessionChainRegistry(game, [from, ...others]);
  return {
    registry,
    source: {
      allowed: () => true,
      head: () => registry.heads()[0] ?? null,
      get: (_from: typeof from, seq: number) => {
        const range = registry.readRange(from, seq, seq);
        return range.status === "complete" ? range.envelopes[0] : undefined;
      },
    },
  };
}

function relay(id: number, artifact: EnvelopeArtifact) {
  const decoded = decodeChannelControl(encodeChannelControl({ type: "SYNC_RESP", id, body: { envelopes: [artifact] } }));
  if (decoded.type !== "SYNC_RESP") throw new Error("Expected a response");
  return decoded;
}

describe("authenticated history catch-up", () => {
  it("accepts original signed bytes from a relay while the author is absent", () => {
    const { registry, source } = fixture();
    const relayConnection = new HistorySync();
    const first = sign(0);
    const second = sign(1, first.hash);
    relayConnection.advertise([{ from, seq: 1, hash: second.hash }]);

    const [request] = relayConnection.advance(source);
    expect(request?.body).toEqual({ from, fromSeq: 0, toSeq: 0 });
    expect(relayConnection.ready).toBe(false);
    const result = relayConnection.receive(relay(request!.id, first), source);
    expect(result).toMatchObject({ artifact: first });
    expect(relayConnection.advance(source)).toEqual([]);
    expect(registry.heads()).toEqual([]);
    expect(registry.ingest(first).status).toBe("accepted");

    const [next] = relayConnection.advance(source);
    expect(next?.body.fromSeq).toBe(1);
    expect(relayConnection.receive(relay(next!.id, second), source)).toMatchObject({ artifact: second });
    expect(registry.ingest(second).status).toBe("accepted");
    expect(relayConnection.advance(source)).toEqual([]);
    expect(relayConnection.ready).toBe(true);
    expect(registry.heads()).toEqual([{ from, seq: 1, hash: second.hash }]);

    const live = sign(2, second.hash);
    relayConnection.advertise([{ from, seq: 2, hash: live.hash }]);
    expect(relayConnection.advance(source)).toHaveLength(1);
    expect(relayConnection.ready).toBe(true);
  });

  it("resolves a newer fork to two signed originals at the same sequence", () => {
    const { registry, source } = fixture();
    const relayConnection = new HistorySync();
    const local = sign(0);
    const fork = sign(0, zero, "fork");
    const tip = sign(1, fork.hash);
    registry.ingest(local);
    relayConnection.advertise([{ from, seq: 1, hash: tip.hash }]);

    const [request] = relayConnection.advance(source);
    const response = relayConnection.receive(relay(request!.id, tip), source);
    expect(response).toMatchObject({ request: { body: { fromSeq: 0, toSeq: 0 } } });
    if (!response || !("request" in response)) throw new Error("Expected a fork probe");
    const evidence = relayConnection.receive(relay(response.request.id, fork), source);
    expect(evidence).toMatchObject({ artifact: fork, conflict: local });
    expect(createEquivocationViolation(registry, local, fork).evidence).toEqual(
      expect.arrayContaining([local, fork]),
    );
    expect(registry.heads()).toEqual([{ from, seq: 0, hash: local.hash }]);
  });

  it("requires an outstanding request from this channel generation and a matching advertised hash", () => {
    const { source } = fixture();
    const connection = new HistorySync();
    const artifact = sign(0);
    connection.advertise([{ from, seq: 0, hash: artifact.hash }]);
    const [request] = connection.advance(source);
    expect(() => new HistorySync().receive(relay(request!.id, artifact), source)).toThrow(/Unsolicited/);
    expect(() => connection.receive(relay(request!.id, sign(0, zero, "other")), source)).toThrow(/does not match/);
  });
});
