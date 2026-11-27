import { bytesEqual, deriveEd25519PublicKey, importEd25519SecretKey } from "@p2pcards/crypto";
import { decodeCanonical, encodeCanonical } from "@p2pcards/encoding";
import {
  encodeJoinBody, encodeReadyBody, encodeRosterBody, hashRosterBody,
  parseDtlsFingerprint, parseGameId, parseHash256, parseIdentityPublicKey, signEnvelope, signHello,
  type EnvelopeArtifact, type EnvelopeMessageType,
} from "@p2pcards/protocol";
import { LobbyChainRegistry, PersistentSessionReceiver, SessionChainRegistry } from "@p2pcards/session";
import { describe, expect, it, vi } from "vitest";

import { liveRulesHash } from "./live-profile";
import { decodeMatchEnvelope } from "./match-envelope";
import { exportTranscript, verifyTranscript } from "./transcript";

const game = parseGameId(new Uint8Array(16).fill(21));
const zero = parseHash256(new Uint8Array(32));
const rulesHash = liveRulesHash();
const secrets = [1, 2, 3, 4].map(n => importEd25519SecretKey(new Uint8Array(32).fill(n)));
const seats = secrets.map(secret => parseIdentityPublicKey(deriveEd25519PublicKey(secret)));
const roster = { gameId: game, rulesHash, iceConfigHash: zero, seats };
const rosterEnvelope = sign(0, 0, zero, "ROSTER", encodeRosterBody(roster));
const joins = seats.slice(1).map((pkId, index) => sign(index + 1, 0, zero, "JOIN",
  encodeJoinBody({ pkId, rulesHash, clientVersion: "test" })));
const ready = [rosterEnvelope, ...joins].map(({ hash }, seat) => sign(seat, 1, hash, "READY",
  encodeReadyBody({ rosterHash: hashRosterBody(roster) })));

function sign(seat: number, seq: number, prev: typeof zero, type: EnvelopeMessageType, body: EnvelopeArtifact["envelope"]["body"]) {
  return signEnvelope({ v: 1, game, from: seats[seat]!, seq, prev, round: 0, phase: "lobby", type, body }, secrets[seat]!);
}

function fixture() {
  const lobby = new LobbyChainRegistry({ ...roster, host: seats[0]! });
  expect(lobby.ingestRoster(rosterEnvelope).status).toBe("accepted");
  for (const join of joins) expect(lobby.bootstrapJoin(join).status).toBe("accepted");
  for (const message of ready) expect(lobby.ingestReady(message).status).toBe("accepted");
  const bytes = exportTranscript(lobby.finalizedRegistry!, rosterEnvelope);
  return {
    bytes,
    fields: decodeCanonical(bytes) as { version: number; rules_hash: Uint8Array; roster: Uint8Array; envelopes: Uint8Array[] },
  };
}

function seededBytes(seed: number, length: number): Uint8Array {
  return Uint8Array.from({ length }, () => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return seed & 0xff;
  });
}

describe("offline Sasku transcripts", () => {
  it("round-trips an agreed history and reports it as incomplete", async () => {
    const { bytes, fields } = fixture();
    expect(fields.roster).toEqual(rosterEnvelope.canonicalBytes);
    expect(fields.envelopes).toHaveLength(7);
    expect(await verifyTranscript(bytes)).toMatchObject({ status: "incomplete", match: { totals: [0, 0] } });
    expect(fixture().bytes).toEqual(bytes);
  });

  it("rejects unknown rules before interpreting the roster or working on proofs", async () => {
    const { fields } = fixture();
    expect(await verifyTranscript(encodeCanonical({ ...fields, rules_hash: zero, roster: null })))
      .toEqual({ status: "violation", message: "Unknown rules hash" });
  });

  it("rejects a transport HELLO, repeated roster, reordered envelopes, and missing chain links", async () => {
    const { fields } = fixture();
    const hello = signHello(game, parseDtlsFingerprint(zero), parseDtlsFingerprint(new Uint8Array(32).fill(1)), secrets[0]!);
    const outsiderSecret = importEd25519SecretKey(new Uint8Array(32).fill(5));
    const outsider = parseIdentityPublicKey(deriveEd25519PublicKey(outsiderSecret));
    const outsiderJoin = signEnvelope({
      ...joins[0]!.envelope, from: outsider, body: encodeJoinBody({ pkId: outsider, rulesHash, clientVersion: "test" }),
    }, outsiderSecret);
    const failures = [
      { envelopes: [...fields.envelopes, outsiderJoin.canonicalBytes], message: /outside the signed roster/ },
      { envelopes: [hello.canonicalBytes, ...fields.envelopes], message: /envelope 0 is invalid/ },
      { envelopes: [...fields.envelopes, fields.roster], message: /repeats sender/ },
      { envelopes: [...fields.envelopes].reverse(), message: /canonical sender order/ },
      { envelopes: fields.envelopes.filter(entry => !joins.some(join => bytesEqual(join.canonicalBytes, entry))), message: /gap/ },
    ];
    for (const { envelopes, message } of failures) {
      const corrupted = encodeCanonical({ ...fields, envelopes });
      const first = await verifyTranscript(corrupted);
      expect(first).toMatchObject({ status: "violation", message: expect.stringMatching(message) });
      expect(await verifyTranscript(corrupted)).toEqual(first);
    }
  });

  it("rejects generated malformed CBOR consistently at file and network ingress", async () => {
    const { bytes } = fixture();
    for (let seed = 1; seed <= 96; seed += 1) {
      for (const input of [
        bytes.slice(0, (seed * 59) % bytes.length),
        Uint8Array.of(0xff, ...seededBytes(seed, seed)),
        Uint8Array.of(0x5a, 0xff, 0xff, 0xff, 0xff, ...seededBytes(seed, seed)),
      ]) {
        expect(() => decodeMatchEnvelope(input)).toThrow();
        const result = await verifyTranscript(input);
        expect(result.status).toBe("violation");
        expect(await verifyTranscript(input)).toEqual(result);
      }
    }
    expect(() => decodeMatchEnvelope(new Uint8Array(64 * 1024 + 1))).toThrow(/64 KiB/);
  });

  it("rejects single-bit changes to a signed envelope at both boundaries", async () => {
    const { fields } = fixture();
    for (let seed = 1; seed <= 64; seed += 1) {
      const [entry, ...rest] = fields.envelopes;
      const corrupted = entry!.slice();
      const index = (seed * 61) % corrupted.length;
      corrupted[index] = corrupted[index]! ^ (1 << (seed % 8));
      expect(() => decodeMatchEnvelope(corrupted)).toThrow();
      expect(await verifyTranscript(encodeCanonical({ ...fields, envelopes: [corrupted, ...rest] })))
        .toMatchObject({ status: "violation", message: expect.stringMatching(/envelope 0 is invalid/) });
    }
  });

  it("keeps signed messages across generated chain gaps out of durable network history", async () => {
    const registry = new SessionChainRegistry(game, seats);
    const persist = vi.fn(async (artifact: EnvelopeArtifact) => ({ status: "stored" as const, record: { artifact } }));
    const receiver = new PersistentSessionReceiver(registry, { persistAcceptedEnvelope: persist });
    const first = decodeMatchEnvelope(rosterEnvelope.canonicalBytes);
    await expect(receiver.receive(first)).resolves.toMatchObject({ status: "accepted" });
    for (let seed = 2; seed <= 65; seed += 1) {
      const seq = seed === 65 ? Number.MAX_SAFE_INTEGER : seed;
      const message = sign(0, seq, first.hash, "READY", ready[0]!.envelope.body);
      await expect(receiver.receive(decodeMatchEnvelope(message.canonicalBytes)))
        .resolves.toMatchObject({ status: "rejected", reason: "gap" });
    }
    expect(persist).toHaveBeenCalledTimes(1);
    expect(registry.heads()).toMatchObject([{ seq: 0 }]);
    await expect(receiver.receive(decodeMatchEnvelope(ready[0]!.canonicalBytes))).resolves.toMatchObject({ status: "accepted" });
  });
});
