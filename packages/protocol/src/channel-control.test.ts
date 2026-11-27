import { deriveEd25519PublicKey, importEd25519SecretKey, signEd25519 } from "@p2pcards/crypto";
import { decodeCanonical, encodeCanonical } from "@p2pcards/encoding";
import { expect, it } from "vitest";

import {
  CHANNEL_CONTROL_PREFIX, decodeAndVerifyEnvelope, decodeChannelControl, encodeChannelControl, envelopeSignatureInput,
  parseGameId, parseHash256, parseIdentityPublicKey, signEnvelope,
} from "./index";

const secret = importEd25519SecretKey(new Uint8Array(32).fill(3));
const from = parseIdentityPublicKey(deriveEd25519PublicKey(secret));
const base = {
  v: 1, game: parseGameId(new Uint8Array(16)), from, seq: 0, prev: parseHash256(new Uint8Array(32)),
  round: 1, phase: "round.1.play.0", body: {},
} as const;

it("round-trips control frames outside the envelope chain", () => {
  const original = signEnvelope({ ...base, type: "ACTION" }, secret);
  const payload = encodeChannelControl({ type: "HEADS", body: { heads: [{ from, seq: 0, hash: original.hash }] } });
  expect(payload[0]).toBe(CHANNEL_CONTROL_PREFIX);
  expect(decodeChannelControl(payload)).toEqual({ type: "HEADS", body: { heads: [{ from, seq: 0, hash: original.hash }] } });
  expect(() => decodeAndVerifyEnvelope(payload)).toThrow();
  for (const type of ["WITNESS", "SYNC_REQ", "SYNC_RESP", "TIMEOUT_VOTE"] as const) {
    expect(() => signEnvelope({ ...base, type }, secret)).toThrow(/cannot be signed/);
  }
});

it("rejects a forged original inside a response carried by an authenticated relay", () => {
  const original = signEnvelope({ ...base, type: "ACTION" }, secret);
  const nested = decodeCanonical(original.canonicalBytes);
  if (typeof nested !== "object" || nested === null || !("sig" in nested)) throw new Error("Missing signature");
  const bytes = encodeCanonical({
    type: "SYNC_RESP", id: 1, body: { envelopes: [{ ...nested, sig: new Uint8Array(64) }] },
  });
  const payload = Uint8Array.of(CHANNEL_CONTROL_PREFIX, ...bytes);
  expect(() => decodeChannelControl(payload)).toThrow(/signed envelope/);
});

it("can still verify a retired control envelope in a stored transcript", () => {
  const unsigned = { ...base, type: "WITNESS", body: { heads: [] } };
  const sig = signEd25519(envelopeSignatureInput(encodeCanonical(unsigned)), secret);
  const saved = encodeCanonical({ ...unsigned, sig });
  expect(decodeAndVerifyEnvelope(saved).envelope.type).toBe("WITNESS");
});
