import { deriveEd25519PublicKey, importEd25519SecretKey } from "@p2pcards/crypto";
import * as protocol from "@p2pcards/protocol";
import {
  ENVELOPE_MESSAGE_TYPES, parseGameId, parseHash256, parseIdentityPublicKey, signEnvelope,
  type EnvelopeArtifact,
} from "@p2pcards/protocol";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  captureSessionHistory, DEFAULT_MAX_SESSION_HISTORY_BYTES, DEFAULT_MAX_SESSION_HISTORY_ENVELOPES,
  SessionChainRegistry, SessionHistoryCaptureError, type CapturedSessionHistory, type SessionHistoryCaptureLimits,
} from "./index";

const GAME = parseGameId(new Uint8Array(16).fill(9));
const ZERO = parseHash256(new Uint8Array(32));
const SECRETS = Array.from({ length: 8 }, (_, seat) => importEd25519SecretKey(new Uint8Array(32).fill(seat + 1)));
const ROSTER = SECRETS.map((secret) => parseIdentityPublicKey(deriveEd25519PublicKey(secret)));

function fixture(counts = [2, 0, 1, 0]) {
  const session = new SessionChainRegistry(GAME, ROSTER.slice(0, counts.length));
  let index = 0;
  const bySeat = counts.map((count, seat) => {
    const artifacts: EnvelopeArtifact[] = [];
    for (let seq = 0; seq < count; seq += 1) {
      const artifact = signEnvelope({
        v: 1, game: GAME, from: ROSTER[seat]!, seq, prev: artifacts.at(-1)?.hash ?? ZERO,
        round: index, phase: "uninterpreted", type: ENVELOPE_MESSAGE_TYPES[index++ % ENVELOPE_MESSAGE_TYPES.length]!,
        body: { bytes: new Uint8Array([seat, seq]), arbitrary: true },
      }, SECRETS[seat]!);
      expect(session.ingest(artifact).status).toBe("accepted");
      artifacts.push(artifact);
    }
    return artifacts;
  });
  return { session, bySeat, envelopes: bySeat.flat() };
}

describe("session history capture", () => {
  afterEach(() => vi.restoreAllMocks());

  it.each([3, 4, 8])("captures a fresh %s-seat session without reading ranges, verifying or writing", (seats) => {
    const { session } = fixture(new Array<number>(seats).fill(0));
    const spies = [vi.spyOn(session, "readRange"), vi.spyOn(session, "classify"), vi.spyOn(session, "ingest"),
      vi.spyOn(protocol, "decodeAndVerifyEnvelope"), vi.spyOn(protocol, "signEnvelope")];
    const history: CapturedSessionHistory = captureSessionHistory(session);

    expect(history.bySeat).toEqual(Array.from({ length: seats }, () => []));
    expect(history.envelopes).toEqual([]);
    expect(history).not.toBeInstanceOf(Promise);
    history.assertUnchanged();
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
    expect(Object.isFrozen(history)).toBe(true);
    expect(Object.isFrozen(history.envelopes)).toBe(true);
    expect(Object.isFrozen(history.bySeat)).toBe(true);
    expect(history.bySeat.every(Object.isFrozen)).toBe(true);
  });

  it("preserves empty seats, prefix order, and detached arrays without interpreting any message type", () => {
    const { session, bySeat, envelopes } = fixture([5, 0, 5, 0, 5]);
    const heads = session.heads();
    const ingest = vi.spyOn(session, "ingest").mockImplementation(() => { throw new Error("No writes"); });
    const sign = vi.spyOn(protocol, "signEnvelope").mockImplementation(() => { throw new Error("No signing"); });
    const range = vi.spyOn(session, "readRange");
    const history = captureSessionHistory(session);

    expect(history.bySeat).toEqual(bySeat);
    expect(history.envelopes).toEqual(envelopes);
    expect(history.envelopes.map(({ envelope }) => envelope.type)).toEqual(ENVELOPE_MESSAGE_TYPES);
    expect(range.mock.calls).toEqual([0, 2, 4].map((seat) => [ROSTER[seat], 0, 4]));
    expect(history.envelopes[0]).toBe(history.bySeat[0]![0]);
    expect(history.envelopes[0]).toBe(envelopes[0]);
    history.assertUnchanged();
    expect(session.heads()).toEqual(heads);
    expect(ingest).not.toHaveBeenCalled();
    expect(sign).not.toHaveBeenCalled();
  });

  it("charges exact envelope and byte limits across all prefixes before verification", () => {
    const { session, envelopes } = fixture();
    const maxBytes = envelopes.reduce((sum, artifact) => sum + artifact.canonicalBytes.length, 0);
    expect(DEFAULT_MAX_SESSION_HISTORY_ENVELOPES).toBe(1024);
    expect(DEFAULT_MAX_SESSION_HISTORY_BYTES).toBe(16 * 1024 * 1024);
    expect(captureSessionHistory(session, { maxEnvelopes: 3, maxBytes }).envelopes).toEqual(envelopes);
    const range = vi.spyOn(session, "readRange");
    const decode = vi.spyOn(protocol, "decodeAndVerifyEnvelope");
    expect(() => captureSessionHistory(session, { maxEnvelopes: 2 })).toThrow(SessionHistoryCaptureError);
    expect(range).not.toHaveBeenCalled();
    expect(() => captureSessionHistory(session, { maxBytes: maxBytes - 1 })).toThrow(SessionHistoryCaptureError);
    expect(decode).not.toHaveBeenCalled();
  });

  it("rejects malformed limits before reading the registry", () => {
    const { session } = fixture();
    const heads = vi.spyOn(session, "heads");
    for (const name of ["maxEnvelopes", "maxBytes"]) {
      for (const value of [0, -0, -1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, "3", null]) {
        expect(() => captureSessionHistory(session, { [name]: value } as SessionHistoryCaptureLimits)).toThrow(RangeError);
      }
    }
    expect(heads).not.toHaveBeenCalled();
  });

  it("detects a new sender chain after an empty capture", () => {
    const { session } = fixture([0, 0, 0]);
    const history = captureSessionHistory(session);
    const { envelopes } = fixture([0, 1, 0]);
    expect(session.ingest(envelopes[0]!).status).toBe("accepted");
    expect(history.assertUnchanged).toThrow(SessionHistoryCaptureError);
  });


});
