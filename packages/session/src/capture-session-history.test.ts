import { deriveEd25519PublicKey, importEd25519SecretKey } from "@p2pcards/crypto";
import { encodeCanonical } from "@p2pcards/encoding";
import * as protocol from "@p2pcards/protocol";
import {
  decodeAndVerifyEnvelope, ENVELOPE_MESSAGE_TYPES, parseGameId, parseHash256, parseIdentityPublicKey, signEnvelope,
  type EnvelopeArtifact, type UnsignedEnvelope,
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
    expect(history.envelopes[0]).not.toBe(envelopes[0]);
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
    for (const limits of [null, false, 1, "limits"]) {
      expect(() => captureSessionHistory(session, limits as SessionHistoryCaptureLimits)).toThrow(TypeError);
    }
    for (const name of ["maxEnvelopes", "maxBytes"]) {
      for (const value of [0, -0, -1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, "3", null]) {
        expect(() => captureSessionHistory(session, { [name]: value } as SessionHistoryCaptureLimits)).toThrow(RangeError);
      }
    }
    expect(heads).not.toHaveBeenCalled();
  });

  it.each([-1, -0, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER + 1, 1024])(
    "rejects unsafe or over-budget head sequence %s before any range allocation", (seq) => {
      const { session } = fixture();
      const heads = session.heads();
      vi.spyOn(session, "heads").mockReturnValue([heads[0]!, { ...heads[1]!, seq }]);
      const range = vi.spyOn(session, "readRange");
      const maxEnvelopes = seq === Number.MAX_SAFE_INTEGER ? Number.MAX_SAFE_INTEGER : DEFAULT_MAX_SESSION_HISTORY_ENVELOPES;
      expect(() => captureSessionHistory(session, { maxEnvelopes })).toThrow(SessionHistoryCaptureError);
      expect(range).not.toHaveBeenCalled();
    },
  );

  it("rejects duplicate, unordered, non-roster, or malformed heads before reading ranges", () => {
    const { session } = fixture();
    const heads = session.heads();
    const read = vi.spyOn(session, "readRange");
    const headSpy = vi.spyOn(session, "heads");
    for (const bad of [null, {}, [...heads].reverse(), [heads[0], heads[0]],
      [{ ...heads[0]!, from: ROSTER[7] }], [{ ...heads[0]!, hash: new Uint8Array(31) }],
      [undefined], [...heads, ...heads, ...heads],
    ]) {
      headSpy.mockReturnValueOnce(bad as never);
      expect(() => captureSessionHistory(session)).toThrow(SessionHistoryCaptureError);
      expect(read).not.toHaveBeenCalled();
    }
  });

  it("rejects malformed and duplicate roster entries even for empty sessions", () => {
    const { session } = fixture([0, 0, 0]);
    const roster = vi.spyOn(session, "roster", "get");
    const heads = vi.spyOn(session, "heads");
    for (const bad of [null, [], ROSTER.slice(0, 2), [...ROSTER, ROSTER[0]],
      [ROSTER[0], ROSTER[0], ROSTER[2]], [ROSTER[0], new Uint8Array(31), ROSTER[2]],
    ]) {
      roster.mockReturnValueOnce(bad as never);
      expect(() => captureSessionHistory(session)).toThrow(SessionHistoryCaptureError);
      expect(heads).not.toHaveBeenCalled();
    }
  });

  it("snapshots bounded roster and head arrays without invoking dependency-owned iterators", () => {
    const { session, envelopes } = fixture();
    const roster = [...session.roster];
    const heads = [...session.heads()];
    const iterate = vi.fn(() => { throw new Error("Dependency iterator used"); });
    Object.defineProperty(roster, Symbol.iterator, { value: iterate });
    Object.defineProperty(heads, Symbol.iterator, { value: iterate });
    vi.spyOn(session, "roster", "get").mockReturnValue(roster);
    vi.spyOn(session, "heads").mockReturnValue(heads);
    expect(captureSessionHistory(session).envelopes).toEqual(envelopes);
    expect(iterate).not.toHaveBeenCalled();
  });

  it("requires exact, complete prefixes before decoding any envelope", () => {
    const { session, bySeat } = fixture();
    const read = vi.spyOn(session, "readRange");
    const decode = vi.spyOn(protocol, "decodeAndVerifyEnvelope");
    for (const bad of [null, { status: "missing", firstMissingSeq: 1 }, { status: "unknown_sender" },
      { status: "COMPLETE", envelopes: bySeat[0] }, { status: "complete", envelopes: {} },
      ...[bySeat[0]!.slice(1), [...bySeat[0]!, bySeat[0]![0]], [undefined, bySeat[0]![1]]]
        .map((envelopes) => ({ status: "complete", envelopes })),
    ]) {
      read.mockReturnValueOnce(bad as never);
      expect(() => captureSessionHistory(session)).toThrow(SessionHistoryCaptureError);
      expect(decode).not.toHaveBeenCalled();
    }
  });

  it("bounds intrinsic source sizes and rejects incompatible views before copying or decoding", () => {
    const { session, bySeat } = fixture();
    class ByteSubclass extends Uint8Array {}
    const wide = Object.setPrototypeOf(new Uint16Array(32), Uint8Array.prototype) as Uint8Array;
    const hiddenSize = Object.defineProperty(new Uint8Array(1025), "length", { value: 1 });
    const fakeSize = Object.defineProperty(new Uint8Array(1), "length", { value: 1025 });
    const read = vi.spyOn(session, "readRange");
    const decode = vi.spyOn(protocol, "decodeAndVerifyEnvelope");
    const copy = vi.spyOn(Uint8Array.prototype, "set");
    for (const source of [null, new Uint8Array(), new ByteSubclass(1), new Uint16Array(1), wide,
      Object.create(Uint8Array.prototype), new Proxy(new Uint8Array(1), {}), hiddenSize, fakeSize,
    ]) {
      read.mockReturnValueOnce({ status: "complete", envelopes: [
        { ...bySeat[0]![0]!, canonicalBytes: source }, bySeat[0]![1]!,
      ] } as never);
      expect(() => captureSessionHistory(session, { maxBytes: 1024 })).toThrow(SessionHistoryCaptureError);
      expect(copy.mock.calls.some(([argument]) => argument === source)).toBe(false);
      expect(decode).not.toHaveBeenCalled();
    }
  });

  it("copies every source before verification and ignores overridable slice/iterator methods", () => {
    const { session, envelopes } = fixture();
    const override = vi.fn(() => { throw new Error("Dependency-owned copy method"); });
    for (const artifact of envelopes) {
      Object.defineProperties(artifact.canonicalBytes, { slice: { value: override }, [Symbol.iterator]: { value: override } });
    }
    const read = vi.spyOn(session, "readRange");
    const copy = vi.spyOn(Uint8Array.prototype, "set");
    const nativeDecode = decodeAndVerifyEnvelope;
    vi.spyOn(protocol, "decodeAndVerifyEnvelope").mockImplementation((bytes) => {
      expect(read).toHaveBeenCalledTimes(2);
      for (const original of envelopes) {
        expect(copy.mock.calls.some(([source]) => source === original.canonicalBytes)).toBe(true);
        expect(bytes === original.canonicalBytes).toBe(false);
      }
      return nativeDecode(bytes);
    });
    expect(captureSessionHistory(session).envelopes.map(({ envelope }) => envelope.seq)).toEqual([0, 1, 0]);
    expect(override).not.toHaveBeenCalled();
  });

  it("verifies canonical encoding and signatures rather than trusting cached decoded views", () => {
    const { session, bySeat } = fixture();
    const first = bySeat[0]![0]!;
    const read = vi.spyOn(session, "readRange");
    for (const canonicalBytes of [new Uint8Array([0xff]), encodeCanonical({ ...first.envelope, sig: new Uint8Array(64) }),
      new Uint8Array([0xb8, 0x0a, ...first.canonicalBytes.slice(1)]),
    ]) {
      read.mockReturnValueOnce({ status: "complete", envelopes: [{ ...first, canonicalBytes }, bySeat[0]![1]!] } as never);
      expect(() => captureSessionHistory(session)).toThrow(SessionHistoryCaptureError);
    }
  });

  it("checks signed game, sender, sequence, genesis and predecessor independently of duplicate claims", () => {
    const { session, bySeat } = fixture();
    const read = vi.spyOn(session, "readRange");
    vi.spyOn(session, "classify").mockImplementation((received) => ({ status: "duplicate", existing: received, received }));
    const changes: readonly [number, Partial<UnsignedEnvelope>][] = [
      [0, { game: parseGameId(new Uint8Array(16)) }], [0, { from: ROSTER[1]! }],
      [0, { seq: 1 }], [0, { prev: parseHash256(new Uint8Array(32).fill(1)) }],
      [1, { seq: 0 }], [1, { prev: ZERO }],
    ];
    for (const [index, change] of changes) {
      const forged = signEnvelope({ ...bySeat[0]![index]!.envelope, ...change }, SECRETS[change.from === undefined ? 0 : 1]!);
      const envelopes = bySeat[0]!.map((artifact, seq) => seq === index ? forged : artifact);
      read.mockReturnValueOnce({ status: "complete", envelopes });
      expect(() => captureSessionHistory(session)).toThrow(SessionHistoryCaptureError);
    }
  });

  it("rejects mismatched head hashes and non-duplicate cache results on capture and stability checks", () => {
    const { session } = fixture();
    const heads = session.heads();
    vi.spyOn(session, "heads").mockReturnValueOnce([{ ...heads[0]!, hash: ZERO }, heads[1]!]);
    expect(() => captureSessionHistory(session)).toThrow(SessionHistoryCaptureError);
    const history = captureSessionHistory(session);
    const classify = vi.spyOn(session, "classify");
    for (const status of ["accepted", "rejected", "DUPLICATE", undefined]) {
      classify.mockReturnValueOnce({ status } as never);
      expect(() => captureSessionHistory(session)).toThrow(SessionHistoryCaptureError);
      classify.mockReturnValueOnce({ status } as never);
      expect(history.assertUnchanged).toThrow(SessionHistoryCaptureError);
    }
    const error = new Error("cache read failed");
    classify.mockImplementationOnce(() => { throw error; });
    expect(history.assertUnchanged).toThrow(expect.objectContaining({ name: "SessionHistoryCaptureError", cause: error }));
  });

  it("isolates private snapshots from both classify arguments and returned artifact mutation", () => {
    const { session, envelopes } = fixture();
    const expected = envelopes.map(({ canonicalBytes }) => decodeAndVerifyEnvelope(canonicalBytes));
    const nativeClassify = session.classify.bind(session);
    const argumentsSeen: EnvelopeArtifact[] = [];
    vi.spyOn(session, "classify").mockImplementation((argument) => {
      const result = nativeClassify(argument);
      argumentsSeen.push(argument);
      argument.canonicalBytes.fill(0xff);
      argument.hash.fill(0xff);
      argument.envelope.from.fill(0xff);
      (argument.envelope.body as Record<string, unknown>)["bytes"] = new Uint8Array();
      return result;
    });
    const history = captureSessionHistory(session);
    expect(history.envelopes).toEqual(expected);
    for (const artifact of history.envelopes) {
      artifact.canonicalBytes.fill(0xee);
      artifact.hash.fill(0xee);
      artifact.envelope.game.fill(0xee);
      (artifact.envelope.body as Record<string, unknown>)["bytes"] = null;
    }
    history.assertUnchanged();
    history.assertUnchanged();
    expect(envelopes).toEqual(expected);
    expect(new Set(argumentsSeen).size).toBe(envelopes.length * 3);
  });

  it("detects a corrupt native cached hash even when reported heads match canonical history", () => {
    const { session } = fixture([0, 0, 0]);
    const { envelopes } = fixture([1, 0, 0]);
    const artifact = envelopes[0]!;
    const hash = parseHash256(artifact.hash);
    artifact.hash.fill(0xff);
    expect(session.ingest(artifact).status).toBe("accepted");
    vi.spyOn(session, "heads").mockReturnValue([{ from: ROSTER[0]!, seq: 0, hash }]);
    expect(() => captureSessionHistory(session)).toThrow(expect.objectContaining({
      name: "SessionHistoryCaptureError", message: "Session history cache changed",
    }));
  });

  it("ignores corrupt decoded headers and hashes when canonical sources and the native cache remain intact", () => {
    const { session, envelopes } = fixture();
    const read = session.readRange.bind(session);
    vi.spyOn(session, "readRange").mockImplementation((...args) => {
      const range = read(...args);
      if (range.status !== "complete") return range;
      return { status: "complete", envelopes: range.envelopes.map((artifact) => ({ ...artifact, hash: ZERO,
        envelope: { ...artifact.envelope, game: parseGameId(new Uint8Array(16)), from: ROSTER[7]!, seq: 999, body: null },
      })) };
    });
    expect(captureSessionHistory(session).envelopes).toEqual(envelopes);
  });

  it.each(["during capture", "after capture"])("detects original byte mutation %s", (timing) => {
    const { session, envelopes } = fixture();
    if (timing === "during capture") {
      const read = session.readRange.bind(session);
      vi.spyOn(session, "readRange").mockImplementation((...args) => {
        const result = read(...args);
        if (args[0][0] === ROSTER[2]![0]) envelopes[0]!.canonicalBytes.fill(0xff);
        return result;
      });
      expect(() => captureSessionHistory(session)).toThrow(SessionHistoryCaptureError);
    } else {
      const history = captureSessionHistory(session);
      envelopes[0]!.canonicalBytes.fill(0xff);
      expect(history.assertUnchanged).toThrow(SessionHistoryCaptureError);
    }
  });

  it.each(["game", "roster", "heads"] as const)("detects mutation of captured %s views even if fresh getters are unchanged", (scope) => {
    const { session } = fixture();
    const game = session.gameId;
    const roster = session.roster;
    const heads = session.heads();
    vi.spyOn(session, "gameId", "get").mockReturnValueOnce(game);
    vi.spyOn(session, "roster", "get").mockReturnValueOnce(roster);
    vi.spyOn(session, "heads").mockReturnValueOnce(heads);
    const history = captureSessionHistory(session);
    if (scope === "game") game.fill(0xff);
    else if (scope === "roster") roster[0]!.fill(0xff);
    else heads[0]!.hash.fill(0xff);
    expect(history.assertUnchanged).toThrow(SessionHistoryCaptureError);
  });

  it.each(["game", "roster", "heads"] as const)("detects changed current %s while original snapshots stay intact", (scope) => {
    const { session } = fixture();
    const history = captureSessionHistory(session);
    if (scope === "game") vi.spyOn(session, "gameId", "get").mockReturnValue(parseGameId(new Uint8Array(16)));
    else if (scope === "roster") vi.spyOn(session, "roster", "get").mockReturnValue([...session.roster].reverse());
    else vi.spyOn(session, "heads").mockReturnValue([]);
    expect(history.assertUnchanged).toThrow(SessionHistoryCaptureError);
  });

  it("detects a new sender chain after an empty capture", () => {
    const { session } = fixture([0, 0, 0]);
    const history = captureSessionHistory(session);
    const { envelopes } = fixture([0, 1, 0]);
    expect(session.ingest(envelopes[0]!).status).toBe("accepted");
    expect(history.assertUnchanged).toThrow(SessionHistoryCaptureError);
  });

  it("passes independent sender copies to range reads", () => {
    const { session, envelopes } = fixture();
    const read = session.readRange.bind(session);
    vi.spyOn(session, "readRange").mockImplementation((sender, ...args) => {
      const result = read(sender, ...args);
      sender.fill(0xff);
      return result;
    });
    const history = captureSessionHistory(session);
    expect(history.envelopes).toEqual(envelopes);
    history.assertUnchanged();
  });
});
