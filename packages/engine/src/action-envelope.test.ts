import {
  deriveEd25519PublicKey, importEd25519SecretKey, RistrettoPoint, scalarFromBigInt, type RandomSource,
} from "@p2pcards/crypto";
import {
  aggregatePublicKeys, CardPointTable, createProvenDecryptionShare, encodeActionBody,
  maskCard, removeDecryptionShares, verifyProvenDecryptionShare,
} from "@p2pcards/deck";
import { decodeCanonical, encodeCanonical, type CborMap, type CborValue } from "@p2pcards/encoding";
import { parseGameId, parseHash256, parseIdentityPublicKey, signEnvelope, type UnsignedEnvelope } from "@p2pcards/protocol";
import { decodeSaskuAction, parseSaskuCard, SASKU_DECK_SPEC, SaskuPublicHandController } from "@p2pcards/rules-sasku";
import { describe, expect, it } from "vitest";

import { ActionEnvelopeError, decodeActionEnvelope, MAX_ACTION_ENVELOPE_BYTES, type ActionEnvelopeScope } from "./action-envelope";

const IDENTITIES = Array.from({ length: 9 }, (_, seat) => {
  const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(30 + seat));
  return { secretKey, publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)) };
});
const GAME = parseGameId(new Uint8Array(16).fill(0x31));
const SCOPE: ActionEnvelopeScope = {
  gameId: GAME, round: 2, actionIndex: 0,
  roster: IDENTITIES.slice(0, 4).map(({ publicKey }) => publicKey), expectedSeats: [0],
};
const PASS = { kind: "pass", data: {}, reveal: [], shares: [] };

describe("scoped signed ACTION decoding", () => {
  it("authenticates the actor and snapshots the canonical body without applying or durably accepting anything", () => {
    const artifact = signed();
    const bytes = artifact.canonicalBytes.slice();
    const decoded = decodeActionEnvelope(bytes, SCOPE);
    expect(decoded.seat).toBe(0);
    expect(decoded.action).toEqual(PASS);
    expect(decoded.received.canonicalBytes).toEqual(artifact.canonicalBytes);
    expect(decoded.received.hash).toEqual(artifact.hash);
    expect(Object.isFrozen(decoded)).toBe(true);
    bytes.fill(0xff);
    expect(decoded.received.canonicalBytes).toEqual(artifact.canonicalBytes);
    expect(decodeActionEnvelope(artifact.canonicalBytes, SCOPE)).toEqual(decoded);
    // Sender sequence is not the action phase index; chain receipt is a separate gate.
    expect(decodeActionEnvelope(signed(0, PASS, { seq: 99, prev: parseHash256(new Uint8Array(32).fill(1)) }).canonicalBytes, SCOPE).seat).toBe(0);
  });

  it.each([3, 8])("supports %i finalized seats and an explicit set of expected senders", (count) => {
    const scope = { ...SCOPE, roster: IDENTITIES.slice(0, count).map(({ publicKey }) => publicKey), expectedSeats: [1, count - 1] };
    for (const seat of scope.expectedSeats) expect(decodeActionEnvelope(signed(seat).canonicalBytes, scope).seat).toBe(seat);
    expect(() => decodeActionEnvelope(signed(0).canonicalBytes, scope)).toThrow(expect.objectContaining({ code: "unexpected_sender" }));
  });

  it.each([
    ["wrong_game", 0, { game: parseGameId(new Uint8Array(16).fill(0x32)) }],
    ["unknown_sender", 4, {}],
    ["unexpected_sender", 1, {}],
    ["wrong_round", 0, { round: 3 }],
    ["wrong_type", 0, { type: "AUDIT_DISCLOSE" }],
    ["wrong_phase", 0, { phase: "round.2.play.1" }],
    ["wrong_phase", 0, { phase: "round.2.play.00" }],
    ["wrong_phase", 0, { phase: "round.2.deal.0" }],
  ] as const)("rejects %s", (code, author, overrides) => {
    expect(() => decodeActionEnvelope(signed(author, PASS, overrides).canonicalBytes, SCOPE)).toThrow(expect.objectContaining({ code }));
  });

  it.each([
    {}, { ...PASS, seat: 0 }, { ...PASS, kind: "Pass" },
    { ...PASS, reveal: [1] }, { ...PASS, data: new Uint8Array(4096) },
  ])("rejects signed malformed bodies: %j", (body) => {
    expect(() => decodeActionEnvelope(signed(0, body).canonicalBytes, SCOPE)).toThrow(expect.objectContaining({ code: "malformed_body" }));
  });

  it("does not trust a mutated artifact view and fails on signature tampering, noncanonical bytes, and oversized input", () => {
    const artifact = signed();
    (artifact.envelope.body as Record<string, CborValue>)["kind"] = "diamonds";
    expect(decodeActionEnvelope(artifact.canonicalBytes, SCOPE).action.kind).toBe("pass");
    const wire = decodeCanonical(artifact.canonicalBytes) as CborMap;
    const tampered = encodeCanonical({ ...wire, body: { ...PASS, kind: "diamonds" } });
    for (const bytes of [tampered, new Uint8Array(), new Uint8Array([0xa0]), new Uint8Array(MAX_ACTION_ENVELOPE_BYTES + 1),
      new Uint8Array([...artifact.canonicalBytes, 0])]) {
      expect(() => decodeActionEnvelope(bytes, SCOPE)).toThrow(expect.objectContaining({ code: "invalid_envelope" }));
    }
    expect(() => decodeActionEnvelope(new Uint16Array(1) as unknown as Uint8Array, SCOPE)).toThrow(ActionEnvelopeError);
  });

  it.each([-0, -1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])("rejects invalid round/action index %s", (value) => {
    const bytes = signed().canonicalBytes;
    expect(() => decodeActionEnvelope(bytes, { ...SCOPE, round: value })).toThrow(RangeError);
    expect(() => decodeActionEnvelope(bytes, { ...SCOPE, actionIndex: value })).toThrow(RangeError);
  });

  it("accepts exact safe-integer phase components without confusing them with sender sequence", () => {
    const value = Number.MAX_SAFE_INTEGER;
    const scope = { ...SCOPE, round: value, actionIndex: value };
    const artifact = signed(0, PASS, { round: value, phase: `round.${value}.play.${value}` });
    expect(decodeActionEnvelope(artifact.canonicalBytes, scope).seat).toBe(0);
  });

  it("rejects malformed scope, invalid roster keys, duplicate identities, and ambiguous expected-seat lists", () => {
    const bytes = signed().canonicalBytes;
    expect(() => decodeActionEnvelope(bytes, null as unknown as ActionEnvelopeScope)).toThrow(TypeError);
    expect(() => decodeActionEnvelope(bytes, { ...SCOPE, gameId: new Uint8Array(15) as typeof GAME })).toThrow();
    for (const roster of [[], SCOPE.roster.slice(0, 2), IDENTITIES.map(({ publicKey }) => publicKey),
      [SCOPE.roster[0]!, SCOPE.roster[0]!, SCOPE.roster[1]!],
      [parseIdentityPublicKey(new Uint8Array(32)), SCOPE.roster[1]!, SCOPE.roster[2]!],
      new Array<typeof SCOPE.roster[number]>(3)]) {
      expect(() => decodeActionEnvelope(bytes, { ...SCOPE, roster })).toThrow();
    }
    for (const expectedSeats of [[], [0, 0], [-0], [-1], [4], [0.5], [NaN], [0, 1, 2, 3, 4], new Array<number>(1)]) {
      expect(() => decodeActionEnvelope(bytes, { ...SCOPE, expectedSeats })).toThrow(RangeError);
    }
  });

  it("keeps decoded action data independent of the returned envelope body", () => {
    const decoded = decodeActionEnvelope(signed(0, { ...PASS, data: { opaque: new Uint8Array([1, 2]) } }).canonicalBytes, SCOPE);
    const body = decoded.received.envelope.body as CborMap;
    ((body["data"] as CborMap)["opaque"] as Uint8Array).fill(0xff);
    expect(decoded.action.data).toEqual({ opaque: new Uint8Array([1, 2]) });
  });

  it("composes signed actions, separately verified DLEQ reveals, and public Sasku progression", () => {
    const hand = new SaskuPublicHandController({ dealer: 3 });
    const opening = decodeActionEnvelope(signed(0, { ...PASS, kind: "diamonds" }).canonicalBytes, SCOPE);
    expect(hand.history).toEqual([]);
    hand.apply(decodeSaskuAction(opening.seat, {
      kind: opening.action.kind, data: opening.action.data, reveal: opening.action.reveal,
    }, {}));

    // A deterministic masked-card fixture, not a shuffle proof or a verified dealing schedule.
    const table = new CardPointTable(SASKU_DECK_SPEC);
    const secrets = [1n, 2n, 3n, 4n].map(scalarFromBigInt);
    const publicKeys = secrets.map((secret) => RistrettoPoint.base().multiply(secret));
    const ciphertext = maskCard(table.pointAt(0), scalarFromBigInt(7n), aggregatePublicKeys(publicKeys));
    const pos = 17;
    const actionScope = { ...SCOPE, actionIndex: 1, expectedSeats: [hand.snapshot.turn!] };
    const context = { gameId: GAME, round: 2, phase: "round.2.play.1" };
    const dealContext = { ...context, phase: "round.2.deal.0" };
    const source: RandomSource = { fill: (bytes) => { bytes.fill(0); bytes[0] = 13; } };
    const earlierShares = secrets.slice(1).map((secret) => createProvenDecryptionShare(dealContext, pos, secret, ciphertext.A, source));
    const ownerShare = { pos, ...createProvenDecryptionShare(context, pos, secrets[0]!, ciphertext.A, source) };
    const body = encodeActionBody({ kind: "play", data: {}, reveal: [pos], shares: [ownerShare] });
    const decoded = decodeActionEnvelope(signed(0, body, { phase: context.phase }).canonicalBytes, actionScope);
    const share = decoded.action.shares[0]!;
    expect(verifyProvenDecryptionShare(context, pos, publicKeys[decoded.seat]!, ciphertext.A, share)).toBe(true);
    earlierShares.forEach((item, index) => expect(verifyProvenDecryptionShare(dealContext, pos, publicKeys[index + 1]!, ciphertext.A, item)).toBe(true));
    const card = parseSaskuCard(table.identify(removeDecryptionShares(ciphertext, [share.S, ...earlierShares.map(({ S }) => S)]))).id;
    const action = decodeSaskuAction(decoded.seat, { kind: decoded.action.kind, data: decoded.action.data, reveal: decoded.action.reveal }, { [pos]: card });
    expect(action).toEqual({ type: "play", seat: 0, card: "6C" });
    expect(hand.history).toHaveLength(1);
    hand.apply(action);
    expect(hand.snapshot.trick).toEqual([{ seat: 0, card: "6C" }]);

    const invalidProofBody = encodeActionBody({ ...decoded.action, shares: [{ ...ownerShare, proof: { ...ownerShare.proof, z: scalarFromBigInt(1n) } }] });
    const unchecked = decodeActionEnvelope(signed(0, invalidProofBody, { phase: context.phase }).canonicalBytes, actionScope);
    expect(verifyProvenDecryptionShare(context, pos, publicKeys[0]!, ciphertext.A, unchecked.action.shares[0]!)).toBe(false);
    expect(hand.history).toHaveLength(2);
    const forgedCardBody = { ...body, data: { card: "AD" } };
    const forged = decodeActionEnvelope(signed(0, forgedCardBody, { phase: context.phase }).canonicalBytes, actionScope);
    expect(() => decodeSaskuAction(forged.seat, { kind: forged.action.kind, data: forged.action.data, reveal: forged.action.reveal }, { [pos]: card })).toThrow();
  });
});

function signed(author = 0, body: CborValue = PASS, overrides: Partial<UnsignedEnvelope> = {}) {
  const identity = IDENTITIES[author]!;
  return signEnvelope({
    v: 1, game: GAME, from: identity.publicKey, seq: 0, prev: parseHash256(new Uint8Array(32)),
    round: 2, phase: "round.2.play.0", type: "ACTION", body, ...overrides,
  }, identity.secretKey);
}
