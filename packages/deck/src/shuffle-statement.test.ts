import { describe, expect, it } from "vitest";
import { RistrettoPoint, scalarFromBigInt } from "@p2pcards/crypto";
import { parseGameId, parseHash256 } from "@p2pcards/protocol";
import { encodeCanonical } from "@p2pcards/encoding";
import { CANDIDATE_SHUFFLE_STATEMENT_PROFILE as profile, encodeCandidateShuffleStatement as encode,
  decodeCandidateShuffleStatement as decode, encodeCandidateShuffleWitness } from "./shuffle-statement";
const deck = Array.from({ length: 36 }, () => ({ A: RistrettoPoint.identity(), B: RistrettoPoint.base() }));
const dimensions = { rows: 4, columns: 9 };
const witness = (input: Parameters<typeof encodeCandidateShuffleWitness>[0]) => encodeCandidateShuffleWitness(input, dimensions);
const statement = { ...dimensions, gameId: parseGameId(new Uint8Array(16)), round: 0, seat: 0,
  rosterHash: parseHash256(new Uint8Array(32)), aggregateKey: RistrettoPoint.base(), inputDeck: deck, outputDeck: deck };
const wire = encode(statement);
const roundOffset = encodeCanonical(profile).length + 20;
describe("bounded candidate shuffle statement", () => {
  it("uses fixed canonical CBOR and permits initial identity ciphertext components", () => {
    const packed = new Uint8Array(2304);
    for (let i = 0; i < 36; i++) packed.set(RistrettoPoint.base().toBytes(), i * 64 + 32);
    expect(wire).toEqual(encodeCanonical([profile, 4, 9, statement.gameId, 0, 0, statement.rosterHash,
      statement.aggregateKey.toBytes(), packed, packed]));
    expect(wire.length).toBe(4744);
    expect(encode({ ...statement, round: Number.MAX_SAFE_INTEGER }).length).toBe(wire.length + 8);
  });
  it.each([0, 23, 24, 255, 256, 65535, 65536, 4294967295, 4294967296, Number.MAX_SAFE_INTEGER])("round trips round %s", round => {
    const bytes = encode({ ...statement, round });
    expect(decode(bytes).round).toBe(round);
    expect(encode(decode(bytes))).toEqual(bytes);
  });
  it("rejects every truncation and trailing data", () => {
    for (let n = 0; n < wire.length; n++) expect(() => decode(wire.slice(0, n))).toThrow();
    expect(() => decode(new Uint8Array([...wire, 0]))).toThrow();
  });
  it("rejects nonminimal integers, unsafe integers, invalid points and forged field lengths", () => {
    const replaceRound = (bytes: number[]) => new Uint8Array([...wire.slice(0, roundOffset), ...bytes, ...wire.slice(roundOffset + 1)]);
    for (const bytes of [[24, 0], [25, 0, 24], [27, 0, 32, 0, 0, 0, 0, 0, 0], [32], [255]])
      expect(() => decode(replaceRound(bytes))).toThrow();
    for (const index of [0, 1, roundOffset + 1, roundOffset + 2, roundOffset + 36, roundOffset + 70]) {
      const bad = wire.slice(); bad[index] = 255; expect(() => decode(bad)).toThrow();
    }
    for (const fill of [0, 255]) {
      const bad = wire.slice(); bad.fill(fill, roundOffset + 38, roundOffset + 70);
      expect(() => decode(bad)).toThrow();
    }
  });
  it("rejects invalid typed inputs", () => {
    for (const round of [-0, -1, 0.5, Infinity, Number.MAX_SAFE_INTEGER + 1]) expect(() => encode({ ...statement, round })).toThrow();
    for (const seat of [-0, -1, 4, 0.5]) expect(() => encode({ ...statement, seat })).toThrow();
    expect(() => encode({ ...statement, aggregateKey: RistrettoPoint.identity() })).toThrow();
    expect(() => encode({ ...statement, inputDeck: deck.slice(1) })).toThrow();
  });
  it.each([[4, 13], [2, 64], [64, 2], [2, 2]])("round trips the %ix%i profile", (rows, columns) => {
    const cards = Array.from({ length: rows * columns }, () => deck[0]!);
    const value = { ...statement, rows, columns, inputDeck: cards, outputDeck: cards };
    expect(decode(encode(value))).toEqual(value);
    const permutation = cards.map((_, i) => i);
    const randomizers = cards.map(() => scalarFromBigInt(1n));
    expect(encodeCandidateShuffleWitness({ permutation, randomizers }, value).randomizers.length)
      .toBe(cards.length * 32);
  });
  it.each([[1, 36], [4, 33], [0, 9], [4.5, 8], [Infinity, 9]])("rejects dimensions %sx%s", (rows, columns) => {
    expect(() => encode({ ...statement, rows, columns })).toThrow(/dimensions/);
  });
  it("rejects dimensions that disagree with the encoded deck", () => {
    const bad = wire.slice(); bad[encodeCanonical(profile).length + 2] = 13;
    expect(() => decode(bad)).toThrow(/byte length/);
  });
  it("detaches decoded data", () => {
    const bytes = wire.slice(), decoded = decode(bytes); bytes.fill(255);
    expect(encode(decoded)).toEqual(wire);
  });
  it("encodes only complete permutations and canonical nonzero private scalars", () => {
    const permutation = Array.from({ length: 36 }, (_, i) => (i + 1) % 36);
    const randomizers = Array.from({ length: 36 }, () => scalarFromBigInt(1n));
    const result = witness({ permutation, randomizers });
    expect(result.permutation).toEqual(new Uint8Array(permutation));
    expect(result.randomizers.length).toBe(1152);
    for (const value of [0, 36, -1, 0.5]) {
      const bad = [...permutation]; bad[0] = value; expect(() => witness({ permutation: bad, randomizers })).toThrow();
    }
    expect(() => witness({ permutation, randomizers: randomizers.slice(1) })).toThrow();
    expect(() => witness({ permutation, randomizers: randomizers.map(() => scalarFromBigInt(0n)) })).toThrow();
    permutation.fill(0); randomizers.fill(scalarFromBigInt(2n));
    expect(result.permutation[0]).toBe(1); expect(result.randomizers[0]).toBe(1);
  });
});
