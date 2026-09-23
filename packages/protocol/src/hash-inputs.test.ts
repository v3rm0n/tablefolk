import {
  bytesToHex,
  hexToBytes,
  sha256,
} from "@p2pcards/crypto";
import { encodeCanonical } from "@p2pcards/encoding";
import { describe, expect, it } from "vitest";

import { parseDtlsFingerprint, parseGameId, parseRandomSecret } from "./fields";
import {
  beaconCommitment,
  cardDerivationHash,
  channelAuthenticationInput,
  deriveSignalingRoomId,
  envelopeSignatureInput,
  hashEnvelope,
  proofChallengeInput,
  proofChallengeScalar,
} from "./hash-inputs";

describe("domain-separated protocol inputs", () => {
  const gameId = parseGameId(hexToBytes("000102030405060708090a0b0c0d0e0f"));

  it("derives the signaling room ID from an independent known-answer vector", () => {
    expect(bytesToHex(deriveSignalingRoomId(gameId))).toBe(
      "2ccf569d072847ebb48abfeddce131403f6c08242103e9fe130b324b180e472e",
    );
  });

  it("builds the channel-authentication input in local/remote order", () => {
    const local = parseDtlsFingerprint(new Uint8Array(32).fill(0x11));
    const remote = parseDtlsFingerprint(new Uint8Array(32).fill(0x22));

    expect(bytesToHex(channelAuthenticationInput(gameId, local, remote))).toBe(
      "70327063617264732f76312f6368616e" +
        "000102030405060708090a0b0c0d0e0f" +
        "11".repeat(32) +
        "22".repeat(32),
    );
  });

  it("prefixes canonical unsigned envelopes for Ed25519 signing", () => {
    const canonical = encodeCanonical({ game: gameId, seq: 0, v: 1 });

    expect(bytesToHex(envelopeSignatureInput(canonical))).toBe(
      "70327063617264732f76312f6d7367" + bytesToHex(canonical),
    );
  });

  it("hashes signed canonical envelopes without a domain prefix", () => {
    const canonical = encodeCanonical({ sig: new Uint8Array(64), v: 1 });

    expect(hashEnvelope(canonical)).toEqual(sha256(canonical));
  });

  it("frames card identifiers as separate canonical CBOR strings", () => {
    expect(bytesToHex(cardDerivationHash("sasku/36@1", "C:K"))).toBe(
      "4e96cd48b7d86585e1c16999385bfaed218a538fee2ccc744e571e579606d46c" +
        "ddb4b8da8e53445ff3a95da530c2cbdb92365851213630167bc3005cc4c210ac",
    );
  });

  it("frames beacon round and seat before the fixed random secret", () => {
    const secret = parseRandomSecret(new Uint8Array(32).fill(0x5a));
    expect(bytesToHex(beaconCommitment(gameId, 3, 2, secret))).toBe(
      "c732892833a79489b392f8af7ed2b6f816526f231b68611c0dcc4fb6b5bf6220",
    );
  });

  it("constructs and reduces a fully framed proof challenge", () => {
    const context = { gameId, round: 4, phase: "round.4.audit" } as const;
    const statement = { H: new Uint8Array(32).fill(1), R: new Uint8Array(32).fill(2) };

    expect(bytesToHex(proofChallengeInput("proofOfPossession", context, statement))).toBe(
      "70327063617264732f76312f706f70" +
        "000102030405060708090a0b0c0d0e0f" +
        "04" +
        "6d726f756e642e342e6175646974" +
        "a261485820" +
        "01".repeat(32) +
        "61525820" +
        "02".repeat(32),
    );
    expect(proofChallengeScalar("proofOfPossession", context, statement)).toBe(
      193730150726948330367485200809680082608773706272248460798390502771427776701n,
    );
  });

  it("rejects invalid hash context values", () => {
    const secret = parseRandomSecret(new Uint8Array(32));
    expect(() => beaconCommitment(gameId, 0, 8, secret)).toThrow(RangeError);
    expect(() => cardDerivationHash("", "C:K")).toThrow(TypeError);
    expect(() =>
      proofChallengeInput(
        "shuffle",
        { gameId, round: -1, phase: "round.0.shuffle.0" },
        {},
      ),
    ).toThrow(RangeError);
  });
});
