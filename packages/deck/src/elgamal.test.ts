import { RistrettoPoint, scalarFromBigInt } from "@p2pcards/crypto";
import { describe, expect, it } from "vitest";

import { deriveCardPoint } from "./card-points";
import {
  aggregatePublicKeys,
  decryptionShare,
  initialMaskedCard,
  maskCard,
  remaskCard,
  removeDecryptionShares,
} from "./elgamal";

describe("exponential ElGamal card masking", () => {
  const secrets = [3n, 5n, 7n].map((value) => scalarFromBigInt(value));
  const publicKeys = secrets.map((secret) => RistrettoPoint.base().multiply(secret));
  const aggregateKey = aggregatePublicKeys(publicKeys);
  const message = deriveCardPoint("test/2@1", "C:A");

  it("constructs the public unmasked initial card", () => {
    const initial = initialMaskedCard(message);
    expect(initial.A.isIdentity()).toBe(true);
    expect(initial.B.equals(message)).toBe(true);
  });

  it("recovers a masked card after all decryption shares", () => {
    const card = maskCard(message, scalarFromBigInt(11n), aggregateKey);
    const shares = secrets.map((secret) => decryptionShare(secret, card.A));

    expect(card.A.isIdentity()).toBe(false);
    expect(card.B.equals(message)).toBe(false);
    expect(removeDecryptionShares(card, shares).equals(message)).toBe(true);
  });

  it("preserves the plaintext through remasking", () => {
    const masked = maskCard(message, scalarFromBigInt(11n), aggregateKey);
    const remasked = remaskCard(masked, scalarFromBigInt(13n), aggregateKey);
    const shares = secrets.map((secret) => decryptionShare(secret, remasked.A));

    expect(remasked.A.equals(masked.A)).toBe(false);
    expect(remasked.B.equals(masked.B)).toBe(false);
    expect(removeDecryptionShares(remasked, shares).equals(message)).toBe(true);
  });

  it("supports recipient-only reveal by withholding that recipient's share", () => {
    const card = maskCard(message, scalarFromBigInt(17n), aggregateKey);
    const publicRemainder = removeDecryptionShares(card, [
      decryptionShare(secrets[1]!, card.A),
      decryptionShare(secrets[2]!, card.A),
    ]);
    const recipientMessage = publicRemainder.subtract(decryptionShare(secrets[0]!, card.A));

    expect(publicRemainder.equals(message)).toBe(false);
    expect(recipientMessage.equals(message)).toBe(true);
  });

  it("rejects identity keys and zero fresh randomness", () => {
    expect(() => aggregatePublicKeys([])).toThrow(RangeError);
    expect(() => aggregatePublicKeys([RistrettoPoint.identity()])).toThrow(TypeError);
    expect(() => maskCard(message, scalarFromBigInt(0n), aggregateKey)).toThrow(TypeError);
    expect(() => maskCard(message, scalarFromBigInt(1n), RistrettoPoint.identity())).toThrow(
      TypeError,
    );
  });
});
