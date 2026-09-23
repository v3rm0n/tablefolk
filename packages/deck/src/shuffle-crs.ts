import { RistrettoPoint, sha512 } from "@p2pcards/crypto";
import { encodeCanonical } from "@p2pcards/encoding";
import { domainSeparator } from "@p2pcards/protocol";

/** Candidate parameters only: not a complete or reviewed shuffle proof profile. */
export const SHUFFLE_CRS_36_PROFILE = "bg-ristretto255-36-4x9-crs-candidate-v1";

export interface ShuffleCrs36 {
  readonly profile: typeof SHUFFLE_CRS_36_PROFILE;
  readonly rows: 4;
  readonly columns: 9;
  readonly encryptionGenerator: RistrettoPoint;
  readonly proofGenerator: RistrettoPoint;
  readonly blindingGenerator: RistrettoPoint;
  readonly messageGenerators: readonly RistrettoPoint[];
}

/** No participant-selected seed, scalar-times-base derivation, or fallback CRS. */
export function deriveShuffleCrs36(): ShuffleCrs36 {
  const encryptionGenerator = RistrettoPoint.base();
  const previous = [encryptionGenerator];
  function derive(role: "proof" | "blinding" | "message", index: number): RistrettoPoint {
    const point = RistrettoPoint.fromUniformBytes(sha512(
      domainSeparator("shuffle"),
      encodeCanonical(["crs", SHUFFLE_CRS_36_PROFILE, 4, 9, role, index]),
    ));
    if (point.isIdentity() || previous.some((other) =>
      point.equals(other) || point.equals(other.negate()))) {
      throw new Error("Degenerate shuffle CRS; profile revision required");
    }
    previous.push(point);
    return point;
  }

  const proofGenerator = derive("proof", 0);
  const blindingGenerator = derive("blinding", 0);
  const messageGenerators = Object.freeze(Array.from({ length: 9 }, (_, i) => derive("message", i)));
  return Object.freeze({
    profile: SHUFFLE_CRS_36_PROFILE,
    rows: 4,
    columns: 9,
    encryptionGenerator,
    proofGenerator,
    blindingGenerator,
    messageGenerators,
  });
}
