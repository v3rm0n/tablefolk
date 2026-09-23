import { parseIdentityPublicKey, type IdentityPublicKey } from "@p2pcards/protocol";

export type PerfectNegotiationRole = "impolite" | "polite";

export function perfectNegotiationRole(
  localIdentity: Uint8Array,
  remoteIdentity: Uint8Array,
): PerfectNegotiationRole {
  const local = parseIdentityPublicKey(localIdentity);
  const remote = parseIdentityPublicKey(remoteIdentity);
  const comparison = compareIdentities(local, remote);
  if (comparison === 0) {
    throw new Error("Perfect-negotiation peers must have distinct identities");
  }
  return comparison < 0 ? "impolite" : "polite";
}

export function compareIdentities(
  left: IdentityPublicKey,
  right: IdentityPublicKey,
): -1 | 0 | 1 {
  for (let index = 0; index < left.length; index += 1) {
    const difference = left[index]! - right[index]!;
    if (difference !== 0) {
      return difference < 0 ? -1 : 1;
    }
  }
  return 0;
}
