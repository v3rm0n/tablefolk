import { parseIdentityPublicKey } from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";

import { compareIdentities, perfectNegotiationRole } from "./peer-role";

describe("perfect-negotiation peer roles", () => {
  it("assigns the lexicographically smaller identity the impolite role", () => {
    const smaller = identity(0, 1);
    const larger = identity(0, 2);

    expect(compareIdentities(smaller, larger)).toBe(-1);
    expect(compareIdentities(larger, smaller)).toBe(1);
    expect(perfectNegotiationRole(smaller, larger)).toBe("impolite");
    expect(perfectNegotiationRole(larger, smaller)).toBe("polite");
  });

  it("rejects a peer pair with the same identity", () => {
    const peer = identity(5, 5);
    expect(compareIdentities(peer, peer)).toBe(0);
    expect(() => perfectNegotiationRole(peer, peer)).toThrow(/distinct identities/);
  });
});

function identity(first: number, last: number) {
  const bytes = new Uint8Array(32);
  bytes[0] = first;
  bytes[31] = last;
  return parseIdentityPublicKey(bytes);
}
