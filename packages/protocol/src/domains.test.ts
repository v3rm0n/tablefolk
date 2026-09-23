import { bytesToHex } from "@p2pcards/crypto";
import { describe, expect, it } from "vitest";

import { DOMAIN_SEPARATORS, domainSeparator } from "./domains";

describe("domain separators", () => {
  it("matches the complete version 1 catalogue", () => {
    expect(DOMAIN_SEPARATORS).toEqual({
      room: "p2pcards/v1/room",
      channel: "p2pcards/v1/chan",
      message: "p2pcards/v1/msg",
      card: "p2pcards/v1/card",
      proofOfPossession: "p2pcards/v1/pop",
      decryptionShare: "p2pcards/v1/dleq",
      shuffle: "p2pcards/v1/shuffle",
      beacon: "p2pcards/v1/beacon",
    });
  });

  it("returns a fresh exact byte representation", () => {
    const first = domainSeparator("room");
    first[0] = 0;

    expect(bytesToHex(domainSeparator("room"))).toBe(
      "70327063617264732f76312f726f6f6d",
    );
  });
});
