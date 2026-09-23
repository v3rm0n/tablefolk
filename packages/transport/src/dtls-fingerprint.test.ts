import { describe, expect, it } from "vitest";

import { DtlsFingerprintError, sha256FingerprintFromSdp } from "./dtls-fingerprint";

const FIRST = fingerprintText(0);
const SECOND = fingerprintText(32);

describe("SDP DTLS fingerprints", () => {
  it("extracts one SHA-256 fingerprint repeated across bundled media sections", () => {
    const fingerprint = sha256FingerprintFromSdp(
      [
        "v=0",
        `a=fingerprint:sha-256 ${FIRST}`,
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
        `a=fingerprint:SHA-256 ${FIRST.toLowerCase()}`,
        "",
      ].join("\r\n"),
    );

    expect(fingerprint).toEqual(Uint8Array.from({ length: 32 }, (_, index) => index));
  });

  it("ignores other algorithms but rejects absent, malformed, or conflicting SHA-256 values", () => {
    expect(() =>
      sha256FingerprintFromSdp("v=0\r\na=fingerprint:sha-384 AA:BB\r\n"),
    ).toThrow(/no SHA-256/);
    expect(() =>
      sha256FingerprintFromSdp("v=0\r\na=fingerprint:sha-256 AA:BB\r\n"),
    ).toThrow(DtlsFingerprintError);
    expect(() =>
      sha256FingerprintFromSdp(
        `v=0\r\na=fingerprint:sha-256 ${FIRST}\r\na=fingerprint:sha-256 ${SECOND}\r\n`,
      ),
    ).toThrow(/conflicting/);
    expect(() => sha256FingerprintFromSdp("")).toThrow(/non-empty/);
  });
});

function fingerprintText(offset: number): string {
  return Array.from({ length: 32 }, (_, index) =>
    ((offset + index) & 0xff).toString(16).padStart(2, "0").toUpperCase(),
  ).join(":");
}
