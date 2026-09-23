import {
  parseDtlsFingerprint,
  type DtlsFingerprint,
} from "@p2pcards/protocol";

export class DtlsFingerprintError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DtlsFingerprintError";
  }
}

export function sha256FingerprintFromSdp(sdp: string): DtlsFingerprint {
  if (typeof sdp !== "string" || sdp.length === 0) {
    throw new DtlsFingerprintError("SDP must be non-empty text");
  }
  const fingerprints = new Map<string, DtlsFingerprint>();
  for (const line of sdp.split(/\r?\n/)) {
    if (!line.toLowerCase().startsWith("a=fingerprint:sha-256")) {
      continue;
    }
    const match = /^a=fingerprint:sha-256[ \t]+((?:[0-9a-f]{2}:){31}[0-9a-f]{2})$/i.exec(
      line,
    );
    if (match === null) {
      throw new DtlsFingerprintError("SDP contains a malformed SHA-256 fingerprint");
    }
    const hex = match[1]!.replaceAll(":", "").toLowerCase();
    const bytes = new Uint8Array(32);
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
    }
    fingerprints.set(hex, parseDtlsFingerprint(bytes));
  }
  if (fingerprints.size === 0) {
    throw new DtlsFingerprintError("SDP contains no SHA-256 fingerprint");
  }
  if (fingerprints.size !== 1) {
    throw new DtlsFingerprintError("SDP contains conflicting SHA-256 fingerprints");
  }
  return parseDtlsFingerprint(fingerprints.values().next().value);
}
