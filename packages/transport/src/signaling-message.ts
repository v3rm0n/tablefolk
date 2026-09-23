import {
  decodeCanonical,
  encodeCanonical,
  type CanonicalCbor,
  type CborValue,
} from "@p2pcards/encoding";
import {
  expectExactMap,
  expectUnsignedInteger,
  ProtocolSchemaError,
} from "@p2pcards/protocol";

export interface DescriptionSignal {
  readonly kind: "description";
  readonly descriptionType: "offer" | "answer";
  readonly sdp: string;
}

export interface CandidateSignal {
  readonly kind: "candidate";
  readonly candidate: string | null;
  readonly sdpMid: string | null;
  readonly sdpMLineIndex: number | null;
  readonly usernameFragment: string | null;
}

export type PeerSignal = DescriptionSignal | CandidateSignal;

export const MAX_SDP_BYTES = 256 * 1024;
export const MAX_ICE_CANDIDATE_BYTES = 4 * 1024;
export const MAX_ICE_FIELD_BYTES = 256;
export const MAX_SIGNALING_MESSAGE_BYTES = MAX_SDP_BYTES + 1024;

const DESCRIPTION_KEYS = ["kind", "description_type", "sdp"] as const;
const CANDIDATE_KEYS = [
  "kind",
  "candidate",
  "sdp_mid",
  "sdp_mline_index",
  "username_fragment",
] as const;
const MAX_SDP_M_LINE_INDEX = 0xffff;

export function encodePeerSignal(signal: PeerSignal): CanonicalCbor {
  const normalized = normalizePeerSignal(signal);
  if (normalized.kind === "description") {
    return encodeBoundedSignal({
      kind: normalized.kind,
      description_type: normalized.descriptionType,
      sdp: normalized.sdp,
    });
  }
  return encodeBoundedSignal({
    kind: normalized.kind,
    candidate: normalized.candidate,
    sdp_mid: normalized.sdpMid,
    sdp_mline_index: normalized.sdpMLineIndex,
    username_fragment: normalized.usernameFragment,
  });
}

export function decodePeerSignal(encoded: Uint8Array): PeerSignal {
  requireEncodedSignal(encoded);
  const value = decodeCanonical(encoded);
  if (!isMap(value)) {
    throw new ProtocolSchemaError("PeerSignal", "must be a CBOR map");
  }
  const kind = expectText(value["kind"], "PeerSignal.kind");
  if (kind === "description") {
    const signal = expectExactMap(value, DESCRIPTION_KEYS, "DescriptionSignal");
    return normalizeDescription(
      signal["description_type"],
      signal["sdp"],
    );
  }
  if (kind === "candidate") {
    const signal = expectExactMap(value, CANDIDATE_KEYS, "CandidateSignal");
    return normalizeCandidate(
      signal["candidate"],
      signal["sdp_mid"],
      signal["sdp_mline_index"],
      signal["username_fragment"],
    );
  }
  throw new ProtocolSchemaError(
    "PeerSignal.kind",
    'must be either "description" or "candidate"',
  );
}

export function descriptionSignal(description: RTCSessionDescriptionInit): DescriptionSignal {
  return normalizeDescription(description.type, description.sdp);
}

export function candidateSignal(candidate: RTCIceCandidate | null): CandidateSignal {
  if (candidate === null) {
    return normalizeCandidate(null, null, null, null);
  }
  const value = candidate.toJSON();
  return normalizeCandidate(
    value.candidate ?? "",
    value.sdpMid ?? null,
    value.sdpMLineIndex ?? null,
    value.usernameFragment ?? null,
  );
}

export function candidateSignalInit(signal: CandidateSignal): RTCIceCandidateInit | null {
  const normalized = normalizeCandidate(
    signal.candidate,
    signal.sdpMid,
    signal.sdpMLineIndex,
    signal.usernameFragment,
  );
  if (normalized.candidate === null) {
    return null;
  }
  return {
    candidate: normalized.candidate,
    sdpMid: normalized.sdpMid,
    sdpMLineIndex: normalized.sdpMLineIndex,
    usernameFragment: normalized.usernameFragment,
  };
}

function normalizePeerSignal(signal: PeerSignal): PeerSignal {
  if (typeof signal !== "object" || signal === null) {
    throw new ProtocolSchemaError("PeerSignal", "must be an object");
  }
  if (signal.kind === "description") {
    return normalizeDescription(signal.descriptionType, signal.sdp);
  }
  if (signal.kind === "candidate") {
    return normalizeCandidate(
      signal.candidate,
      signal.sdpMid,
      signal.sdpMLineIndex,
      signal.usernameFragment,
    );
  }
  throw new ProtocolSchemaError(
    "PeerSignal.kind",
    'must be either "description" or "candidate"',
  );
}

function normalizeDescription(type: unknown, sdp: unknown): DescriptionSignal {
  if (type !== "offer" && type !== "answer") {
    throw new ProtocolSchemaError(
      "DescriptionSignal.description_type",
      'must be either "offer" or "answer"',
    );
  }
  const normalizedSdp = boundedText(
    sdp,
    "DescriptionSignal.sdp",
    MAX_SDP_BYTES,
    false,
  );
  return Object.freeze({
    kind: "description",
    descriptionType: type,
    sdp: normalizedSdp,
  });
}

function normalizeCandidate(
  candidate: unknown,
  sdpMid: unknown,
  sdpMLineIndex: unknown,
  usernameFragment: unknown,
): CandidateSignal {
  const normalizedCandidate = nullableText(
    candidate,
    "CandidateSignal.candidate",
    MAX_ICE_CANDIDATE_BYTES,
  );
  const normalizedSdpMid = nullableText(
    sdpMid,
    "CandidateSignal.sdp_mid",
    MAX_ICE_FIELD_BYTES,
  );
  const normalizedSdpMLineIndex = nullableUnsignedInteger(
    sdpMLineIndex,
    "CandidateSignal.sdp_mline_index",
  );
  const normalizedUsernameFragment = nullableText(
    usernameFragment,
    "CandidateSignal.username_fragment",
    MAX_ICE_FIELD_BYTES,
  );
  if (
    normalizedCandidate === null &&
    (normalizedSdpMid !== null ||
      normalizedSdpMLineIndex !== null ||
      normalizedUsernameFragment !== null)
  ) {
    throw new ProtocolSchemaError(
      "CandidateSignal",
      "end-of-candidates must set every candidate field to null",
    );
  }
  return Object.freeze({
    kind: "candidate",
    candidate: normalizedCandidate,
    sdpMid: normalizedSdpMid,
    sdpMLineIndex: normalizedSdpMLineIndex,
    usernameFragment: normalizedUsernameFragment,
  });
}

function nullableText(value: unknown, path: string, maximumBytes: number): string | null {
  if (value === null) {
    return null;
  }
  return boundedText(value, path, maximumBytes, true);
}

function nullableUnsignedInteger(value: unknown, path: string): number | null {
  if (value === null) {
    return null;
  }
  return expectUnsignedInteger(value as CborValue, path, MAX_SDP_M_LINE_INDEX);
}

function expectText(value: CborValue | undefined, path: string): string {
  if (typeof value !== "string") {
    throw new ProtocolSchemaError(path, "must be text");
  }
  return value;
}

function boundedText(
  value: unknown,
  path: string,
  maximumBytes: number,
  allowEmpty: boolean,
): string {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0)) {
    throw new ProtocolSchemaError(path, allowEmpty ? "must be text" : "must be non-empty text");
  }
  if (new TextEncoder().encode(value).length > maximumBytes) {
    throw new ProtocolSchemaError(path, `must contain at most ${maximumBytes} UTF-8 bytes`);
  }
  return value;
}

function encodeBoundedSignal(value: CborValue): CanonicalCbor {
  const encoded = encodeCanonical(value);
  requireEncodedSignal(encoded);
  return encoded;
}

function requireEncodedSignal(value: Uint8Array): void {
  if (!(value instanceof Uint8Array) || value.constructor !== Uint8Array) {
    throw new TypeError("Peer signaling message must be a Uint8Array");
  }
  if (value.length > MAX_SIGNALING_MESSAGE_BYTES) {
    throw new ProtocolSchemaError(
      "PeerSignal",
      `must encode to at most ${MAX_SIGNALING_MESSAGE_BYTES} bytes`,
    );
  }
}

function isMap(value: CborValue): value is Record<string, CborValue> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof Uint8Array)
  );
}
