import { encodeCanonical } from "@p2pcards/encoding";
import { ProtocolSchemaError } from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";

import {
  candidateSignal,
  candidateSignalInit,
  decodePeerSignal,
  descriptionSignal,
  encodePeerSignal,
  MAX_SDP_BYTES,
  MAX_SIGNALING_MESSAGE_BYTES,
} from "./signaling-message";

describe("peer signaling messages", () => {
  it("fixes the canonical SDP-description encoding", () => {
    const encoded = encodePeerSignal({
      kind: "description",
      descriptionType: "offer",
      sdp: "v=0\r\n",
    });

    expect(toHex(encoded)).toBe(
      "a36373647065763d300d0a646b696e646b6465736372697074696f6e" +
        "706465736372697074696f6e5f74797065656f66666572",
    );
    expect(decodePeerSignal(encoded)).toEqual({
      kind: "description",
      descriptionType: "offer",
      sdp: "v=0\r\n",
    });
  });

  it("round-trips ICE candidates and the null end-of-candidates marker", () => {
    const signal = {
      kind: "candidate" as const,
      candidate: "candidate:1 1 UDP 1 192.0.2.1 5000 typ host",
      sdpMid: "0",
      sdpMLineIndex: 1,
      usernameFragment: "abcd",
    };

    expect(decodePeerSignal(encodePeerSignal(signal))).toEqual(signal);
    expect(candidateSignalInit(signal)).toEqual({
      candidate: signal.candidate,
      sdpMid: "0",
      sdpMLineIndex: 1,
      usernameFragment: "abcd",
    });
    expect(candidateSignal(null)).toEqual({
      kind: "candidate",
      candidate: null,
      sdpMid: null,
      sdpMLineIndex: null,
      usernameFragment: null,
    });
    expect(candidateSignalInit(candidateSignal(null))).toBeNull();
  });

  it("snapshots browser descriptions and candidate JSON", () => {
    const browserCandidate = {
      toJSON: () => ({
        candidate: "candidate:2",
        sdpMid: "data",
        sdpMLineIndex: 0,
      }),
    } as RTCIceCandidate;

    expect(descriptionSignal({ type: "answer", sdp: "answer-sdp" })).toEqual({
      kind: "description",
      descriptionType: "answer",
      sdp: "answer-sdp",
    });
    expect(candidateSignal(browserCandidate)).toEqual({
      kind: "candidate",
      candidate: "candidate:2",
      sdpMid: "data",
      sdpMLineIndex: 0,
      usernameFragment: null,
    });
  });

  it("rejects extensions, unsupported descriptions, and malformed candidates", () => {
    expect(() =>
      decodePeerSignal(
        encodeCanonical({
          kind: "description",
          description_type: "offer",
          sdp: "v=0",
          extra: true,
        }),
      ),
    ).toThrow(ProtocolSchemaError);
    expect(() =>
      descriptionSignal({ type: "rollback", sdp: "rollback" }),
    ).toThrow(/offer.*answer/);
    expect(() =>
      encodePeerSignal({
        kind: "candidate",
        candidate: null,
        sdpMid: "0",
        sdpMLineIndex: null,
        usernameFragment: null,
      }),
    ).toThrow(/every candidate field to null/);
    expect(() =>
      decodePeerSignal(
        encodeCanonical({
          kind: "candidate",
          candidate: "candidate:1",
          sdp_mid: null,
          sdp_mline_index: 65_536,
          username_fragment: null,
        }),
      ),
    ).toThrow(/65535/);
    expect(() =>
      encodePeerSignal({
        kind: "description",
        descriptionType: "offer",
        sdp: "x".repeat(MAX_SDP_BYTES + 1),
      }),
    ).toThrow(/at most/);
    expect(() => decodePeerSignal(new Uint8Array(MAX_SIGNALING_MESSAGE_BYTES + 1))).toThrow(
      /encode to at most/,
    );
  });
});

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
