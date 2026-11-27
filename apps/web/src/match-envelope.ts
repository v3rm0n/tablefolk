import { decodeAndVerifyEnvelope, type EnvelopeArtifact } from "@p2pcards/protocol";

export function isLobbyEnvelope({ envelope }: EnvelopeArtifact): boolean {
  return envelope.type === "JOIN" || envelope.type === "ROSTER" || envelope.type === "READY";
}

export function decodeMatchEnvelope(bytes: Uint8Array): EnvelopeArtifact {
  if (bytes.length > 64 * 1024) throw new Error("Envelope exceeds 64 KiB");
  const artifact = decodeAndVerifyEnvelope(bytes);
  if (isLobbyEnvelope(artifact) && bytes.length > 4 * 1024) throw new Error("Lobby envelope exceeds 4 KiB");
  return artifact;
}
