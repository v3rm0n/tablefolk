import { bytesToHex, randomBytes } from "@p2pcards/crypto";
import type { EnvelopeArtifact } from "@p2pcards/protocol";

interface Marker { kind: "prefix" | "ack"; token: string; seq: number; hash: string }
/** Ephemeral messages are scoped to one authenticated channel generation, never signed chain entries. */
export class PeerHistoryBarrier {
  readonly token = bytesToHex(randomBytes(32));
  #sent: Marker | null = null;
  #remote: Marker | null = null;
  #acked = false;
  #received = false;
  get ready(): boolean { return this.#acked && this.#received; }
  acknowledged(head: EnvelopeArtifact): boolean {
    return this.#acked && this.#sent?.seq === head.envelope.seq && this.#sent.hash === bytesToHex(head.hash);
  }
  announce(head: EnvelopeArtifact): Uint8Array {
    const hash = bytesToHex(head.hash);
    // Replaying an unchanged, already acknowledged prefix must not flicker readiness.
    if (this.#sent?.seq === head.envelope.seq && this.#sent.hash === hash) return encode(this.#sent);
    this.#sent = { kind: "prefix", token: this.token, seq: head.envelope.seq, hash };
    this.#acked = false;
    return encode(this.#sent);
  }
  receive(payload: Uint8Array): void {
    if (payload.length > 512 || payload[0] !== 0) throw new Error("Invalid history marker");
    const m: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload.subarray(1)));
    if (!m || typeof m !== "object" || Object.keys(m).sort().join() !== "hash,kind,seq,token") throw new Error("Invalid history marker");
    const value = m as Marker;
    if ((value.kind !== "prefix" && value.kind !== "ack") || !Number.isSafeInteger(value.seq) || value.seq < 0 ||
      typeof value.hash !== "string" || !/^[a-f0-9]{64}$/.test(value.hash) || typeof value.token !== "string" || !/^[a-f0-9]{64}$/.test(value.token)) throw new Error("Invalid history marker");
    if (value.kind === "ack") {
      if (this.#sent && value.token === this.token && value.seq === this.#sent.seq && value.hash === this.#sent.hash) this.#acked = true;
    } else { this.#remote = value; this.#received = false; }
  }
  acknowledge(read: (seq: number) => EnvelopeArtifact | undefined): Uint8Array | null {
    if (!this.#remote || this.#received) return null;
    const artifact = read(this.#remote.seq);
    if (!artifact) return null;
    if (bytesToHex(artifact.hash) !== this.#remote.hash) throw new Error("Peer history watermark conflicts with admitted history");
    this.#received = true;
    return encode({ ...this.#remote, kind: "ack" });
  }
}
function encode(marker: Marker): Uint8Array {
  const json = new TextEncoder().encode(JSON.stringify(marker)), bytes = new Uint8Array(json.length + 1);
  bytes.set(json, 1); return bytes;
}
