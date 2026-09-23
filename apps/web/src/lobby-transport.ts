import { bytesToHex, type Ed25519KeyPair } from "@p2pcards/crypto";
import { type GameId, type IdentityPublicKey } from "@p2pcards/protocol";
import {
  AuthenticatedPeerChannel, FullMeshTransport,
  type MeshPeerConnectionFactory, type SignalingAdapter,
} from "@p2pcards/transport";

import { lobbyRtcConfiguration } from "./lobby-config";

interface Peer {
  readonly identity: IdentityPublicKey;
  readonly generation: number;
  readonly wire: RTCDataChannel;
  readonly open: () => void;
  timer: ReturnType<typeof setTimeout> | null;
  channel: AuthenticatedPeerChannel | null;
}

export interface LobbyTransportOptions {
  readonly roomId: string;
  readonly gameId: GameId;
  readonly identity: Ed25519KeyPair;
  readonly roster: readonly IdentityPublicKey[];
  readonly signaling: SignalingAdapter;
  readonly createPeerConnection?: MeshPeerConnectionFactory;
  readonly onUnknownPeer: (remote: IdentityPublicKey) => boolean;
  readonly onAuthenticated: (remote: IdentityPublicKey, generation: number) => void;
  readonly onMessage: (remote: IdentityPublicKey, payload: Uint8Array, generation: number) => Promise<void>;
  readonly onDisconnected: (remote: IdentityPublicKey) => void;
  readonly onError: (error: Error, remote: IdentityPublicKey | null) => void;
  readonly onChange: () => void;
}

/** Authenticated browser mesh. Session readiness is owned by the application history barrier. */
export class LobbyTransport {
  readonly #mesh: FullMeshTransport;
  readonly #options: LobbyTransportOptions;
  readonly #peers = new Map<string, Peer>();
  #closed = false;

  constructor(options: LobbyTransportOptions) {
    this.#options = options;
    this.#mesh = new FullMeshTransport({
      roomId: options.roomId, self: options.identity.publicKey, roster: options.roster,
      membership: "lobby", signaling: options.signaling, rtcConfiguration: lobbyRtcConfiguration(),
      ...(options.createPeerConnection === undefined ? {} : { createPeerConnection: options.createPeerConnection }),
      onUnknownPeer: options.onUnknownPeer,
      onUnauthenticatedDataChannel: (identity, wire, generation) => {
        const key = bytesToHex(identity);
        const peer: Peer = {
          identity, wire, generation, channel: null, timer: null,
          open: () => {
            if (this.#closed || this.#peers.get(key) !== peer || peer.channel !== null) { return; }
            wire.removeEventListener("open", peer.open);
            try {
              const fingerprints = this.#mesh.dtlsFingerprints(identity);
              const channel = new AuthenticatedPeerChannel({
                channel: wire, gameId: options.gameId, secretKey: options.identity.secretKey,
                remoteIdentity: identity, localFingerprint: fingerprints.localFingerprint,
                remoteFingerprint: fingerprints.remoteFingerprint,
                maxQueuedMessages: 32,
                reassembler: { maxMessageBytes: 65536, maxPendingBytes: 262144, maxPendingGroups: 8 },
                sender: { maxPayloadBytes: 65536 },
                onAuthenticated: () => {
                  if (this.#peers.get(key) !== peer) { return; }
                  options.onAuthenticated(identity, generation);
                  options.onChange();
                },
                onMessage: (payload) => {
                  if (this.#peers.get(key) !== peer) { return; }
                  void options.onMessage(identity, payload, generation).then(() => {
                    if (this.#peers.get(key) === peer && peer.timer !== null) {
                      clearTimeout(peer.timer); peer.timer = null;
                    }
                  }).catch((cause: unknown) => this.#fail(peer, cause));
                },
                onError: (error) => this.#fail(peer, error),
              });
              peer.channel = channel;
              void channel.start().catch((cause: unknown) => this.#fail(peer, cause));
            } catch (cause) { this.#fail(peer, cause); }
          },
        };
        this.#peers.set(key, peer);
        peer.timer = setTimeout(() => this.#fail(peer, new Error("Peer connection timed out; retry or check relay/TURN settings")), 30_000);
        wire.addEventListener("open", peer.open);
        if (wire.readyState === "open") { peer.open(); }
        options.onChange();
      },
      onPeerDisconnected: (identity, generation) => {
        const key = bytesToHex(identity);
        const peer = this.#peers.get(key);
        if (peer?.generation === generation) {
          this.#peers.delete(key);
          peer.wire.removeEventListener("open", peer.open);
          if (peer.timer !== null) { clearTimeout(peer.timer); }
          const error = peer.channel?.failure;
          peer.channel?.close();
          if (error !== null && error !== undefined && !this.#closed) { options.onError(error, identity); }
        }
        if (!this.#closed) { options.onDisconnected(identity); options.onChange(); }
      },
      onError: (error, remote) => { if (!this.#closed) { options.onError(error, remote); } },
    });
  }

  get peers() { return this.#mesh.peers; }
  authenticated(remote: IdentityPublicKey): boolean { return this.#peers.get(bytesToHex(remote))?.channel?.authenticated ?? false; }
  generation(remote: IdentityPublicKey): number | undefined { return this.#peers.get(bytesToHex(remote))?.generation; }
  async start(): Promise<void> {
    await this.#mesh.start();
    await Promise.all(this.#mesh.peers.map((peer) => this.#mesh.requestNegotiation(peer.identity)));
  }
  admit(remote: IdentityPublicKey): Promise<void> { return this.#mesh.admitPeer(remote); }
  remove(remote: IdentityPublicKey): void { this.#mesh.removePeer(remote); }
  retry(remote: IdentityPublicKey): Promise<void> { return this.#mesh.reconnectPeer(remote); }
  path(remote: IdentityPublicKey) { return this.#mesh.connectionPath(remote); }

  async send(remote: IdentityPublicKey, generation: number, payload: Uint8Array): Promise<void> {
    const peer = this.#peers.get(bytesToHex(remote));
    if (this.#closed || peer?.generation !== generation || !peer.channel?.authenticated) {
      throw new Error("Lobby connection was replaced or is not authenticated");
    }
    if (payload.length > 65536) { throw new Error("Envelope exceeds 64 KiB"); }
    await peer.channel.send(payload);
  }

  #fail(peer: Peer, cause: unknown): void {
    if (this.#closed || this.#peers.get(bytesToHex(peer.identity)) !== peer) { return; }
    const error = cause instanceof Error ? cause : new Error("Lobby peer failed");
    this.#options.onError(error, peer.identity);
    this.#mesh.disconnectPeer(peer.identity, peer.generation);
  }

  async close(): Promise<void> {
    if (this.#closed) { return; }
    this.#closed = true;
    await this.#mesh.close();
  }
}
