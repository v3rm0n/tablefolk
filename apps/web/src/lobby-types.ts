import type { LiveRoundView } from "./live-round";
import type { SaskuActionIntent } from "@p2pcards/game-sasku";
export interface LobbySeatView {
  readonly publicKey: string;
  readonly fingerprint: string;
  readonly isSelf: boolean;
  readonly isHost: boolean;
  readonly ready: boolean;
  readonly connected: boolean;
}

export interface LobbyPeerView {
  readonly publicKey: string;
  readonly fingerprint: string;
  readonly state: "connecting" | "authenticated" | "disconnected" | "failed";
  readonly generation: number;
  readonly path: "direct" | "relayed" | "unknown";
}

export interface BrowserLobbySnapshot {
  readonly game?: LiveRoundView | null;
  readonly phase: "loading" | "welcome" | "connecting" | "lobby" | "agreed";
  readonly identity: { readonly publicKey: string; readonly fingerprint: string } | null;
  readonly pendingInvitation: string;
  readonly room: {
    readonly gameId: string;
    readonly host: string;
    readonly isHost: boolean;
    readonly invitation: string;
    readonly seats: readonly LobbySeatView[];
    readonly rosterHash: string | null;
    readonly canReady: boolean;
    readonly ownReady: boolean;
  } | null;
  readonly peers: readonly LobbyPeerView[];
  readonly relays: readonly { readonly url: string; readonly state: string; readonly error: string | null }[];
  readonly busy: "identity" | "hosting" | "joining" | "ready" | "leaving" | null;
  readonly error: string | null;
  readonly events: readonly string[];
}

export interface BrowserLobbyActions {
  readonly getSnapshot: () => BrowserLobbySnapshot;
  readonly subscribe: (listener: () => void) => () => void;
  create(relayText?: string): Promise<void>;
  join(invitation: string, relayText?: string): Promise<void>;
  markReady(): Promise<void>;
  setReady(ready: boolean): Promise<void>;
  playAction?(intent: SaskuActionIntent): Promise<void>;
  retryPeer(publicKey: string): Promise<void>;
  leave(): Promise<void>;
}
