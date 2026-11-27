import { expect, it, vi } from "vitest";
import { backgroundWarning, connectionWarnings, observeRoundVisibility } from "./connection-warnings";
import type { LobbyPeerView } from "./lobby-types";

const peer = { publicKey: "peer", fingerprint: "PEER", generation: 1 } as const;

it("offers retry for disconnected peers and warns only for active TURN paths", () => {
  const previousRelay: LobbyPeerView = { ...peer, state: "disconnected", path: "relayed" };
  const connecting: LobbyPeerView = { ...peer, state: "connecting", path: "unknown" };
  const activeRelay: LobbyPeerView = { ...peer, state: "authenticated", path: "relayed" };
  const direct: LobbyPeerView = { ...activeRelay, path: "direct" };
  expect(connectionWarnings({ peers: [previousRelay, connecting, direct], relays: [] })).toMatchObject({
    disconnected: [previousRelay], relayed: false,
  });
  expect(connectionWarnings({ peers: [activeRelay], relays: [] })).toMatchObject({ disconnected: [], relayed: true });
});

it("warns about a total relay outage and clears the warning when any relay recovers", () => {
  const failed = { url: "wss://relay.example", state: "failed", error: "Timed out subscribing" };
  const connected = { url: "wss://other.example", state: "connected", error: null };
  expect(connectionWarnings({ peers: [], relays: [failed] }).relayOutage).toBe(true);
  expect(connectionWarnings({ peers: [], relays: [failed, connected] }).relayOutage).toBe(false);
});

it("tracks visibility changes and offers return guidance during active rounds only", () => {
  const tab = Object.assign(new EventTarget(), { visibilityState: "visible" as DocumentVisibilityState });
  const changed = vi.fn();
  const stop = observeRoundVisibility(tab, changed);
  expect(changed).not.toHaveBeenCalled();
  expect(backgroundWarning("shuffle", "visible")).toMatch(/Keep this tab open/);
  tab.visibilityState = "hidden";
  tab.dispatchEvent(new Event("visibilitychange"));
  expect(changed).toHaveBeenLastCalledWith("hidden");
  expect(backgroundWarning("playing", "hidden")).toMatch(/foreground/);
  tab.visibilityState = "visible";
  tab.dispatchEvent(new Event("visibilitychange"));
  expect(changed).toHaveBeenLastCalledWith("resumed");
  expect(backgroundWarning("audit", "resumed")).toMatch(/was in the background/);
  expect(backgroundWarning("complete", "resumed")).toBeNull();
  expect(backgroundWarning("match_complete", "hidden")).toBeNull();
  stop();
  tab.dispatchEvent(new Event("visibilitychange"));
  expect(changed).toHaveBeenCalledTimes(2);
});
