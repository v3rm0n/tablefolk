import type { LiveRoundView } from "./live-round";
import type { BrowserLobbySnapshot } from "./lobby-types";

export function connectionWarnings({ peers, relays }: Pick<BrowserLobbySnapshot, "peers" | "relays">) {
  return {
    disconnected: peers.filter(peer => peer.state === "disconnected" || peer.state === "failed"),
    relayed: peers.some(peer => peer.state === "authenticated" && peer.path === "relayed"),
    relayOutage: relays.length > 0 && relays.every(relay => relay.error !== null && relay.state !== "connected"),
  };
}

type RoundTabVisibility = "visible" | "hidden" | "resumed";

export function observeRoundVisibility(
  tab: Pick<Document, "visibilityState" | "addEventListener" | "removeEventListener">,
  changed: (visibility: RoundTabVisibility) => void,
): () => void {
  let wasHidden = false;
  const update = () => {
    if (tab.visibilityState === "hidden") {
      wasHidden = true;
      changed("hidden");
    } else if (wasHidden) {
      changed("resumed");
    }
  };
  tab.addEventListener("visibilitychange", update);
  update();
  return () => tab.removeEventListener("visibilitychange", update);
}

export function backgroundWarning(phase: LiveRoundView["phase"], visibility: RoundTabVisibility): string | null {
  if (phase === "complete" || phase === "match_complete") return null;
  if (visibility === "hidden") return "Bring this tab to the foreground. Your browser may pause the round while this tab is hidden.";
  if (visibility === "resumed") return "This tab was in the background. Keep it open and your screen awake. If play stalls, retry the disconnected peers.";
  if (phase === "setup" || phase === "shuffle" || phase === "dealing" || phase === "audit") {
    return "Keep this tab open and your screen awake while the table processes the hand.";
  }
  return null;
}
