import { sha256 } from "@p2pcards/crypto";
import { encodeCanonical } from "@p2pcards/encoding";
import { parseHash256, type Hash256 } from "@p2pcards/protocol";
import { DEFAULT_STUN_URLS } from "@p2pcards/transport";

import { liveRulesHash } from "./live-profile";

export const CONNECTION_RULES = Object.freeze({ id: "sasku-match-candidate", version: "4", players: 4, label: "Sasku match" });

export function connectionRulesHash(): Hash256 {
  return liveRulesHash();
}

// Keep the signed browser profile stable across deployments and rotating TURN credentials.
export function lobbyIceConfigHash(): Hash256 {
  return parseHash256(sha256(encodeCanonical({
    iceServers: [{ urls: [...DEFAULT_STUN_URLS] }], iceTransportPolicy: "all", bundlePolicy: "max-bundle",
  })));
}

export function parseRelayText(text: string): readonly string[] | undefined {
  if (typeof text !== "string" || text.length > 10_240) { throw new Error("Relay configuration is too long"); }
  if (text.trim() === "") { return undefined; }
  const lines = text.trim().split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.length > 5) { throw new Error("Use at most five relay URLs, one per line"); }
  const urls = lines.map((line) => {
    if (new TextEncoder().encode(line).length > 2048) { throw new Error("Relay URL is too long"); }
    let url: URL;
    try { url = new URL(line); } catch { throw new Error("Enter a valid relay URL on each line"); }
    const local = url.protocol === "ws:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if ((url.protocol !== "wss:" && !local) || url.username || url.password || url.href.includes("?") || url.href.includes("#")) {
      throw new Error("Use wss relay URLs without credentials, query or fragment; ws is allowed only on localhost");
    }
    if (url.href.length > 2048) { throw new Error("Relay URL is too long"); }
    return url.href;
  });
  return Object.freeze([...new Set(urls)]);
}

const RELAY_STORAGE_KEY = "tablefolk.nostr-relays";

export function readRelayPreference(): string {
  try {
    const saved = window.localStorage.getItem(RELAY_STORAGE_KEY) ?? "";
    return parseRelayText(saved)?.join("\n") ?? "";
  } catch {
    return "";
  }
}

export function saveRelayPreference(urls: readonly string[] | undefined): boolean {
  try {
    if (urls === undefined) window.localStorage.removeItem(RELAY_STORAGE_KEY);
    else window.localStorage.setItem(RELAY_STORAGE_KEY, urls.join("\n"));
    return true;
  } catch {
    return false;
  }
}
