import { sha256 } from "@p2pcards/crypto";
import { encodeCanonical } from "@p2pcards/encoding";
import { parseHash256, type Hash256 } from "@p2pcards/protocol";
import { DEFAULT_STUN_URLS } from "@p2pcards/transport";

import { liveRulesHash } from "./live-profile";

export const CONNECTION_RULES = Object.freeze({ id: "sasku-first-round-candidate", version: "1", players: 4, label: "Sasku first round" });

export function connectionRulesHash(): Hash256 {
  return liveRulesHash();
}

export function lobbyRtcConfiguration(): RTCConfiguration {
  return { iceServers: [{ urls: [...DEFAULT_STUN_URLS] }], iceTransportPolicy: "all", bundlePolicy: "max-bundle" };
}

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
    if (line.length > 2048) { throw new Error("Relay URL is too long"); }
    const url = new URL(line);
    const local = url.protocol === "ws:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if ((url.protocol !== "wss:" && !local) || url.username || url.password || url.search || url.hash) {
      throw new Error("Use wss relay URLs without credentials, query or fragment; ws is allowed only on localhost");
    }
    return url.toString();
  });
  return Object.freeze([...new Set(urls)]);
}
