import { hexToBytes } from "@p2pcards/crypto";
import { parseGameId, parseIdentityPublicKey } from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";
import { createLobbyInvitation, identityFingerprint, parseLobbyInvitation } from "./lobby-invitation";
import { connectionRulesHash, lobbyIceConfigHash, lobbyRtcConfiguration, parseRelayText } from "./lobby-config";

const GAME = parseGameId(new Uint8Array(16).fill(0x11));
const HOST = parseIdentityPublicKey(hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));

describe("browser lobby invitation profile", () => {
  it("round trips exact fragment fields while preserving the deployment path", () => {
    const url = createLobbyInvitation("https://example.test/cards/?tracking=1#old", GAME, HOST);
    expect(url).toBe(`https://example.test/cards/#g=${"11".repeat(16)}&h=${Array.from(HOST, (v) => v.toString(16).padStart(2, "0")).join("")}&r=sasku-first-round-candidate%401&s=trystero-nostr`);
    expect(parseLobbyInvitation(url)).toEqual({ gameId: GAME, host: HOST });
    expect(parseLobbyInvitation(new URL(url).hash)).toEqual({ gameId: GAME, host: HOST });
    const parsed = parseLobbyInvitation(url);
    parsed.gameId.fill(0xff); parsed.host.fill(0xff);
    expect(parseLobbyInvitation(url)).toEqual({ gameId: GAME, host: HOST });
  });

  it.each(["&g=00", "&extra=1", "&h=00", "&s=manual"])("rejects duplicate or unprofiled fields: %s", (suffix) => {
    expect(() => parseLobbyInvitation(createLobbyInvitation("https://example.test", GAME, HOST) + suffix)).toThrow();
  });
  it("rejects unsupported rules, strategies, protocols and weak identities", () => {
    const valid = createLobbyInvitation("https://example.test", GAME, HOST);
    for (const bad of [valid.replace("sasku-first-round-candidate%401", "sasku%401"), valid.replace("trystero-nostr", "manual"), valid.replace("https:", "javascript:"), valid.replace(/h=[0-9a-f]+/, `h=${"00".repeat(32)}`), "x".repeat(4097)]) {
      expect(() => parseLobbyInvitation(bad)).toThrow();
    }
  });
  it("matches the independent SHA256/base32 human fingerprint fixture", () => {
    expect(identityFingerprint(HOST)).toBe("EH7D DX5B KSRG CYTL 7BKA I36S E4");
  });
  it("binds the first-round rules bundle and ICE configuration to stable independent snapshots", () => {
    const hash = connectionRulesHash();
    expect(hash).toHaveLength(32);
    hash.fill(0xff);
    expect(connectionRulesHash()).not.toEqual(hash);
    const configuration = lobbyRtcConfiguration();
    configuration.iceServers = [];
    expect(lobbyRtcConfiguration().iceServers).toHaveLength(1);
    expect(lobbyIceConfigHash()).toHaveLength(32);
  });
  it("normalizes reviewed relay URLs and rejects secret-bearing or remote insecure URLs", () => {
    expect(parseRelayText(" ")).toBeUndefined();
    expect(parseRelayText("wss://relay.example\nwss://relay.example/\nws://127.0.0.1:1234")).toEqual(["wss://relay.example/", "ws://127.0.0.1:1234/"]);
    for (const bad of ["ws://remote.example", "https://relay.example", "wss://user:secret@relay.example", "wss://relay.example/?token=secret", "wss://relay.example/#token", Array(6).fill("wss://relay.example").join("\n")]) {
      expect(() => parseRelayText(bad)).toThrow();
    }
  });
});
