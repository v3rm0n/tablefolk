import { bytesToHex, hexToBytes, importEd25519PublicKey, sha256 } from "@p2pcards/crypto";
import { parseGameId, parseIdentityPublicKey, type GameId, type IdentityPublicKey } from "@p2pcards/protocol";

export interface LobbyInvitation {
  readonly gameId: GameId;
  readonly host: IdentityPublicKey;
}

export function createLobbyInvitation(baseUrl: string, gameId: GameId, host: IdentityPublicKey): string {
  const url = new URL(baseUrl);
  if (!/^https?:$/.test(url.protocol) || url.username !== "" || url.password !== "") {
    throw new Error("Invitations require an HTTP or HTTPS application URL");
  }
  const game = parseGameId(gameId);
  const identity = parseIdentityPublicKey(importEd25519PublicKey(host));
  url.search = "";
  url.hash = new URLSearchParams({
    g: bytesToHex(game), h: bytesToHex(identity), r: "sasku-first-round-candidate@1", s: "trystero-nostr",
  }).toString();
  return url.toString();
}

export function parseLobbyInvitation(input: string): LobbyInvitation {
  if (typeof input !== "string" || input.length > 4096) {
    throw new Error("Invitation is too long or is not text");
  }
  const text = input.trim();
  const url = new URL(text.startsWith("#") ? `https://invitation.invalid/${text}` : text);
  if (!/^https?:$/.test(url.protocol) || url.username !== "" || url.password !== "") {
    throw new Error("Invitation must be an HTTP or HTTPS link");
  }
  const params = new URLSearchParams(url.hash.slice(1));
  const keys = [...params.keys()];
  if (keys.length !== 4 || new Set(keys).size !== 4 || keys.some((key) => !["g", "h", "r", "s"].includes(key))) {
    throw new Error("Invitation must contain exactly g, h, r and s once each");
  }
  const game = params.get("g")!;
  const host = params.get("h")!;
  if (!/^[0-9a-f]{32}$/.test(game) || !/^[0-9a-f]{64}$/.test(host)) {
    throw new Error("Invitation contains an invalid game or host identity");
  }
  if (params.get("r") !== "sasku-first-round-candidate@1" || params.get("s") !== "trystero-nostr") {
    throw new Error("This invitation requires the Sasku first-round candidate profile over Nostr");
  }
  return Object.freeze({
    gameId: parseGameId(hexToBytes(game)),
    host: parseIdentityPublicKey(importEd25519PublicKey(hexToBytes(host))),
  });
}

export function identityFingerprint(key: Uint8Array): string {
  const bytes = sha256(importEd25519PublicKey(key)).slice(0, 16);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let buffer = 0;
  let encoded = "";
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      encoded += alphabet[(buffer >>> bits) & 31];
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits !== 0) { encoded += alphabet[(buffer << (5 - bits)) & 31]; }
  return encoded.match(/.{1,4}/g)!.join(" ");
}
