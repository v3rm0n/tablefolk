import { DEFAULT_STUN_URLS } from "@p2pcards/transport";
import { afterEach, expect, it, vi } from "vitest";
import { browserIceDeployment, loadLobbyIce, parseIceDeployment } from "./ice-config";

const BASE = "https://cards.example/table/";
const TURN = { urls: ["turn:turn.example:3478?transport=udp", "turns:turn.example:5349?transport=tcp"],
  username: "temporary-user", credential: "temporary-password" };

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

it("supports the default STUN profile, build JSON and a runtime override", () => {
  expect(parseIceDeployment(undefined, BASE).staticServers).toEqual([{ urls: DEFAULT_STUN_URLS }]);
  vi.stubEnv("VITE_TABLEFOLK_ICE_CONFIG", JSON.stringify({ iceServers: [{ urls: "stun:stun.example" }, TURN] }));
  expect(browserIceDeployment(BASE).staticServers).toEqual([{ urls: ["stun:stun.example"] }, TURN]);
  vi.stubGlobal("TABLEFOLK_ICE_CONFIG", { credentialEndpoint: "./turn-credentials" });
  expect(browserIceDeployment(BASE)).toEqual({
    staticServers: [{ urls: DEFAULT_STUN_URLS }],
    credentialEndpoint: new URL("https://cards.example/table/turn-credentials"),
  });
});

it.each([
  "{temporary-password",
  { iceServers: [TURN] },
  { iceServers: [{ urls: "stun:stun.example?transport=udp" }] },
  { iceServers: [{ urls: ["stun:stun.example", "turn:turn.example:65536"] }] },
  { iceServers: [{ urls: "stun:stun.example" }, { ...TURN, credential: "" }] },
  { credentialEndpoint: "http://turn.example/credentials" },
  { credentialEndpoint: "https://turn.example/credentials?token=temporary-password" },
  { credentialEndpoint: "https://user:temporary-password@turn.example/credentials" },
])("rejects malformed deployment settings without including the supplied values", value => {
  expect(() => parseIceDeployment(value, BASE)).toThrow(/^Invalid deployment ICE settings\./);
  try { parseIceDeployment(value, BASE); } catch (error) {
    expect(String(error)).not.toContain("temporary-password");
  }
});

it("fetches short-lived TURN credentials and adds them only to the WebRTC configuration", async () => {
  const endpoint = parseIceDeployment({ credentialEndpoint: "/credentials" }, BASE);
  const request = vi.fn(async () => Response.json({ ttlSeconds: 600, iceServers: [TURN] }));
  const { rtcConfiguration, credentialWarning } = await loadLobbyIce(endpoint, new AbortController().signal, request);
  expect(rtcConfiguration).toEqual({
    iceServers: [{ urls: DEFAULT_STUN_URLS }, TURN],
    iceTransportPolicy: "all", bundlePolicy: "max-bundle",
  });
  expect(credentialWarning).toBe(false);
  expect(request).toHaveBeenCalledWith(new URL("/credentials", BASE), expect.objectContaining({
    cache: "no-store", redirect: "error", referrerPolicy: "no-referrer", credentials: "same-origin",
  }));
});

it.each([
  () => Response.json({ error: TURN.credential }, { status: 503 }),
  () => Response.json({ ttlSeconds: 0, iceServers: [TURN] }),
  () => Response.json({ ttlSeconds: 600, iceServers: [{ urls: "stun:stun.example" }] }),
  () => { throw new Error(TURN.credential); },
])("falls back to static ICE for unavailable or invalid credential responses", async createResponse => {
  const config = parseIceDeployment({ credentialEndpoint: "/credentials" }, BASE);
  const result = await loadLobbyIce(config, new AbortController().signal, async () => createResponse());
  expect(result.credentialWarning).toBe(true);
  expect(result.rtcConfiguration.iceServers).toEqual([{ urls: DEFAULT_STUN_URLS }]);
  expect(JSON.stringify(result)).not.toContain(TURN.credential);
});

it("cancels a credential request when the room closes and falls back on request timeout", async () => {
  vi.useFakeTimers();
  const config = parseIceDeployment({ credentialEndpoint: "/credentials" }, BASE);
  const request: typeof fetch = (_input, init) => new Promise((_resolve, reject) => {
    init?.signal?.addEventListener("abort", () => reject(new Error(TURN.credential)), { once: true });
  });
  const room = new AbortController();
  const cancelled = expect(loadLobbyIce(config, room.signal, request)).rejects.toThrow(/cancelled/);
  room.abort();
  await cancelled;
  const timedOut = loadLobbyIce(config, new AbortController().signal, request);
  await vi.advanceTimersByTimeAsync(4_000);
  expect(await timedOut).toMatchObject({ credentialWarning: true });
});
