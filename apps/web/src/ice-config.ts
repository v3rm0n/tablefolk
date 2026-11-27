import { DEFAULT_STUN_URLS } from "@p2pcards/transport";

export interface IceDeploymentConfig {
  readonly staticServers: RTCIceServer[];
  readonly credentialEndpoint: URL | null;
}

export function browserIceDeployment(baseUrl: string): IceDeploymentConfig {
  const runtime = (globalThis as { TABLEFOLK_ICE_CONFIG?: unknown }).TABLEFOLK_ICE_CONFIG;
  return parseIceDeployment(runtime ?? import.meta.env["VITE_TABLEFOLK_ICE_CONFIG"], baseUrl);
}

export function parseIceDeployment(input: unknown, baseUrl: string): IceDeploymentConfig {
  try {
    const { iceServers, credentialEndpoint: endpoint } = record(typeof input === "string" ? JSON.parse(input) : input ?? {});
    const staticServers = iceServers === undefined
      ? [{ urls: [...DEFAULT_STUN_URLS] }]
      : parseServers(iceServers);
    if (!staticServers.some(({ urls }) => (Array.isArray(urls) ? urls : [urls]).some(url => /^stuns?:/.test(url)))) throw new Error();
    let credentialEndpoint = null;
    if (endpoint !== undefined) {
      if (typeof endpoint !== "string" || !endpoint.trim()) throw new Error();
      credentialEndpoint = new URL(endpoint, baseUrl);
      const local = ["localhost", "127.0.0.1", "[::1]"].includes(credentialEndpoint.hostname);
      if ((credentialEndpoint.protocol !== "https:" && !(local && credentialEndpoint.protocol === "http:")) ||
        credentialEndpoint.username || credentialEndpoint.password || credentialEndpoint.href.includes("#") || credentialEndpoint.href.includes("?")) throw new Error();
    }
    return { staticServers, credentialEndpoint };
  } catch {
    throw new Error("Invalid deployment ICE settings. Ask the table operator to check the STUN and TURN configuration.");
  }
}

export async function loadLobbyIce(
  config: IceDeploymentConfig,
  signal: AbortSignal,
  fetchCredentials = globalThis.fetch,
): Promise<{ rtcConfiguration: RTCConfiguration; credentialWarning: boolean }> {
  const iceServers = [...config.staticServers];
  let credentialWarning = false;
  if (config.credentialEndpoint !== null) {
    const request = new AbortController();
    const abort = () => request.abort();
    signal.addEventListener("abort", abort, { once: true });
    const timeout = setTimeout(abort, 4_000);
    try {
      signal.throwIfAborted();
      const response = await fetchCredentials(config.credentialEndpoint, {
        signal: request.signal,
        cache: "no-store",
        redirect: "error",
        credentials: "same-origin",
        referrerPolicy: "no-referrer",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) throw new Error();
      const { ttlSeconds, iceServers: ephemeralServers } = record(await response.json());
      if (typeof ttlSeconds !== "number" || !Number.isSafeInteger(ttlSeconds) ||
        ttlSeconds < 30 || ttlSeconds > 86_400) throw new Error();
      iceServers.push(...parseServers(ephemeralServers, true));
    } catch {
      if (signal.aborted) throw new Error("Table connection was cancelled");
      credentialWarning = true;
    } finally {
      clearTimeout(timeout);
      signal.removeEventListener("abort", abort);
    }
  }
  signal.throwIfAborted();
  return { rtcConfiguration: { iceServers, iceTransportPolicy: "all", bundlePolicy: "max-bundle" }, credentialWarning };
}

function parseServers(input: unknown, turnOnly = false): RTCIceServer[] {
  if (!Array.isArray(input) || input.length === 0 || input.length > 8) throw new Error();
  return input.map(entry => {
    const { urls, username, credential } = record(entry);
    const values = typeof urls === "string" ? [urls] : urls;
    if (!Array.isArray(values) || values.length === 0 || values.length > 8 ||
      values.some(url => typeof url !== "string" || !validIceUrl(url))) throw new Error();
    const turn = /^turns?:/.test(values[0]);
    if (values.some(url => /^turns?:/.test(url) !== turn) || (turnOnly && !turn)) throw new Error();
    const unique = [...new Set<string>(values)];
    if (turn) {
      if (!validCredential(username) || !validCredential(credential)) throw new Error();
      return { urls: unique, username, credential };
    }
    if (username !== undefined || credential !== undefined) throw new Error();
    return { urls: unique };
  });
}

function validIceUrl(value: string): boolean {
  if (value.length > 512) return false;
  const match = /^(stuns?|turns?):(\[[\da-fA-F:.]+\]|[\da-zA-Z.-]+)(?::(\d{1,5}))?(\?transport=(?:udp|tcp))?$/.exec(value);
  if (!match || match[0] !== value || (match[4] && !match[1]?.startsWith("turn"))) return false;
  const port = match[3];
  if (port !== undefined && (Number(port) < 1 || Number(port) > 65535)) return false;
  try { return new URL(`https://${match[2]}`).hostname.length > 0; } catch { return false; }
}

function validCredential(value: unknown): value is string {
  return typeof value === "string" && value.length <= 1024 && value.trim().length > 0;
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error();
  return value as Record<string, unknown>;
}
