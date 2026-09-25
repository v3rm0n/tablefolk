import { generateEd25519KeyPair } from "@p2pcards/crypto";
import { parseGameId, parseIdentityPublicKey } from "@p2pcards/protocol";
import { describe, expect, it, vi } from "vitest";

import { LocalDemoTransportNetwork } from "./local-demo-transport";

describe("local demo transport", () => {
  it("connects isolated seats, copies messages, and reconnects an admitted player", async () => {
    const network = new LocalDemoTransportNetwork();
    const host = generateEd25519KeyPair(), guest = generateEd25519KeyPair();
    const hostId = parseIdentityPublicKey(host.publicKey), guestId = parseIdentityPublicKey(guest.publicKey);
    const gameId = parseGameId(new Uint8Array(16));
    const onUnknownPeer = vi.fn(() => true);
    const messages: number[][] = [];
    const callbacks = {
      onAuthenticated: () => undefined,
      onDisconnected: () => undefined,
      onError: (error: Error) => { throw error; },
      onChange: () => undefined,
    };
    const hostTransport = network.createTransport({ roomId: "demo", gameId, identity: host, roster: [hostId], onUnknownPeer,
      onMessage: async (_remote, payload) => { messages.push([...payload]); }, ...callbacks });
    const guestTransport = network.createTransport({ roomId: "demo", gameId, identity: guest, roster: [guestId, hostId],
      onUnknownPeer: () => false, onMessage: async () => undefined, ...callbacks });

    await hostTransport.start();
    await guestTransport.start();
    await Promise.resolve();
    expect(hostTransport.authenticated(guestId)).toBe(true);
    expect(guestTransport.authenticated(hostId)).toBe(true);

    const firstGeneration = guestTransport.generation(hostId)!;
    const payload = Uint8Array.of(1, 2, 3);
    await guestTransport.send(hostId, firstGeneration, payload);
    payload[1] = 9;
    await Promise.resolve();
    expect(messages).toEqual([[1, 2, 3]]);

    onUnknownPeer.mockReturnValue(false);
    await guestTransport.retry(hostId);
    await Promise.resolve();
    expect(guestTransport.generation(hostId)).toBeGreaterThan(firstGeneration);
    expect(hostTransport.authenticated(guestId)).toBe(true);
    expect(onUnknownPeer).toHaveBeenCalledTimes(1);

    await guestTransport.close();
    expect(hostTransport.peers).toHaveLength(0);
    await hostTransport.close();
  });
});
