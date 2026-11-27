# Transport deployment and verification

Tablefolk defaults to Google and Cloudflare STUN and the pinned Trystero Nostr
relays. Each browser gathers ICE candidates using its own deployment settings
and prefers a direct path when it can make one. Peers can use different ICE
servers. Use the same Nostr relay list to give everyone a shared signaling path.

## Configure ICE and TURN

Set `VITE_TABLEFOLK_ICE_CONFIG` to a JSON object in the build environment or
in `apps/web/.env.local` before building the web app.
For runtime configuration, serve a deployment-owned script from the site's
origin and add its script tag ahead of the app module in the deployed
`index.html`. Have the script assign the object to
`globalThis.TABLEFOLK_ICE_CONFIG`. The runtime object takes precedence.

```json
{
  "iceServers": [
    { "urls": ["stun:stun.example.net:3478"] }
  ],
  "credentialEndpoint": "/api/turn-credentials"
}
```

Omit `iceServers` to keep the default STUN servers. An explicit list must
include STUN. A static TURN entry takes `urls`, `username` and `credential`.
Keep static TURN credentials in local deployment inputs outside source control.
Every client can read static credentials from the served assets, so reserve
them for deployments where that exposure is acceptable. Keep the TURN signing
secret exclusively in the issuer's server-side secret store.

The optional endpoint takes a GET and returns JSON with a remaining lifetime
in seconds and one or more TURN-only entries. The browser requests credentials
when opening a table and when a player retries a peer. Use a lifetime long
enough for the intended match and keep the credential value valid on the TURN
server for that duration. An existing connection retains the configuration it
was created with. If it drops, **Retry peer** requests a fresh credential for
the new connection.

```json
{
  "ttlSeconds": 3600,
  "iceServers": [
    {
      "urls": [
        "turn:turn.example.net:3478?transport=udp",
        "turns:turn.example.net:5349?transport=tcp"
      ],
      "username": "<issued username>",
      "credential": "<issued password>"
    }
  ]
}
```

Serve the endpoint over HTTPS and send `Cache-Control: no-store`. A
same-origin endpoint can use site cookies. For a separate origin, allow the
app origin via CORS and include the endpoint origin in the site's CSP
`connect-src` if configured. The client omits cross-origin credentials and
rejects redirects and endpoint URLs with embedded user info, queries or
fragments. Loopback HTTP is supported for local development. The client accepts
a lifetime of 30–86,400 seconds. If the endpoint fails, returns malformed data
or takes longer than four seconds, the player sees a warning and the browser
continues using static ICE servers. Apply issuance and TURN usage limits at the
deployment. TURN passwords belong only in the credential response and the
browser's WebRTC configuration. Keep them out of logs, screenshots, and test
attachments.

## Cross-browser and network verification

Run `npm run check`, then the Playwright connectivity smoke test on the installed
engines. Chromium is the default. The smoke uses a working local Nostr relay
and a second relay that rejects subscriptions. It checks saved relay settings,
relay recovery, and fallback from a stub credential issuer. Unit tests cover
the peer disconnect and selected TURN-path warnings. The full lobby test
exercises real WebRTC channels and dispatches visibility changes during a round.

```sh
npm exec playwright install chromium firefox webkit
PLAYWRIGHT_BROWSER=chromium npm run test:browser -- connectivity
PLAYWRIGHT_BROWSER=firefox npm run test:browser -- connectivity
PLAYWRIGHT_BROWSER=webkit npm run test:browser -- connectivity
```

For a deployment check, seat four players using Chrome, Firefox, and Safari on
desktop and at least one physical iOS or Android device. Run the following
scenarios against the deployed app and its live relay list. Playwright WebKit
covers an engine smoke test. Mobile Safari suspension and carrier NAT require
physical devices.

| Scenario | Verify |
| --- | --- |
| Home Wi-Fi on two separate networks | All six peer links authenticate. Start a hand and record the selected path reported on each browser. |
| Corporate or carrier network with TURN disabled | Record which links fail. Check disconnect and retry behavior where the network permits a previously authenticated link to drop. |
| Same networks with deployment TURN enabled | Seat four players and complete a hand. Where direct paths are blocked, confirm `relayed` in Network diagnostics and the visible TURN message. |
| UDP blocked with TURN over TCP/TLS available | Confirm the TURN link establishes over TCP/TLS and completes a hand. Use controlled firewall rules to isolate this path. |
| One live public Nostr relay unavailable to a browser | Leave at least one common relay reachable. Open and join the table, inspect the failed relay's diagnostic, and check that it reconnects when access returns. |
| Expired credentials or unavailable issuer | Retry the peer to request fresh credentials. Check the fallback message when issuance is disabled and verify that no credential appears in the table UI. |
| Mobile backgrounding during shuffle and during play | Switch apps or lock the screen, then return. Check the foreground guidance. If a peer disconnected, retry it and verify that the hand resumes from signed history. |

Record the browser versions, operating systems, network types, relay states,
ICE path classifications, and whether the audited hand completed. Keep the
live matrix separate from the local smoke results when recording a release.
