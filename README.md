# Tablefolk

Good company, good cards. A browser-based, peer-to-peer platform for
multiplayer card games with no game server, starting with four-player
**Sasku**. Three-player games such as 500 and 1000 are planned.

[Play Tablefolk](https://cards.maido.io/) · [GitHub](https://github.com/v3rm0n/tablefolk)

> **Status:** Plays complete four-player Sasku matches to 12 game points
> (`sasku-match-candidate@3`) with DTLS-authenticated WebRTC, Rust/WASM
> Bayer–Groth shuffle proofs, private dealing, audited scoring, dealer
> rotation, and reload recovery. **Disclaimer: the cryptography is self-audited
> and has not undergone an independent external audit.** WASM crypto
> consolidation, ephemeral reconnect, in-browser transcript
> export, and strict CSP remain follow-up work (see
> [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)).

## Requirements

- Node.js `^22.12.0` or `>=24.0.0` with npm workspaces
- Rust toolchain `1.90.0` (`wasm32-unknown-unknown` target) and
  `wasm-bindgen-cli` `0.2.100` to build the local shuffle WASM backend on a
  fresh checkout
- A modern browser with WebRTC, Web Crypto, IndexedDB, and Web Locks served
  over HTTPS or `localhost`

## Quickstart

```sh
npm install

# Fresh checkout: build the candidate Rust/WASM shuffle backend once
# (see experiments/shuffle-backend/README.md for details)
cd experiments/shuffle-backend
cargo build --release --locked --features candidate-transcript --lib --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/release/shuffle_backend_evaluation.wasm --target web --out-dir pkg-transcript
cd ../..

npm run dev    # stages WASM and starts the Vite dev server
npm run check  # workspace typechecks, unit/integration tests, and production build
```

## Playing & Local Tools

- **Live four-player table:** Run `npm run dev` (or visit
  [cards.maido.io](https://cards.maido.io/)), choose **Start a game**, and
  share the invitation link with three other devices or isolated browser
  profiles. Guests open or paste the link and choose **Join this table**.
  Players are ready by default (and may toggle **Not ready** while waiting);
  once all four seats are ready, the table deals automatically and continues
  audited hands until one partnership reaches 12 P (capped at 32 hands).
- **Four-player demo (`demo.html`):** Choose **Four-player demo** on the
  landing page to run four isolated local seats in one tab without WebRTC or
  public relays. Use the seat tabs or **Automatically switch to active player**
  to play all four hands, or **New demo table** to restart.
- **Scoring reference (`scoring.html`):** Try completed-hand totals, named
  trumps, *pokk*, *karvane*, and pass-round scoring using `@p2pcards/rules-sasku`.
- **How it works (`how-it-works.html`):** Visual walkthrough of Nostr
  signaling, WebRTC channel auth, joint shuffling, private dealing, and audits.

### Networking & identity notes

- Blank relay settings use the pinned Trystero Nostr defaults. Use **Connection
  settings** to save a custom list on this browser. All four players should use
  the same list so they have a shared relay.
- Deployments can add TURN for strict NATs or firewalls. All four players must
  stay online, and mobile players should keep the table tab in the foreground.
  See the [transport deployment and verification guide](docs/transport-deployment.md).
- Browser identities store a raw 32-byte Ed25519 seed in IndexedDB (protected
  by strict CSP; see [docs/decisions.md](docs/decisions.md)). Clearing site data
  loses that identity; Web Locks prevent two tabs with the same identity from
  writing the same table.

## Browser Tests

```sh
npm exec playwright install chromium
npm run test:browser
```

Set `PLAYWRIGHT_EXECUTABLE_PATH` to use an installed Chromium-family browser,
`PLAYWRIGHT_PRODUCTION=1` to test the built bundle after `npm run build`, and
`PLAYWRIGHT_OUTPUT_DIR` to move screenshots/diagnostics from
`test-results/browser`. Use `PLAYWRIGHT_BROWSER=firefox` or
`PLAYWRIGHT_BROWSER=webkit` to select another installed Playwright engine,
and `PLAYWRIGHT_PORT` to override the local test server port. Browser tests
use real WebRTC and local Nostr-compatible relay fixtures.

## Documentation

| Document | Contents |
| --- | --- |
| [RULES.md](RULES.md) | Sasku game rules and scoring tables |
| [docs/spec.md](docs/spec.md) | Original platform architecture and threat model (v0.1 draft) |
| [docs/decisions.md](docs/decisions.md) | Accepted architecture and scope decisions (ADRs) |
| [docs/protocol.md](docs/protocol.md) | Normative CBOR, envelope, signaling, transport, and storage profile |
| [docs/shuffle.md](docs/shuffle.md) | Candidate 36-card Bayer–Groth CRS, proof codec, transcript, and API |
| [docs/sasku.md](docs/sasku.md) | Active `sasku-match-candidate@3` profile, ownership, and recovery |
| [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) | Remaining milestones and release gates |
| [experiments/shuffle-backend/README.md](experiments/shuffle-backend/README.md) | Building, staging, and testing the Rust/WASM shuffle backend |

## Workspaces

- `apps/web` — React/Vite browser app (live Sasku match, one-tab demo, scoring
  reference, walkthrough)
- `packages/encoding` — strict RFC 8949 Core Deterministic CBOR codec
- `packages/crypto` — SHA-256/512, injectable CSPRNG, Ed25519, Ristretto255
- `packages/protocol` — fixed wire fields, domain separators, signed envelopes,
  `HELLO` artifacts
- `packages/session` — sender chains, lobby/session recovery, witnesses,
  bounded sync planning/receipt, authored-history replay
- `packages/deck` — card-point derivation, ElGamal masking, Schnorr/DLEQ
  proofs, candidate shuffle CRS/codec/transcript/statement codecs
- `packages/engine` — durable setup coordination, commit/reveal beacon,
  shuffle ledger, private-deal/reveal ledger
- `packages/rules-sasku` — canonical `sasku-36/v1` deck, auction,
  effective-suit following, public/reference controllers, audit, scoring
- `packages/game-sasku` — durable Sasku round receiver, exclusive phase owner,
  owner-coordinated sync, bounded prerequisite inbox
- `packages/storage` — IndexedDB persistence (`identity`, `games`,
  `transcripts`, `authored_heads`)
- `packages/transport` — room-encrypted Nostr signaling adapter, full-mesh
  perfect negotiation, DTLS `HELLO` authentication, 16 KiB framing, readiness
  gate

## Deployment

Pushes to `main` run [.github/workflows/pages.yml](.github/workflows/pages.yml),
which runs sharded unit tests, typechecks, verifies the vendored proof
manifest, compiles the pinned Rust/WASM shuffle backend, builds `apps/web/dist`
with relative paths (`./`), and deploys statically to GitHub Pages at
[https://cards.maido.io/](https://cards.maido.io/). No application server or
deployment secrets are required.
