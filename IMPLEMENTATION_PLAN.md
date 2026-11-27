# Tablefolk Implementation Roadmap

This is the forward-looking roadmap for the platform specified in
[docs/spec.md](docs/spec.md). Past increments are recorded in `git log`;
accepted scope and architecture decisions live in
[docs/decisions.md](docs/decisions.md).

## Current Status

The browser application plays complete four-player Sasku matches to 12 game
points under the experimental `sasku-match-candidate@4` profile:

- **Implemented on `main`:** strict RFC 8949 deterministic CBOR
  (`@p2pcards/encoding`), SHA-256/512 and Ed25519/Ristretto255 primitives
  (`@p2pcards/crypto`), signed envelopes and per-sender hash chains
  (`@p2pcards/protocol`, `@p2pcards/session`), ElGamal masking, Schnorr PoP,
  Chaum–Pedersen DLEQ, and candidate 36-card 4×9 Bayer–Groth Rust/WASM proofs in
  Web Workers (`@p2pcards/deck`, `crates/shuffle-wasm`), encrypted Nostr
  signaling and DTLS-authenticated WebRTC full-mesh transport
  (`@p2pcards/transport`), durable IndexedDB persistence and full-replay restart
  recovery (`@p2pcards/storage`), complete Sasku rules, audit, and multi-round
  match execution (`@p2pcards/engine`, `@p2pcards/rules-sasku`,
  `@p2pcards/game-sasku`, `apps/web`), one-tab four-player local demo, scoring
  reference, technical walkthrough, Playwright four-browser WebRTC tests, and
  GitHub Pages CI/CD.
- **Current limitations on `main` (addressed by #2–#8):** shuffle remasking and
  DLEQ still run in JS on the main thread or per-call workers; envelopes are
  re-verified across internal layers and on page reload; synchronization uses
  chained `WITNESS`/`SYNC_*` and per-message `PeerHistoryBarrier` stalls; ICE is
  STUN-only without TURN; and in-browser CBOR transcript export and strict CSP
  are not yet implemented.
- **Cryptographic status:** the Bayer–Groth shuffle profile and Rust/WASM
  backend have not undergone an independent external cryptographic audit; see
  [docs/decisions.md](docs/decisions.md#2026-11-27-pragmatic-card-game-scope--re-ordered-roadmap).

## Remaining Milestones

Every milestone preserves all player-facing cryptographic guarantees (**G1–G7**
in [docs/spec.md](docs/spec.md#11-goals)) while prioritizing speed, real-world
connectivity, and simplicity.

### 1. Speed & WASM Crypto Consolidation (`#2`, `#3`, `#5`, `#6`)

- [ ] **#2 — Rust/WASM hot paths & reused crypto worker:** move shuffle
      remasking (`prepare_and_prove_candidate_shuffle36`) and batched
      Chaum–Pedersen DLEQ (`create_dleq_batch` / `verify_dleq_batch`) into
      Rust/WASM, cache CRS and `CardPointTable` derivations, and reuse a single
      persistent crypto Web Worker (zeroizing private buffers in `finally`;
      respawning only on timeout or error).
- [ ] **#3 — Single-pass boundary verification & local reload checkpoint:**
      verify envelopes once at untrusted boundaries (network ingress and storage
      load), eliminate duplicate shuffle/DLEQ re-verification and O(N²)
      history re-checks, cache the decrypted private hand per round, and store a
      trusted local IndexedDB reload checkpoint keyed by the four
      `(seat, seq, hash)` transcript heads (retaining the full signed transcript
      for peer sync and on-demand full verification).
- [ ] **#5 — Single-owner round queue:** collapse nested async round queues into
      a single-owner coordinator and remove hostile-in-process-caller defenses
      while keeping strict validation at network and storage boundaries.
- [x] **#6 — Parameterized `(m, n)` Bayer–Groth profile & crate graduation:**
      v2 supports 4×9 and 4×13 with cross-runtime checks and timings.
      `SHUFFLE` carries `{outputDeck, proof}` and peers reconstruct the
      statement. The Rust/WASM crate lives at `crates/shuffle-wasm`.
- [ ] **Soundness vectors & focused self-audit:** expand cross-runtime (native
      Rust, browser WASM, Python/TS), mutation, and soundness proof vectors and
      complete a focused self-audit of the vendored `cards-proofs` adaptation,
      secret zeroization, and RNG usage.

### 2. TURN & Ephemeral Reconnect (`#4`, `#7`)

- [ ] **#4 — Ephemeral `HEADS`/`SYNC_*` catch-up & human-triggered abort:**
      move `HEADS`, `SYNC_REQ`, and `SYNC_RESP` out of the signed per-sender
      hash chain onto ephemeral messages over the DTLS+`HELLO`-authenticated
      mesh; remove per-message `PeerHistoryBarrier` RTT stalls; support
      mid-round reconnect and relay-assisted catch-up; keep wire `VIOLATION`
      certificates strictly for `equivocation` (`[env1, env2]`); and replace
      hard automatic 60 s forfeit deadlines with a disconnected-player banner
      and optional human-triggered table abort voting.
- [ ] **#7 — TURN support, Nostr hardening & browser/mobile warnings:** support
      deployment-configured TURN credentials (including ephemeral time-limited
      credentials outside source control), harden live public Nostr relay
      failover with configurable relay lists, add actionable UI warnings for
      disconnects, TURN relay fallback, and mobile background-tab suspension,
      and validate across Chrome, Firefox, Safari, and NAT matrices.

### 3. In-Browser Transcript Export & CSP (`#8`)

- [ ] **#8 — Minimal CBOR transcript & in-browser verifier:** freeze the
      self-contained CBOR transcript container
      `{version, rules_hash, roster, envelopes}` in canonical order (omitting
      non-verifiable `HELLO` transport bindings), implement shared
      `verifyTranscript(bytes)` (rejecting unknown `rules_hash` values), and
      expose lightweight "Export transcript (.cbor)" / "Verify transcript" UI
      directly in `apps/web` (no separate Node CLI).
- [ ] **#8 — Strict CSP & boundary fuzzing:** enforce a strict static
      Content-Security-Policy (protecting the raw Ed25519 identity seed and
      `x_i` in IndexedDB) and add property/fuzz tests for malformed CBOR,
      invalid envelopes, and chain gaps at the network boundary.

### 4. Additional Games (Only When Wanted)

- [ ] Generalize draws, exchanges, reshuffles, and rules packaging only when a
      concrete second game (such as three-player 500 or 1000) supplies real
      requirements.
- [ ] Exercise three- and eight-seat meshes with synthetic rules fixtures when
      needed.

## Release Gates

Before treating Tablefolk as a release:

1. The frozen parameterized Bayer–Groth profile and Rust/WASM backend pass
   cross-runtime, mutation, and soundness test vectors plus a focused
   self-audit, accompanied by a transparent disclaimer that the cryptography has
   not undergone an independent external audit.
2. Every adversarial behavior in [docs/spec.md](docs/spec.md#14-verification-and-test-plan)
   produces deterministic rejection and identical local blame across honest
   peers (with self-certifying `[env1, env2]` wire evidence for equivocation).
3. Exported transcripts verify offline in the browser with identical state
   hashes across Chrome, Firefox, and Safari.
4. Interrupted sessions survive mid-round reconnection via ephemeral
   `HEADS`/`SYNC_*` without re-signing previously authored envelopes, and peers
   connect reliably across NAT types with TURN configured.
