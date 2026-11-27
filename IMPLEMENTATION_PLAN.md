# Tablefolk Implementation Roadmap

This is the forward-looking roadmap for the platform specified in
[docs/spec.md](docs/spec.md). Past increments are recorded in `git log`;
accepted scope and architecture decisions live in
[docs/decisions.md](docs/decisions.md).

## Current Status

The browser application plays complete four-player Sasku matches to 12 game
points under the experimental `sasku-match-candidate@3` profile:

- **Implemented:** strict RFC 8949 deterministic CBOR (`@p2pcards/encoding`),
  SHA-256/512 and Ed25519/Ristretto255 primitives (`@p2pcards/crypto`),
  signed envelopes and per-sender hash chains (`@p2pcards/protocol`,
  `@p2pcards/session`), ElGamal masking, Schnorr PoP, Chaum–Pedersen DLEQ, and
  candidate 36-card 4×9 Bayer–Groth Rust/WASM proofs in Web Workers
  (`@p2pcards/deck`, `experiments/shuffle-backend`), encrypted Nostr signaling
  and DTLS-authenticated WebRTC full-mesh transport (`@p2pcards/transport`),
  durable IndexedDB persistence and restart recovery (`@p2pcards/storage`),
  complete Sasku rules, audit, and multi-round match execution
  (`@p2pcards/engine`, `@p2pcards/rules-sasku`, `@p2pcards/game-sasku`,
  `apps/web`), one-tab four-player local demo, scoring reference, technical
  walkthrough, Playwright four-browser WebRTC tests, and GitHub Pages CI/CD.
- **Not yet production-reviewed:** the candidate Bayer–Groth shuffle profile
  and Rust/WASM backend have not undergone independent cryptographic review.

## Remaining Milestones

### 1. Cryptographic Profile Freeze & Independent Review

- [ ] Freeze the production Bayer–Groth profile (matrix layouts beyond 4×9 as
      needed, CRS derivation, SHA-512/CBOR transcript, proof codec, and
      statement admission).
- [ ] Generate implementation-independent positive and rejection proof vectors
      across native Rust, browser WASM, and a separate reference.
- [ ] Audit the attributed `vendor/cards-proofs` adaptation, secret-dependent
      operations, memory handling, and RNG usage.
- [ ] Complete independent cryptographic review before making a public security
      claim.
- [ ] Benchmark 36-, 52-, and 128-card decks on representative desktop and
      mobile hardware.

### 2. General Synchronization, Reconnect & Fault Handling

- [ ] Profile and implement the automatic `SYNC_REQ` / `SYNC_RESP` reconnect
      controller (complete head discovery, completion/watermark agreement,
      chained-control gap handling, response correlation, and bounded paging)
      to replace the current all-four-online prefix/ack barrier.
- [ ] Implement deterministic violation certificates beyond `equivocation`
      (bad proof, unscheduled share, illegal action, audit violation).
- [ ] Profile and implement `TIMEOUT_VOTE` deadlines and late-message handling,
      narrowing blame claims that cannot be proven under a hostile network.
- [ ] Add actionable UI warnings for disconnects, TURN fallback, timeouts, and
      mobile background tab suspension.

### 3. Offline Verifier & Transcript Export

- [ ] Freeze the self-contained CBOR transcript container (including `HELLO`,
      `ROSTER`, canonical envelope ordering, rules hash, and `transcript_hash`).
- [ ] Implement transcript export in the browser and a network-free verifier
      (shared core for Node CLI and browser import) that reproduces either the
      match result or the first deterministic violation.
- [ ] Reject unknown rules hashes rather than executing downloaded code.

### 4. Storage, Transport & Cross-Browser Hardening

- [ ] Add WebCrypto non-extractable Ed25519 identity storage where supported
      (keeping the existing IndexedDB raw-seed store as fallback).
- [ ] Support deployment-configured TURN credentials (outside source control)
      and validate direct/relayed/reconnect matrices across NAT types.
- [ ] Validate against live public Nostr relays and compare replay state hashes
      across Chrome, Firefox, and Safari (desktop and representative mobile).
- [ ] Harden static build CSP, dependency audit, accessibility, and fuzzing for
      malformed CBOR, chain gaps, and conflicting envelopes.

### 5. Additional Games (Post-Review)

- [ ] Generalize draws, exchanges, reshuffles, and rules packaging only when a
      concrete second game (such as three-player 500 or 1000) supplies real
      requirements.
- [ ] Exercise three- and eight-seat meshes with synthetic rules fixtures.

## Release Gates

Before treating Tablefolk as a reviewed release:

1. The frozen shuffle profile and implementation pass independent cryptographic
   review with independent test vectors.
2. Every adversarial behavior in [docs/spec.md](docs/spec.md#14-verification-and-test-plan)
   produces deterministic rejection and identical blame across honest peers.
3. Exported transcripts verify offline with identical state hashes across
   Chrome, Firefox, and Safari.
4. Interrupted sessions survive mid-round reconnection within active deadlines
   without re-signing previously authored envelopes.
