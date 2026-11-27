# Architecture and Delivery Decisions

## 2026-09-17: Preserve Security, Narrow the First Playable Milestone

Status: **Accepted** following the architecture/scope discussion.

These decisions revise delivery scope and sequencing in the implementation plan.
They do not change signed wire formats or authorize weaker cryptographic checks.

### D1 — Keep the Untrusted-Peer Security Model Explicit

Keep authenticated peers, canonical signed history, conflicting-history detection,
verified shuffling and private dealing, deterministic rules, and bounded processing.
Public progression and hidden-hand legality remain distinct: some hidden-rule
violations are established only by the prescribed proof or later disclosure/audit.

The model assumes a trustworthy local client/device, working CSPRNG, appropriate
cryptographic assumptions, and at least one honest shuffle participant. It does not
promise completion against a peer withholding messages/shares, prevent voluntary
out-of-band hand sharing, or prove malicious intent from a network interruption.
Shuffle fairness does not supply abort resistance.

### D2 — Complete One Verifiable Live Sasku Hand Before Broadening the Platform

Prioritize the Bayer-Groth implementation/profile and review path, then integrate
one four-peer hand through setup, sequential verified shuffles, private dealing,
legal play, and audited scoring. Preserve the requirement for off-main-thread
proof work and independent review before a public cryptographic security claim.

An unproven shuffle, supplied-deck test, or successful local audit cannot unlock
verified multiplayer gameplay. Do not substitute a different proof system or curve
silently. Resolve implementation feasibility before expanding surrounding machinery.

The single-hand milestone is a delivery boundary, not a decision about Sasku match
termination. Initial dealer, production deal schedule, beacon scheduling, and match
policy still require explicit agreement; tests continue to supply named fixtures.

### D3 — Retain Durable Foundations; Defer Broader Recovery Automation

Keep tested persistence-before-publication, durable private material, original-byte
replay, guarded signing, and existing read-only recovery. Once the same game is
resumed, these are correctness requirements rather than optional UX polish.

Do not make seamless reconnect, generalized whole-session/multi-round recovery,
or a polished transcript export/offline-verifier flow prerequisites for completing
the first live-hand integration. Those remain later release milestones. Implement
only the readiness and history agreement needed by that live path; authentication
alone is not session readiness. Interrupted sessions must stop safely unless an
implemented, verified recovery path establishes readiness. A new game uses fresh
session identity/material; retrying a contribution never means re-signing it.

### D4 — Reuse Concrete Boundaries, Not a Speculative Universal Engine

Keep shared transport/session/cryptographic deck operations separate from game
rules and their composition. Additional games should reuse the security machinery.
Generalize draws, exchanges, reshuffles, rules packaging, or other mechanics when
a second game supplies actual requirements.

Consolidate demonstrated duplication in durable orchestration and local rule checks
when the live path makes the common contract clear. Avoid a broad framework rewrite
or package expansion before the first complete hand. Test count is not a measure
of unnecessary architecture; repeated responsibilities and delivery dependencies are.

## Consequences

- The next engineering priority is a credible verifiable-shuffle path, followed by
  end-to-end hand integration using the components already built.
- Existing security invariants and recovery tests remain useful foundations.
- Broader recovery automation and speculative abstractions move behind that path.
- A backend feasibility blocker is recorded explicitly rather than hidden behind
  a placeholder verifier or further unrelated infrastructure work.

## 2026-09-25: Extend the Candidate Browser Path to Full 12 P Sasku Matches

Status: **Accepted.**

With one verified live Sasku hand working end-to-end, extend the candidate
browser profile to play successive audited rounds with rotating dealers until a
partnership reaches 12 game points (capped at 32 hands per table). Keep the
existing per-round verification, audit, and local recovery guarantees.

## 2026-09-26: Short-lived Sasku startup profile (`sasku-match-candidate@3`)

Status: **Accepted.**

Keep the untrusted-peer checks in D1. Remove the unused setup randomness beacon
from this match profile, and batch the four-seat private deal by donor while
retaining every signed share and proof. Reuse verifier workers while keeping
proving workers disposable and cancellable. Measure readiness acknowledgements
before changing their scope. The wire change and compatibility boundary are
recorded in [sasku.md](sasku.md#3-match-profile-sasku-match-candidate4) and [protocol.md](protocol.md).

## 2026-11-27: Pragmatic Card-Game Scope & Re-ordered Roadmap

Status: **Accepted.**

Tablefolk is a non-business-critical peer-to-peer card game among friends, not a
financial or high-stakes custody system. This decision simplifies engineering
scope and re-orders the remaining roadmap around speed, real-world connectivity,
and maintainability while preserving every player-facing cryptographic guarantee
in [spec.md](spec.md#11-goals) (**G1–G7**): no trusted party, hidden-information
secrecy, fair verifiable shuffles, deterministic rule enforcement and audit,
offline verifiability, NAT traversal, and static hosting.

### D5 — Re-order Milestones Around Speed, Connectivity, and Practical Verifiability

Execute remaining work in four pragmatic phases:

1. **Speed & WASM crypto consolidation (#2, #3, #5, #6):** move shuffle
   remasking and batched Chaum–Pedersen DLEQ into Rust/WASM, cache static
   derivations, reuse a single persistent crypto worker, eliminate redundant
   in-process re-verification, add trusted local reload checkpoints, collapse
   nested round queues, parameterize `(m, n)` Bayer–Groth layouts, trim the
   `SHUFFLE` wire body, and graduate `experiments/shuffle-backend` into a
   top-level crate.
2. **TURN & ephemeral reconnect (#4, #7):** move `HEADS`/`SYNC_*` out of the
   hash chain, remove per-message `PeerHistoryBarrier` stalls, replace hard
   automatic 60 s forfeit timers with human-triggered table abort voting, add
   deployment-configured TURN support, harden live Nostr relay failover, and
   surface disconnect/relay/background-tab warnings.
3. **In-browser transcript export & CSP (#8):** freeze a minimal CBOR transcript
   container (omitting `HELLO`), provide in-browser export and verification
   (without maintaining a separate Node CLI), enable strict static CSP, and add
   network/CBOR boundary fuzzing.
4. **Additional games only when wanted:** generalize draws, exchanges,
   reshuffles, and rules packaging only when a concrete second game supplies
   real requirements.

### D6 — Replace External Audit & Second Reference Gate With Soundness Vectors, Self-Audit, and Disclaimer

Supersedes the independent-review release gate in D2. Rather than blocking
releases on an independent external cryptographic audit and a second full
reference implementation, verify the frozen Bayer–Groth profile with:

- cross-runtime test vectors (native Rust, browser WASM, and independent
  Python/TypeScript challenge-derivation checks),
- mutation and soundness tests covering tampered statements, proofs, and edge
  cases,
- a focused self-audit of the vendored `cards-proofs` adaptation, secret
  zeroization, and RNG usage, and
- a transparent disclaimer in the app and documentation stating that the
  cryptography has not undergone an independent external audit.

### D7 — Keep Raw Ed25519 Identity Seeds in IndexedDB With Strict CSP

Drop the requirement for WebCrypto non-extractable Ed25519 identity keys. Keep
the existing raw 32-byte Ed25519 seed in IndexedDB protected by a strict static
Content-Security-Policy (#8). Per-game ElGamal secrets (`x_i`) are already
stored raw in IndexedDB, the local browser JS heap is inside the threat-model
trust boundary, and async WebCrypto calls inside IndexedDB transactions
introduce transaction auto-commit pitfalls without meaningful security gain.

### D8 — Standardize on Nostr Signaling With Configurable Relays

Drop the unused `trystero-torrent`, `trystero-mqtt`, and `manual` signaling
adapter requirements from [spec.md](spec.md). Standardize on Nostr signaling
with configurable relay lists and resilient failover (#7).

### D9 — Limit Wire `VIOLATION` Certificates to Equivocation

Drop bespoke wire `VIOLATION` certificate formats for non-equivocation faults
(invalid proof, unscheduled share, illegal action, audit violation). Every
honest peer already observes the offending signed envelope and validates it
deterministically; only `equivocation` requires paired `[env1, env2]` wire
evidence because two peers may initially observe different envelopes at the same
`(from, seq)`.

### D10 — Planned Protocol & Runtime Simplifications

Accept the following architectural shifts, tracked in #2–#8. The active
profile at the time of this decision was `sasku-match-candidate@3`.

- **Ephemeral `HEADS` / `SYNC_REQ` / `SYNC_RESP` (#4):** move liveness and
  catch-up out of the signed per-sender hash chain onto ephemeral messages over
  the DTLS+`HELLO`-authenticated mesh, avoiding the self-repair chain gap
  paradox, idle transcript bloat, and per-message `PeerHistoryBarrier` RTT
  stalls.
- **Trusted local IndexedDB reload checkpoints (#3):** store a derived local
  checkpoint keyed by the four `(seat, seq, hash)` transcript heads so reloads
  restore immediately while retaining the full signed transcript for peer sync
  and on-demand full verification.
- **Single reused crypto Web Worker (#2):** reuse one persistent worker for
  proving, verification, and batched DLEQ (zeroizing private witness buffers in
  `finally` and terminating/respawning only on error or timeout) instead of
  spawning a fresh worker per shuffle.
- **Omit `HELLO` from offline transcripts (#8):** `HELLO` binds ephemeral WebRTC
  DTLS fingerprints that an offline third party cannot verify against a live TLS
  handshake, so exported CBOR transcripts contain `{version, rules_hash, roster,
  envelopes}` in canonical order without `HELLO`.
