# P2P Card Game Platform Implementation Plan

This is the living implementation roadmap for the platform described in
`p2p-card-game-platform-spec.20260903124812.c0fadb623e0bf2f6.md`.

## Selected Direction

- Delivery target: one verifiable live Sasku hand first, followed by broader
  recovery, transcript/export, and compatibility milestones.
- Application stack: React, TypeScript, and Vite.
- Shuffle proof: Bayer-Groth from the first playable release.
- First rules module: Sasku, based on `RULES.md`.
- Initial game size: four players for Sasku. Shared packages remain generic for
  the specified three-to-eight-player range.
- Package management: npm workspaces, using the toolchain already available in
  the development environment.

## MVP Boundary

The first playable milestone is one complete four-player Sasku hand over the
authenticated P2P path, with Bayer-Groth shuffles in a worker, private dealing,
legal play, and audited scoring. Resolve the shuffle implementation/profile and
review path before expanding surrounding orchestration. Explicit agreed dealer,
deal, and setup randomness policies remain prerequisites; this milestone does not select a
match-termination policy.

Retain the existing durable authoring, secrets, and read-only recovery foundations.
Seamless reconnect, broader session/multi-round recovery automation, transcript
export, and a packaged offline verifier follow the complete live-hand path.
Authentication alone never grants readiness; an interrupted session stops safely
unless an implemented recovery path re-establishes it. Configurable STUN/TURN and
deployment/cross-browser validation remain release work.

Accepted rationale and consequences: [2026-09-17 decisions](docs/decisions.md).

The MVP does not execute arbitrary downloaded rules modules. Sasku is built in
and selected by a known content hash. Additional signaling adapters, generic
rules packaging, full mobile hardening, and the maximum-size load matrix follow
after the protocol has passed review.

## Phase 0: Specification Freeze

- [ ] Define byte-exact deterministic CBOR schemas for every protocol value.
- [x] Define the base CBOR value domain, safe integer bounds, duplicate-key
      rejection, and canonicality checks.
- [x] Freeze fixed byte lengths, the domain-separator catalogue, and the
      unambiguous room/channel/message hash inputs.
- [ ] Define exact point, scalar, digest, fingerprint, and signature encodings.
- [x] Resolve signed `JOIN` validation before a joiner belongs to the roster.
- [x] Define new-peer hash-chain bootstrap during lobby changes.
- [ ] Define deterministic processing of simultaneous phase messages.
- [x] Exclude housekeeping envelopes from recursive witness generation.
- [ ] Define live chain-gap and reconnect synchronization behavior.
- [ ] Define a canonical transcript order and transcript hash.
- [ ] Define timeout certificates and late-message behavior.
- [ ] Narrow timeout blame claims that cannot be proven under a hostile network.
- [ ] Define the self-contained transcript container and rules identification.
- [x] Validate whether Trystero exposes enough connection and fingerprint control;
      otherwise implement signaling-only adapters without unsupported internals.

### Bayer-Groth Profile

- [ ] Select and document the `m x n` matrix for each supported deck size.
- [ ] Define Pedersen generator/CRS derivation with no known discrete-log relation.
- [ ] Define every Fiat-Shamir transcript field and its canonical ordering.
- [ ] Define proof serialization, scalar rules, and point validation.
- [ ] Produce implementation-independent known-answer and rejection vectors.
- [ ] Require independent cryptographic review before a public security claim.

### Sasku Rules Clarifications

- [x] Confirm the 36-card deck and exact rank set.
- [x] Define bidding order, values, passes, ties, and termination.
- [x] Define first leader, turn order, and between-hand dealer rotation.
- [x] Define initial dealer selection for the candidate match: player 4.
- [x] Define plain-suit and chosen-trump ranking completely.
- [x] Define follow obligations when a court or other trump is led.
- [x] Clarify whether the printed suit of a court matters when following suit.
- [x] Define legal play when void in the led suit.
- [x] Define the candidate match target: first partnership to 12 game points.
- [x] Turn all scoring boundaries and special results into decision tables.

## Phase 1: Workspace and Quality Baseline

- [x] Create strict TypeScript npm workspaces.
- [x] Add the React/Vite browser application and module-worker support.
- [ ] Add packages for encoding, crypto, protocol, session, transport, engine,
      Sasku rules, storage, and the adversarial test harness as they become needed.
- [ ] Configure Vitest, property tests, Playwright, linting, formatting, and CI.
- [ ] Configure a static build with a strict CSP and no runtime third-party scripts.
- [x] Establish shared browser/Node TypeScript build targets.

## Phase 2: Cryptographic Core

- [x] Implement SHA-256 and SHA-512 over strict byte inputs with known-answer
      vectors.
- [x] Implement raw Ed25519 identity keys and strict signature verification with
      RFC 8032 vectors.
- [x] Wrap Ristretto points, scalars, hashes, and signatures in validated types.
- [x] Use `crypto.getRandomValues` through a single injectable randomness boundary.
- [x] Implement unbiased random permutations and random scalar generation.
- [x] Implement card-point derivation and lookup tables.
- [x] Implement exponential ElGamal masking and remasking.
- [x] Implement bounded private deck permutation/remasking preparation with a
      prover witness and sequential 36-card round-trip tests, without proof claims.
- [x] Implement aggregate game keys and Schnorr proofs of possession.
- [x] Implement Chaum-Pedersen decryption-share proofs.
- [x] Reproduce a pinned Bayer-Groth proof core natively and in browser WASM,
      including initial identity-A decks, 4x9/6x6 layouts, rejection checks, and
      bidirectional native/browser proof interoperability in an isolated experiment.
- [x] Evaluate Ristretto arithmetic/serialization adapters against the existing
      TypeScript primitives before adapting the candidate's transcript/profile.
- [ ] Implement the frozen Bayer-Groth profile.
- [ ] Move proving and verification into a module worker with progress reporting.
- [ ] Benchmark 36-, 52-, and 128-card decks on representative hardware.

Exit gate: positive and negative vectors pass, malformed encodings are rejected,
tampered proofs fail deterministically, and the proof implementation has been
independently reviewed.

## Phase 3: Session and Transcript

- [x] Implement canonical envelope encoding, signing, hashing, and verification.
- [x] Profile strict bounded ACTION/AUDIT_DISCLOSE bodies and stateless signed
      ACTION scope/sender decoding, without implying proof validation or durable receipt.
- [x] Persist authored envelopes before broadcast to prevent sequence reuse.
- [x] Implement per-sender chain transitions, duplicate handling, and
      equivocation/gap/broken-link classification.
- [x] Route established-session chains by finalized roster and expose complete
      local synchronization ranges.
- [x] Gate finalized-session chain advancement on durable accepted-envelope
      commit through a serialized receive boundary.
- [x] Rebuild finalized-roster sender chains from verified durable artifacts
      without trusting local arrival order.
- [x] Gate lobby admission, roster, readiness, and finalization transitions on
      durable transcript and roster-snapshot commits.
- [x] Implement witness heads without witness-triggered witness loops.
- [ ] Implement remaining deterministic violation certificates.
- [x] Implement self-certifying equivocation evidence with deterministic artifact
      ordering and finalized-roster blame binding.
- [ ] Aggregate simultaneous phase messages and process them in seat order.
- [ ] Persist records by sender/sequence and export in canonical transcript order.
- [x] Define and implement canonical ordering for the verified signed-envelope
      set independently of local arrival metadata.
- [ ] Make transcript replay a pure, network-free operation.
- [ ] Fuzz malformed CBOR, invalid fields, chain gaps, and conflicting envelopes.

## Phase 4: Engine and Sasku

- [ ] Implement the setup, beacon, shuffle, deal, play, audit, and end states.
- [ ] Track stock positions, ownership, public reveals, and dead positions.
- [ ] Enforce expected senders, phase names, rounds, and one action per phase.
- [ ] Enforce scheduled shares and valid position ownership.
- [x] Implement commit/reveal randomness and deterministic seed use.
- [x] Bind setup key/beacon traffic to signed envelope game, round, phase, and
      finalized-roster authority checks.
- [x] Gate setup-state mutation on durable sender-chain receipt and replay setup
      deterministically from accepted transcript artifacts.
- [x] Privately own setup receipt and local KEY_SHARE/RAND_COMMIT/RAND_REVEAL
      authoring in a bounded session-bound queue, with pre-preparation/pre-sign
      head checks, load-only reveal authorization, and completed-only handoff.
- [x] Add an initial private-round ledger for explicit stock allocation, signed
      scheduled share verification, owner-proven public reveals, atomic explicit
      commits, and bounded exact replay, without implying shuffle provenance.
- [ ] Implement Sasku partnerships, bidding, card ranking, trick resolution,
      audits, card points, and game points.
- [x] Implement fixed partnerships, public court/point reference data, and
      completed-hand game-point scoring with input feasibility validation.
- [x] Add a browser scoring reference that cannot alter lobby or game state.
- [x] Implement confirmed card IDs/deck order, effective-suit legal-move filtering,
      and public trick adjudication, with cryptographic deck mapping tests.
- [x] Add public trick-practice examples using the shared rules, without assuming
      bidding, full turn-order policy, or cryptographic dealing.
- [x] Implement the confirmed auction and a complete-information single-hand
      controller with non-mutating preview, atomic rejection, scoring, and replay.
- [x] Build full public-hand browser practice with equal- and unequal-strength deals.
- [x] Share single-hand progression between complete-information and public-only
      controllers, without giving the public controller opponents' hidden cards.
- [x] Audit publicly admissible action histories against a disclosed deal, with
      deterministic first hidden-hand violations and no completion claim for prefixes.
- [x] Map positional Sasku action fields and an engine-supplied opened-card map
      into local rules actions, without accepting claimed actor/card identities.
- [x] Privately own the reveal ledger and public hand in a bounded serialized
      Sasku receiver, gating both commits on matching durable session receipt and
      stopping on receipt/commit invariant failures.
- [x] Durably collect signed post-hand audit disclosures from all four seats and
      audit the original scheduled hands against committed public history, without
      implying peer-signed result agreement or match finalization.
- [x] Derive key-bound local original/remaining hands from committed initial-deal
      shares without publishing private cards, retaining owner shares, or adding
      a plaintext hand store.
- [x] Serialize explicit local Sasku intents with incoming receipt, validate private
      legality, prepare current-phase owner proofs, and guard durable signing by
      snapshot freshness and matching authored/accepted heads before local commit.
- [x] Author exact scheduled nonrecipient deal batches and completed-hand audit
      disclosures through the same durable boundary, allowing other contributors
      within the captured phase but never repeating a consumed local obligation.
- [x] Add a bounded direct-peer round inbox that preserves sender sequence,
      defers missing prerequisites without persistence, and drains eligible
      originals on admission or explicit local/control progress notifications.
- [x] Add exhaustive rule tests for boundary scores and special results.
- [ ] Use synthetic rules fixtures to exercise three and eight seats.

## Phase 5: Transport

- [x] Implement in-memory signaling for deterministic integration tests.
- [x] Implement the production Nostr signaling adapter.
- [x] Implement full-mesh perfect negotiation and trickle ICE.
- [x] Create one reliable ordered data channel per peer pair.
- [x] Authenticate channels with reciprocal signed DTLS fingerprints.
- [x] Reject every non-HELLO payload until authentication succeeds.
- [x] Implement 16 KiB framing, bounded reassembly, expiry, and backpressure.
- [x] Report direct versus relayed ICE paths.
- [ ] Validate the Nostr adapter against live deployment relays and browser WebRTC.
- [x] Replace individual same-identity peer connections with generation-isolated
      callbacks, fresh channels, and reciprocal HELLO authentication.
- [x] Require an explicit session synchronization barrier before exposing peer
      readiness or resuming ordinary application traffic.
- [x] Plan bounded requests from accepted witnesses and verify complete response
      metadata/signatures/internal links before mutation.
- [x] Durably receive chain-admissible requested ranges outer-first through an
      explicit semantic history dispatcher, reporting partial progress and cancellation.
- [x] Provide bounded, checkpoint-anchored replay of original self-authored
      envelopes without re-signing or changing sender sequences.
- [x] Check authored checkpoint/tail/cardinality consistency before invoking new
      signing callbacks, and isolate callback scope, head, and artifact buffers.
- [ ] Reconnect with the same identity and synchronize before resuming.
- [ ] Profile complete reconnect discovery/completion, chained-control gap
      handling, response correlation, routing, and bounded-history exchange;
      implement the production synchronization controller through durable receipt.
- [ ] Keep TURN credentials in deployment configuration, not source control.
- [x] Add explicit pre-finalization dynamic transport admission without weakening
      finalized roster requirements.

## Phase 6: Persistence and Browser Application

- [ ] Store identity keys with a WebCrypto-backed implementation where supported.
- [x] Implement atomic IndexedDB raw-identity fallback with strict validation and
      no silent key regeneration, and public identity fingerprint display.
- [x] Persist the game secret before broadcasting `KEY_SHARE`.
- [x] Persist one scope-bound setup-beacon secret before exposing its commitment,
      and restore it load-only against accepted commitment history without
      silently generating a new preimage after restart.
- [x] Verify local private-hand reconstruction after IndexedDB restart using the
      saved game key and replayed signed history, with no silent key replacement.
- [x] Reconstruct one supplied Sasku round read-only from bounded complete sender
      prefixes, preserving sender order and setup correspondence without signing,
      duplicate persistence, or a synchronization-readiness claim.
- [ ] Persist roster, phase snapshots, transcript records, and outgoing messages.
- [x] Recover an interrupted first round before processing new live messages.
- [x] Implement invitation, lobby, readiness, and connection diagnostics for the
      first-round profile.
- [x] Build a non-playable four-seat connection-check browser lobby with strict
      invitations, signed durable JOIN/ROSTER/READY, history replay, Web Locks,
      and responsive public connection diagnostics.
- [x] Implement crypto progress, private hand, bidding, tricks, and scoring views
      for the first round.
- [ ] Implement actionable disconnect, TURN, timeout, and suspension warnings.
- [ ] Keep secret hand data out of React state snapshots and diagnostic logs.

## Phase 7: Offline Verifier

- [ ] Export one canonical CBOR transcript container.
- [ ] Verify versions and canonical encoding before replay.
- [ ] Verify signatures, chains, shuffle proofs, shares, actions, audits, and scores.
- [ ] Reproduce either the deterministic result or the first violation evidence.
- [ ] Refuse unknown rules hashes rather than execute arbitrary JavaScript.
- [ ] Provide both a Node CLI and browser import flow from the same verifier core.

## Phase 8: Verification and Release Gates

- [ ] Share known-answer vectors across browser and verifier implementations.
- [ ] Property-test shuffle/deal/reveal round trips.
- [ ] Detect every adversarial behavior listed in specification section 14.
- [ ] Compare every replay state hash across Chrome, Firefox, and Safari.
- [ ] Test direct, relayed, reordered-signaling, disconnect, and reconnect paths.
- [ ] Test current desktop browsers and representative iOS/Android devices.
- [ ] Complete accessibility, dependency, protocol, and external security reviews.

## First Playable Milestone Definition of Done

- Four players can complete and audit-score one live Sasku hand.
- Every shuffle is backed by a verified Bayer-Groth proof produced off-main-thread.
- Every persisted game envelope is canonical, signed, chained, and independently
  checked. Ephemeral history-prefix acknowledgements are generation-bound
  authenticated transport messages, not transcript records.
- Publicly invalid actions/proofs/shares are rejected, hidden-rule violations are
  checked by the prescribed audit, and conflicting signed histories are detected.
- The exact shuffle profile/implementation has independent review before a public
  security claim; supplied-deck tests do not satisfy this gate.
- Interrupted or failed work cannot unlock gameplay or cause fresh signatures for
  already authored contributions.

## Subsequent Release Milestones

- Complete deterministic violation evidence, without treating network silence as
  proof of malicious intent.
- The game survives a reconnect within the active phase deadline.
- An exported transcript reproduces the same result without network access.
- Chrome, Firefox, and Safari produce identical replay state hashes.

## Planned Execution Order

1. Resolve the Bayer-Groth backend feasibility, exact profile, and review path for
   the 36-card deck; implement bounded concrete prerequisites where independently
   specified, rather than inventing proof equations or a placeholder verifier.
2. Freeze the remaining policies required by one Sasku hand, and connect the
   existing setup/round stack through verified shuffle/deal provenance.
3. Complete authenticated-ready live delivery, private-hand input/rendering, and
   audited scoring for that hand; add only orchestration needed by this path.
4. Validate the end-to-end protocol, review, browser, and deployment gates.
5. Extend recovery automation, transcript export/offline verification, and
   compatibility; generalize game mechanics when a second concrete game needs them.

## Progress Log

- 2026-09-03: Initial roadmap recorded. React/Vite, Bayer-Groth, Sasku, and a
  protocol-first MVP selected. Workspace confirmed as greenfield.
- 2026-09-03: Bootstrapped npm workspaces and the React/Vite application. Added
  the deterministic CBOR profile and encoding package with known-answer and
  rejection tests. Type checks, 33 unit tests, production build, dependency
  audit, and local HTTP smoke test pass. Stable-Chrome visual testing is pending
  because the current machine does not have that browser executable.
- 2026-09-03: Added shared SHA-256/SHA-512 and byte utilities, semantic
  fixed-length field codecs, all eight version 1 domain separators, and safe
  builders for room, channel, message-signature, and envelope-hash inputs.
  Variable-length challenge layouts remain blocked pending an explicit profile.
- 2026-09-04: Added the injectable CSPRNG boundary and raw Ed25519 identity
  operations. Key derivation and deterministic signing match RFC 8032 vectors;
  public keys use strict prime-subgroup validation and ZIP-215 is disabled.
- 2026-09-04: Added the exact version 1 signed-envelope codec and closed message
  type catalogue. A golden envelope fixture is independently signed with Node's
  Ed25519 implementation and covers canonical unsigned bytes, signature, and
  final envelope hash.
- 2026-09-04: Added per-sender chain transitions and an established-session
  registry with game/roster binding, seat-ordered heads, and contiguous sync
  range reads. Added opaque Ristretto255 point and canonical scalar APIs backed
  by RFC 9496 vectors and uniform non-zero scalar sampling.
- 2026-09-04: Froze self-delimiting card, beacon, and proof hash inputs. Added
  deterministic card-point lookup, ElGamal masking/remasking, aggregate keys,
  Schnorr possession proofs, Chaum-Pedersen decryption-share proofs, and strict
  `KEY_SHARE`/`SHARES` body codecs.
- 2026-09-04: Added unbiased uint32 rejection sampling, descending Fisher-Yates
  permutations, exact `RAND_COMMIT`/`RAND_REVEAL` body codecs, and a deterministic
  commit/reveal beacon with seat-ordered seed derivation and explicit rejection
  outcomes.
- 2026-09-04: Added deterministic setup coordination. Key shares are proof-checked
  under the fixed setup context, deduplicated per seat, and aggregated only after
  all seats contribute; identity aggregates fail collectively before the beacon
  starts.
- 2026-09-04: Added serialized envelope authoring and an IndexedDB implementation
  that atomically appends the transcript row and advances the durable sender head.
  Concurrent tabs cannot reuse a sequence, failed transactions consume nothing,
  and callers receive an artifact only after transaction commit.
- 2026-09-04: Added the exact `WITNESS` body codec, seat-ordered current-head
  snapshots, deterministic matching/stale/sync/conflict assessment, and a fixed
  policy suppressing immediate witnesses for housekeeping envelopes. Periodic
  witnesses still cover housekeeping heads without recursive traffic.
- 2026-09-04: Added exact inclusive `SYNC_REQ` and nested-envelope `SYNC_RESP`
  codecs. Nested signatures are checked at decode, complete local ranges can be
  served, response metadata is preflighted before mutation, and chain application
  preserves duplicate and equivocation evidence outcomes.
- 2026-09-04: Added atomic IndexedDB game-secret get-or-create and gated local
  `KEY_SHARE` preparation on its commit. Concurrent tabs reuse one canonical
  non-zero scalar, restarts recover it, and deletion preserves unrelated game
  state.
- 2026-09-04: Added exact `JOIN`, `ROSTER`, and `READY` body codecs with canonical
  fixtures and a fixed roster-body hash. Intermediate lobby rosters contain one
  to eight unique identities; finalized sessions retain the three-seat minimum.
- 2026-09-04: Added explicit lobby sender-chain bootstrap. Unknown identities are
  never auto-admitted; a strict signed `JOIN` genesis requires an external host
  admission decision or prior host-roster authorization. Host rosters are
  context-bound and chain-checked, while ICE hash differences are surfaced
  without being treated as security failures.
- 2026-09-04: Added deterministic roster-bound readiness. Votes are retained by
  roster hash, duplicate readiness cannot count twice, and the final seat
  triggers a seat-ordered replay of every complete lobby sender chain into the
  established-session registry.
- 2026-09-04: Added durable accepted-envelope storage and atomic lobby-roster
  snapshots. Incoming artifacts are reverified, duplicates are idempotent,
  equal-sequence conflicts preserve evidence, concurrent roster writes converge
  on the newest host sequence, and recovery rejects malformed persisted rows.
- 2026-09-04: Added pure lobby recovery independent of IndexedDB arrival order.
  It reverifies and groups artifacts by sender, enforces host and join genesis
  rules, checks the durable roster snapshot, restores readiness by roster hash,
  and reproduces either a forming lobby or finalized continuous session chains.
- 2026-09-04: Added non-mutating chain classification and serialized durable
  finalized-session receipt. Storage failure or conflict cannot advance memory,
  duplicate disk/memory restart mismatches converge safely, and pure recovery
  rebuilds finalized-roster chains independent of IndexedDB arrival order.
- 2026-09-04: Added serialized durable lobby receipt. Joins, rosters, readiness,
  and finalization now mutate only after exact storage success; stale durable
  roster snapshots require recovery. This work also found and fixed decoded
  envelope-body byte strings aliasing caller-owned encoded buffers.
- 2026-09-04: Added envelope-aware setup coordination and durable setup receipt.
  Key shares and beacon messages are context/body/proof classified before
  persistence, setup mutates only after chain commit, and shuffled IndexedDB
  records replay to identical aggregate setup state and beacon seed.
- 2026-09-04: Profiled self-certifying equivocation violations. Evidence contains
  two verified equal-sender/equal-sequence envelopes in ascending hash order,
  and session checks bind the claimed forfeiting seat to that sender.
- 2026-09-04: Added canonical signed-envelope ordering by identity-key bytes and
  sender sequence, with full chain validation. IndexedDB exposes this order while
  retaining arrival indices only as diagnostics; the final container and hash
  remain unprofiled.
- 2026-09-04: Added the transport workspace with deterministic directed in-memory
  signaling, strict canonical frame maps, 16 KiB splitting, bounded out-of-order
  reassembly, 30-second expiry, and RTCDataChannel buffered-amount backpressure.
- 2026-09-04: Added strict canonical SDP/ICE signaling messages and a full-mesh
  WebRTC coordinator. Peer roles use identity-byte order, offer glare follows
  perfect negotiation, trickled candidates are bounded and generation-aware,
  and each pair creates the same reliable externally negotiated data channel.
- 2026-09-04: Profiled and implemented the signed non-envelope `HELLO` artifact,
  strict SDP SHA-256 fingerprint extraction, reciprocal identity/fingerprint
  verification, frame-zero reservation, and a channel gate that closes on any
  pre-authentication application payload or authentication mismatch.
- 2026-09-04: Composed negotiation and channel authentication into an
  authenticated full-mesh facade. Browser callers see a peer and receive or send
  framed application payloads only after that peer's SDP fingerprints and signed
  reciprocal `HELLO` pass the transport gate.
- 2026-09-05: Validated and pinned Trystero 0.25.4. Added a signaling-only Nostr
  adapter using public event signing and a stateless subscription serializer,
  preserving ownership of negotiation and channel authentication in the mesh.
  Profiled room-key AES-GCM packets, relay selection, and bounded chunking, with
  independent encrypted-wire and relay-selection fixtures.
- 2026-09-05: Added EOSE readiness, publication acknowledgements, relay reconnect
  with bounded recent-event replay, global receive/send limits, exact reassembly
  expiry, and adversarial delayed-import/socket/ACK and leave/rejoin tests.
  Added direct/relayed/unknown ICE diagnostics and per-ICE-generation candidate
  accounting. Public-relay and cross-browser end-to-end validation remain open.
- 2026-09-05: Verification passes: 54 test files, 409 tests, all workspace type
  checks, the web production build, a separate browser bundle of the Nostr
  adapter, and npm audit with zero reported vulnerabilities.
- 2026-09-06: Added same-identity per-peer replacement with local generations,
  native disconnect retirement, remote-restart detection from existing SDP,
  bounded retired-session suppression, and candidate migration across reordered
  restart signaling. Old callbacks and in-flight work cannot affect replacements.
- 2026-09-06: Added a required session-owned synchronization hook after every
  HELLO, separate ready-peer APIs, bounded asynchronous synchronization receipt,
  and cancellation/timeout failure gates. Reentrant error observers and stale
  completions are generation-isolated. The actual automatic catch-up wire
  controller remains deferred pending explicit gap and completion rules.
- 2026-09-06: Reconnection verification passes: 54 test files, 467 tests, all
  workspace type checks, the web production build, and a separate browser bundle
  of the authenticated mesh facade.
- 2026-09-06: Added bounded accepted-witness planning and shared response preflight
  with signature/canonical re-verification, internal chain-link checks, independent
  byte snapshots, and count/byte budgets. Empty or partial witnesses never imply
  catch-up completion.
- 2026-09-06: Added outer-first durable requested-range receipt with a bound shared
  chain receiver and mandatory semantic history dispatch. Gapped outer responses
  cannot repair themselves. Confirmed prefixes survive later failure; queued
  cancellation releases budgets while submitted commits finish consistently.
- 2026-09-06: Added IndexedDB/setup integration for range receipt and recovery,
  semantic rejection, partial progress, and terminal aggregate-key failure, plus
  a transport test proving range receipt alone cannot open the readiness gate.
- 2026-09-06: Requested-range verification passes: 57 test files, 575 tests, all
  workspace type checks, the web production build, a separate browser bundle of
  the session package, and npm audit with zero reported vulnerabilities.
- 2026-09-08: Added bounded authored-history reads and two-pass original-envelope
  replay anchored to a captured checkpoint. The full prefix is verified before
  transmission, and each page is revalidated before submission; concurrent
  appends do not extend the replay target or imply session readiness.
- 2026-09-08: Hardened native authoring against missing/inconsistent checkpoints,
  stale or non-authored tails, and callback head/byte mutation. Signing callbacks
  are isolated, single-use, and expire after append settles. Added restart replay
  integration proving the next chained control needs no predecessor exemption.
- 2026-09-08: Authored-history verification passes: 58 test files, 609 tests, all
  workspace type checks, the web production build, and separate browser bundles
  of the session and storage packages.
- 2026-09-09: Built the first usable browser connection-check lobby. Persistent
  identities and strict invitations feed explicit dynamic transport admission,
  reciprocal HELLO, and signed durable four-seat lobby agreement. The UI keeps
  connection verification, readiness votes, and unavailable gameplay distinct.
- 2026-09-09: Added Playwright coverage with four isolated browser identities,
  a local Nostr-compatible relay, real WebRTC and browser IndexedDB, matching
  transcripts, reload, duplicate-tab exclusion, and local roster-snapshot repair.
  Desktop and 320/390-pixel mobile layouts are checked. Public relays, TURN,
  other browser engines, and actual Sasku gameplay remain open.
- 2026-09-09: Browser-lobby verification passes: 61 unit/integration test files,
  634 tests, all workspace and browser-test type checks, the production build,
  two Playwright tests using installed Brave, and npm audit with zero reported
  vulnerabilities.
- 2026-09-10: Added the rules-sasku workspace with fixed opposite-seat partnerships,
  public point values/court order, and deterministic hand scoring. Named diamonds,
  pass-rounds, pokk, karvane, and 90/91-point bonuses have explicit precedence;
  impossible point/trick totals are rejected without assuming low-rank names.
- 2026-09-10: Added an interactive browser scoring reference backed by that package,
  with no network, persistence, or lobby effects. Tests cover the full scoring
  matrix, partnership symmetry, invalid inputs, and desktop/mobile interactions.
- 2026-09-10: Scoring verification passes: 62 test files, 761 unit/integration
  tests, all type checks and the production build, three Playwright tests using
  Brave, and npm audit with zero reported vulnerabilities.
- 2026-09-14: User confirmed the 36-card rank set, A > 10 > 9 > 8 > 7 > 6
  non-court order, and effective-suit following with free discard and no overtake
  obligation. Updated the earlier contradictory printed-court following rule.
- 2026-09-14: Added canonical sasku-36/v1 card IDs, legal-card filtering, ordered
  public trick winners/point totals, and Ristretto deck integration. Added browser
  trick practice using public examples; no gameplay or shuffle verification is
  implied by the practice view.
- 2026-09-14: Deck/trick verification passes: 63 test files, 790 unit/integration
  tests, all type checks and the production build, four Playwright tests using
  Brave, and npm audit with zero reported vulnerabilities. Following-rule coverage
  includes all 85,680 trump/lead/disjoint-two-card-hand combinations.
- 2026-09-15: User confirmed non-court suit counts for exact bids, repeated raises
  and passes with re-entry, on-turn immediate diamonds declarations, declarer-first
  lead, clockwise play, winner-led subsequent tricks, and one-seat dealer rotation.
- 2026-09-15: Added the complete-information single-hand controller and replay,
  plus full browser hand practice through bidding, 36 plays, nine tricks, and
  scoring. Public snapshots exclude unplayed cards; fixed public practice deals
  are not cryptographic or network gameplay.
- 2026-09-15: Hardened initial polite WebRTC rollback with an event-driven native
  ICE-initialization guard and cancellation on peer replacement. Superseded
  end-of-candidates events are discarded. The final stress run passed 50 full
  four-browser lobby repetitions and 50 invitation/mobile checks using Brave;
  public relays, TURN, and other browser engines remain unvalidated.
- 2026-09-15: Added public-only Sasku hand progression sharing the reference
  transition logic, with no hidden-hand inputs/readers and explicitly provisional
  scores. Added disclosed-hand audit with strict public-history validation,
  incomplete-prefix results, and indexed bid-strength/ownership/following violations.
  Dealer/match policies, signed actions, and cryptographic deal binding remain open.
- 2026-09-15: Public-hand verification passes: 65 test files, 936 unit/integration
  tests (88 new public-hand/audit cases), all workspace/browser-test type checks,
  the production build, and all five Playwright tests using Brave. Existing hand
  practice and the real four-identity connection-check lobby remain functional.
- 2026-09-16: Profiled and implemented bounded ACTION/AUDIT_DISCLOSE codecs with
  strict reveal/share correspondence and canonical point/scalar validation. Added
  stateless signed ACTION decoding bound to game, round, exact action phase,
  finalized-roster identities, and expected senders. Added a pure positional
  Sasku action adapter; actual revealed cards must come from the engine, not
  untrusted action data. The lobby still rejects all gameplay traffic.
- 2026-09-16: Action-boundary verification passes: 68 test files, 1,071
  unit/integration tests (135 new codec/scope/adapter cases), all workspace and
  browser-test type checks, the production build, and all five Playwright tests
  using Brave. Canonical fixtures and a separately verified DLEQ/card-lookup
  integration test cover the new boundary; no stateful game receipt is implied.
- 2026-09-16: Added a round-scoped initial private-deal/reveal ledger over supplied
  completed setup, ciphertext deck, and explicit schedule. It checks signatures,
  sender/phase binding, exact share batches, DLEQ proofs, ownership, reveal
  freshness, and card-point lookup before any mutation. Classification and commit
  are separate; exact replay is idempotent and non-revealing actions consume the
  configured resource budget. Supplied-deck inconsistencies are not blamed on
  whichever player reveals the affected position.
- 2026-09-16: Added test-only composition with real durable session receipt and
  IndexedDB, including complete supplied-deck Sasku play/audit and envelope-based
  replay. Delayed/failed writes, chain gaps, conflicts, and rejected rules leave
  ledger/public state unchanged. The production durable receiver, shuffle
  provenance, and browser gameplay remain unimplemented.
- 2026-09-16: Reveal-ledger verification passes: 70 test files, 1,107
  unit/integration tests (36 new ledger/persistence cases), all workspace and
  browser-test type checks, the production build, and all five Playwright tests
  using Brave. Integration includes all nine tricks and replay of 61 persisted
  setup/deal/action envelopes against the supplied test round context.
- 2026-09-16: Added the game-sasku workspace and production durable round receiver.
  It requires four matching setup/session seats, nine scheduled cards each, and
  an explicit dealer. One bounded queue owns proof/rules validation, durable
  receipt, and both semantic state updates; exact replay and already-durable
  history do not double-apply actions. Receipt correlation checks canonical bytes
  and the bound registry's accepted hash, with fail-closed recovery on corruption.
- 2026-09-16: Replaced the IndexedDB suite's test-only driver with the production
  receiver. Queue limits, caller/callback mutation, reentrant close, queued
  cancellation, storage errors, and post-persistence failures are covered without
  opening browser gameplay or claiming verified shuffle provenance.
- 2026-09-16: Durable-receiver verification passes: 71 test files, 1,130
  unit/integration tests (23 new receiver cases plus the migrated IndexedDB
  suite), all workspace/browser-test type checks, the production build, and all
  five Playwright tests using Brave. Full-hand recovery now replays the 61 stored
  envelopes through the production receiver, including duplicate replay after
  completion. The real-crypto full-round/replay test uses a 15-second test budget;
  no protocol deadlines were changed.
- 2026-09-16: Extended the durable Sasku receiver through signed post-hand audit
  disclosure. All four scoped contributions are required despite having no cards
  left to disclose. Original hands are reconstructed from verified openings and
  scheduled ownership; the local result is an audited score or the first earlier
  hidden-rule violation, never blame on the final discloser. No wire type, result
  agreement, production deal convention, match policy, or browser game path was added.
- 2026-09-16: Added disclosure ordering, strict scope/body, queueing, duplicate,
  chain-rejection, corrupted-receipt, and internal-audit-failure coverage. IndexedDB
  integration now stores 65 envelopes, restores a three-disclosure prefix through
  a fresh connection, completes with the original fourth message, and rebuilds a
  completed audit. Hidden-rule failures replay without producing an audited score.
- 2026-09-16: Signed-audit verification passes: 71 test files, 1,144 unit/integration
  tests (14 new audit cases), all workspace/browser-test type checks, the production
  build, and all five Playwright tests using Brave. Recovery also rebuilds the
  result after a fourth contribution was durably stored but its receipt validation
  or local audit failed. The browser remains connection-check plus public practice;
  neither gameplay nor peer-signed audit-result agreement is enabled.
- 2026-09-16: Added explicit local private-hand reads to the reveal ledger and
  durable Sasku receiver. Reads bind the caller's game key to the accepted setup
  seat, wait for the entire committed initial deal, and derive immutable original
  and remaining position maps without changing public snapshots or storing private
  cards. Only committed owner reveals remove cards from the remaining hand.
- 2026-09-16: Private-context inconsistencies stop the receiver, including active
  semantic commits whose writes are still pending. Wrong keys remain nonterminal;
  private reads cannot inspect a closed or internally failed instance. Added
  IndexedDB restart coverage for non-contiguous hands, partial play, and missing,
  corrupt, or mismatched keys, with raw-storage checks for no plaintext additions.
- 2026-09-16: Private-hand verification passes: 72 test files, 1,174 unit/integration
  tests (30 new cases), all workspace/browser-test type checks, the production
  build, and all five Playwright tests using Brave. Coverage includes three/eight
  seats, stock and non-contiguous ownership, committed-only visibility, terminal
  failure races, and load-only IndexedDB recovery without new plaintext records.
  No browser gameplay, proof-authoring path, database schema, or protocol deadline
  was changed.
- 2026-09-16: Added optional synchronous pre-sign guards and copied game scope to
  the durable envelope author, plus current-phase owner-share preparation in the
  reveal ledger. Local Sasku action authoring now shares the receiver's bounded
  queue, validates exact bids/following/ownership, rejects stale snapshot requests,
  and requires matching authored/accepted heads immediately before signing.
- 2026-09-16: Local actions return an original signed artifact only after durable
  authoring and local receipt. Post-permission append failures or post-authoring
  receipt failures stop further work for original-history recovery. Native
  IndexedDB tests preserve genuine authored provenance through a full hand/audit
  and restart between authored append and semantic receipt without re-signing.
- 2026-09-16: Review found and fixed author-store error masking: a known callback
  invariant failure now survives a substituted generic store rejection, preventing
  queued local actions from signing after the failure. Coverage includes private
  legality, fresh proof nonces, byte isolation, quotas, stale/housekeeping heads,
  and close before signing, before authored commit, and after commit.
- 2026-09-16: Local-authoring verification passes: 74 test files, 1,246
  unit/integration tests (72 new cases), all workspace/browser-test type checks,
  the production build, and all five Playwright tests using Brave. The existing
  private-hand restart test needed a scoped 15-second budget under parallel
  real-crypto load; its key-creation spies are now instance-local to prevent
  cross-test interference after timeout. No protocol deadline or browser gameplay
  gate changed.
- 2026-09-16: Added scheduled nonrecipient share preparation and guarded local
  `authorDealShares` / `authorAuditDisclose`. Contributions require the current
  receiver snapshot at admission, then preserve the captured pending obligation
  while other seats contribute within the same phase. Caller-selected recipients,
  positions, and bodies are not accepted; completed-hand disclosure needs no game
  secret or new proof nonce. Action authoring keeps its turn-bound snapshot rule.
- 2026-09-16: Added a four-peer independent-IndexedDB scenario using production
  deal/action/audit authors, one saved local key per peer, and genuine native
  checkpoints. Every peer reaches the same public state and 65-envelope canonical
  set. Stored-but-unapplied deal and audit contributions recover from original
  bytes without re-signing; direct test delivery is not production transport.
- 2026-09-16: Tests and review found nonce-sampler callback gaps. Phase, pending
  membership, and receiver lifecycle are now checked after each random draw,
  including rejected zero nonces, for deal and action proof preparation. A
  consumed obligation, closure, or terminal failure cannot trigger further
  sampling. Added queued self-disclosure coverage before and at audit completion.
- 2026-09-16: Contribution-authoring verification passes: 76 test files, 1,294
  unit/integration tests (48 new cases), all workspace/browser-test type checks,
  the production build, and all five Playwright tests using Brave. The four-peer
  supplied-deck scenario verifies 65 originals, correct per-peer authored flags,
  saved-key-only recovery, and matching audit results. Its real-crypto/recovery
  test has a scoped 30-second budget; no protocol deadline or browser gameplay
  gate changed.
- 2026-09-16: Added synchronous read-only Sasku round recovery from complete
  captured registry prefixes with count/byte bounds, signature/chain/cache checks,
  and recorded setup key/seed correspondence. A sender-order-preserving merge
  reconstructs only the supplied round and rejects impossible leftover history
  rather than sorting a sender's later messages ahead of its prerequisites.
- 2026-09-16: Replaced four IndexedDB suites' manual recovery ordering and duplicate
  persistence loops with the production factory. Recovery writes nothing and
  preserves original records, heads, authored provenance, and saved keys before
  normal continuation. Whole-session control recovery, multi-round replay, and
  synchronization readiness remain separate responsibilities.
- 2026-09-16: Review identified and fixed semantic-buffer substitution and mutable
  recovery-option rereads. Classification and commit receive independent artifact
  copies; action content comes from private canonical bytes, commit results are
  correlated before publication, and construction/history validation share one
  captured options context. Regression tests also cover late commit/audit failure
  without exposing a partial recovered receiver.
- 2026-09-16: Read-only recovery verification passes: 77 test files, 1,330
  unit/integration tests (36 new cases), all workspace/browser-test type checks,
  the production build, and all five Playwright tests using Brave. The repeated
  real-crypto recovery/live-continuation regression uses a scoped 15-second test
  budget under full-suite load; no protocol deadline changed. The factory remains
  single-round reconstruction over quiescent restored inputs, not full-session
  control recovery, verified shuffle provenance, or a readiness signal.
- 2026-09-16: Added `SaskuRoundInbox` for signature/source-bound direct-peer round
  traffic, with count/byte limits, sender-ordered queues, and fair prerequisite
  deferral. Future phases and chain gaps are not persisted or allowed to block
  other senders' prerequisites. Local/control progress explicitly wakes the
  scheduler; no timer, re-signing, automatic retry, or readiness claim was added.
- 2026-09-16: Added exact round/session binding metadata and an admitted-work idle
  barrier. Inbox shutdown cancels unsubmitted messages without interrupting an
  already submitted durable receipt. Four independent IndexedDB peers now exercise
  cross-sender reorders at deal, play, and final-card/audit boundaries and converge
  on the original 65-envelope history and audited result.
- 2026-09-16: Review found and fixed lost reentrant progress/admission wakes and
  receipt byte-length accessor spoofing. The scheduler rechecks work after source
  observations, and compares bounded private byte copies using intrinsic typed-array
  sizes. Tests distinguish pending deferrals from idleness/readiness and cover
  cancellation, hostile callbacks, resource bounds, and ordinary/terminal failures.
- 2026-09-16: Round-inbox verification passes: 80 test files, 1,376
  unit/integration tests (46 new cases), all workspace/browser-test type checks,
  the production build, and all five Playwright tests using Brave. Reordered
  four-peer traffic converges on 65 original envelopes with no early persistence
  of deferred messages. Inbox and receiver idleness remain local scheduling
  observations, not session readiness; no protocol deadline or browser gameplay
  gate changed.
- 2026-09-17: Added one atomic setup-beacon secret record per game, bound to the
  explicit setup round, local identity, and full ordered roster. Concurrent
  connections reuse one committed preimage; corrupt or conflicting scopes are
  rejected rather than overwritten. Raw 32-byte zero/full-ff values remain valid,
  and deletion preserves unrelated game fields and transcripts.
- 2026-09-17: Added durable-before-commitment preparation and load-only restoration
  against accepted commitment history. Creator callbacks are single-attempt and
  expire after storage settles; failed or substituted results return no material.
  A four-peer native-store fixture restarts after commitments, replays exact
  originals, then reaches identical aggregate keys and seat-ordered beacon seeds.
- 2026-09-17: Hardened fixed-byte snapshots against overridden typed-array lengths
  and slice methods, without changing valid wire encodings. Added transaction
  completion/abort coverage, including handled request errors, and clarified that
  losing an unrevealed beacon preimage cannot be repaired by generating another.
- 2026-09-17: Durable-beacon verification passes: 84 test files, 1,643
  unit/integration tests (267 new cases, including fixed-field and scope rejection
  matrices), all workspace/browser-test type checks, the production build, and
  all five Playwright tests using Brave. Four-peer commit/reveal restart reaches
  the same 12-envelope setup history and seed. Native-browser crash/quota behavior,
  guarded setup authoring, and readiness-aware delivery remain unvalidated or
  separate work; no wire format, database version, or browser gameplay gate changed.
- 2026-09-17: Replaced the structural setup adapter with a private, concrete-session
  owner. Construction captures and verifies available sender history read-only;
  public hex snapshots expose progress without secrets, and completed setup is
  handed off only after admitted work settles. Existing development callers were
  migrated; no production caller required the old mutable-coordinator constructor.
- 2026-09-17: Added guarded local key, randomness commitment, and reveal authoring.
  Native head inspection precedes private preparation and the atomic pre-sign
  guard repeats head/phase/pending checks. Private helpers now guard asynchronous
  storage and every random draw. Reveals only load the original preimage against
  its accepted commitment; failed post-authoring receipt stops further signing.
- 2026-09-17: Extracted reusable bounded session-history capture and added serialized
  readonly native-author head reads. Review identified and fixed canonical setup
  authority: the coordinator now re-verifies original bytes at classification and
  ingestion rather than trusting a mutable decoded view. Regressions use valid
  substituted proofs and ensure no unrecorded key can be published.
- 2026-09-17: Native setup integration covers four isolated databases, all three
  production authoring paths, stored-but-unapplied recovery at each boundary,
  exact-original replay, retained lobby prefixes, and completed setup handoff to
  an explicitly configured Sasku round. Broadcast and automatic setup scheduling
  remain outside this increment.
- 2026-09-17: Guarded-setup verification passes: 87 test files, 1,783
  unit/integration tests (140 more cases than the previous baseline), all
  workspace/browser-test type checks, the production build, and all five
  Playwright tests using Brave. Native restart tests preserve both fresh setup
  genesis and existing lobby prefixes; collective key failure never yields a
  completed handoff. No wire format, database schema, protocol deadline, or
  browser gameplay gate changed.

- 2026-09-17: Accepted the [scope/sequencing decisions](docs/decisions.md): preserve
  security and existing durable foundations, prioritize verifiable shuffle and
  one live Sasku hand, and defer broader recovery automation/speculative game
  abstractions. Updated milestone definitions and execution order accordingly.
- 2026-09-17: Recorded a [pinned backend assessment](docs/shuffle-backend-assessment.md).
  No examined backend is a reviewed drop-in for the selected Ristretto/SHA-512/CBOR
  profile. Parity is the next feasibility candidate; Swiss Post is a separate
  reference. No dependency or curve/proof-system change was made.
- 2026-09-17: Added `createUnprovenDeckShuffle`: bounded detached statement capture,
  private unbiased permutation, fresh nonzero remasking scalars, output-indexed
  witness, and four sequential 36-card shuffle/opening tests. The primitive does
  not establish shuffle provenance or advance production gameplay.
- 2026-09-17: Shuffle-preparation verification passes: all 11 focused cases, then
  `rtk npm run check` with all workspace/browser-test type checks, 88 test files /
  1,794 unit/integration tests, and the production build. The browser bundle hashes
  match the preceding baseline; this increment adds a headless primitive and docs.
- 2026-09-17: Added the standalone `experiments/shuffle-backend` evaluation, pinned
  to Parity `ac4fb67b`, Rust 1.90.0, wasm-bindgen 0.2.100, and Cargo.lock. The
  unchanged secp256k1 proof core builds natively and for browser WASM. Four
  36-card configurations pass the native test; a dedicated Brave worker and
  native process agree in both directions on 256 acceptance/rejection checks.
- 2026-09-17: The final evaluation measured 3,532-byte 4x9 proofs and 3,778-byte
  6x6 proofs, with browser preparation-plus-proving approximately 99–126 ms on
  this desktop. WASM including the test adapter is 540,300 bytes. The assessment
  records build hashes, public fixture artifacts, decoder limitations, and the
  concrete Ristretto adapter/transcript compatibility work. These are experimental
  secp256k1 results, not a production Ristretto proof backend or independent review.
- 2026-09-17: Added isolated Ristretto255 encryption/commitment adapters using
  curve25519-dalek 4.1.3 and the matching Arkworks scalar field, with strict
  32-byte encodings and the existing upstream proof equations/transcript. Five
  native tests pass, including all 56 RFC group-interface vectors; 190 cases
  match the TypeScript primitives in both native and WASM builds (380 comparisons).
  All 256 bidirectional Ristretto proof checks and the 256-check secp256k1
  regression pass in Brave. Ristretto 4x9 proofs are 3,480 bytes; preparation plus
  proving measured about 41–47 ms in the warm browser worker on this desktop.

- 2026-09-22: Implemented the [candidate deterministic 4×9 CRS](docs/shuffle-crs-profile.md)
  for 36-card shuffle adaptation. Fixed SHA-512/CBOR inputs derive the proof base,
  Pedersen blinding base, and nine message bases through the Ristretto group map.
  Identity/repeated/negated bases fail closed; parameters have no caller-selected
  seed or random fallback. Eleven byte-level regression fixtures and eight tests
  cover derivation, parameter isolation, and rejection behavior. The candidate is
  not consumed by the backend and does not freeze the complete proof profile.
- 2026-09-22: CRS increment verification passes: `npm run check`, including all
  workspace/browser-test type checks, 89 test files / 1,802 tests, and the
  production build. Browser gameplay and the experimental Rust/WASM proof backend
  are unchanged; independent CRS interoperability is still pending.

- 2026-09-22: Added an isolated `candidate-crs` Rust feature for the fixed 4×9
  parameters, independently encoding the CBOR tuple and using pinned RustCrypto
  SHA-512 plus Dalek's Ristretto map. Both proof creation and verification use the
  candidate bases; altered parameters and other matrices are rejected. Native and
  browser WASM match all eleven TypeScript fixtures (22 comparisons), with eight
  native tests, 128 cross-runtime proof checks, and 380 adapter comparisons passing.
  Reports identify the CRS profile and reject mismatched builds. The upstream
  Fiat-Shamir transcript/compound proof codec remain experimental and unchanged.
- 2026-09-22: Regression verification also passes for the original Ristretto mode
  (five native tests, 256 browser/native proof checks, 380 adapter comparisons)
  and secp256k1 mode (one native test, 256 browser/native proof checks). All eight
  TypeScript CRS tests pass. Rust 1.90.0 and wasm-bindgen 0.2.100 were restored
  under `/tmp/cards2-rust`; no global toolchain configuration changed. Application
  runtime code and gameplay gates are unchanged by this experiment increment.

- 2026-09-22: Added the [candidate 36-card proof codec](docs/shuffle-proof-codec.md)
  in TypeScript and Rust. It accepts exactly 106 canonical point/scalar elements
  in 3,650 CBOR bytes, rejecting size/header/type/encoding errors before generic
  proof deserialization. The Rust bridge inserts all eleven vector counts from
  constants; candidate proof assessment round-trips through the codec. All 373
  shared cases agree in TypeScript/native/WASM (1,119 comparisons), with 115
  TypeScript codec tests, 12 candidate native tests, and the 128 proof checks passing.
  The outer experimental fixture decoder and upstream Fiat-Shamir transcript
  remain outside this codec boundary.
- 2026-09-22: Codec increment verification passes: `npm run check` with all
  workspace/browser-test types, 90 files / 1,917 tests, and production build.
  Both original proof modes pass native tests and 256 browser/native checks each;
  the Ristretto adapter also retains all 380 comparison results. The application
  bundle hashes match the previous baseline; no live gameplay gate changed.

- 2026-09-23: Added an explicit [candidate SHA-512/CBOR transcript](docs/shuffle-transcript.md)
  in TypeScript and an attributed local Rust proof-core adaptation. It retains
  the existing game/round/phase framing, binds the additional generators, and
  absorbs each challenge response. All equation files/append call sites are
  unchanged; the private matrix-product blinder uses the supplied cryptographic
  RNG directly. A 55-file source hash manifest records the exact adaptation.
- 2026-09-23: The adapted native/WASM proof mode passes 15 native tests, 128
  proof checks, 1,119 codec comparisons, 22 CRS comparisons, and 380 adapter
  comparisons. Eight independent Python/hashlib challenge vectors match all
  implementations, and TypeScript reconstructs 64 real proof challenge records.
  Four genuine proofs pass under their own transcript profile and fail under
  the other profile. Typed production statement/context admission and review
  remain unfinished; the experimental fixture parser is not a network boundary.
- 2026-09-23: Final verification passes: `npm run check` with all workspace and
  browser-test types, 91 files / 1,925 tests, and the production build. All four
  backend modes pass their native tests and browser/native proof checks (768
  checks total); prior fixed-CRS codec and arithmetic comparisons remain green.
  `verify-vendor.mjs` verifies the 55-file attributed source snapshot. The
  application bundle hashes match the previous baseline and gameplay remains gated.

- 2026-09-23: Implemented the [bounded candidate shuffle API](docs/shuffle-api.md):
  fixed 36-card statements bind game/round/seat/roster/key/decks; native/WASM APIs
  bypass the legacy fixture decoder. Private permutation, scalar, and remasking
  checks precede proof RNG access; generated proofs self-verify. Four sequential
  TypeScript-prepared shuffles yield eight native/browser proofs, passing 144
  verification checks, 84 admission comparisons, and 16 private-input rejections.
  Candidate native tests pass (17); `npm run check` passes all types, 92 files /
  1,941 tests, and production build. Existing candidate regressions retain 128
  proof checks, 1,119 codec comparisons, 22 CRS comparisons, 380 adapter comparisons,
  and 64 challenge comparisons. The vendor manifest verifies all 55 files; the
  application bundle hashes and live-game gates remain unchanged.

- 2026-09-23: Added a cancellable application shuffle worker/client and a
  [candidate signed shuffle ledger](docs/shuffle-worker.md). Witness generation
  stays inside disposable workers; the ledger derives the initial deck from the
  card table and binds four sequential contributions to completed setup,
  roster/key/round/seat, and the preceding verified deck. Admission and worker
  lifecycle tests cover rejection before backend work, retries, duplicate receipts,
  cancellation, timeout, concurrency, detached buffers, and stale completion.
  `npm run check` passes all types, 94 test files / 1,952 tests, and production
  build. Real browser tests complete four signed shuffles in both development and
  a production build served under `/nested/`, including cancellation/reuse and
  invalid-proof rejection without state advancement. Live gameplay remains gated.

- 2026-09-23: Added the [durable candidate shuffle receiver](docs/shuffle-durability.md).
  Proof verification precedes durable sender-chain admission, and the deck advances
  only after receipt/registry checks. Bounded recovery reconstructs setup and
  re-verifies all stored shuffle proofs without writes. Local authoring binds the
  current snapshot and authored predecessor, with recovery required after ambiguous
  signing/appends. Private witnesses stay outside stores and authoring APIs.
  `npm run check` passes all type checks, 96 test files / 1,965 tests, and the
  production build. Browser development and nested-path production checks pass
  real WASM proof authoring, IndexedDB receipt, and fresh-connection recovery of
  every partial/completed prefix. Application bundle hashes remain unchanged.

- 2026-09-23: Added [shuffle-backed Sasku round recovery](docs/shuffled-sasku-round.md).
  It accepts no supplied deck: setup and all four shuffle proofs are reconstructed
  from durable sender history before private dealing/play/audit recovery. The
  caller-agreed dealer and schedule are explicitly validated and captured before
  asynchronous proof work. Private-hand recovery uses existing local game secrets
  and durable donor shares, without persisting private hands.
  `npm run check` passes all types, 97 files / 1,968 tests, and the production
  build. Both browser builds complete real-proof shuffles, four private nine-card
  hands, 36 legal plays, a valid local audit, and fresh-IndexedDB-connection recovery
  of the completed round. This isolated four-identity harness does not establish
  network readiness, four-peer gameplay, or peer-signed score agreement.

- 2026-09-23: Added a [bounded semantic phase owner](docs/candidate-round-owner.md)
  across shuffle, dealing, play, and audit. It serializes direct/history receipt
  and local authoring, defers missing sender/phase prerequisites, and hands off
  only after the fourth shuffle is durably accepted and re-verified. Active work
  remains budgeted; close cancels queued work while active persistence finishes.
  Controls remain excluded until they can share this ownership boundary safely.
  Workspace check passes all types, 98 files / 1,973 tests, and production build;
  the final owner-focused suite passes six tests including the additional failed
  handoff/recovery case. Both browser builds replay 57 signed semantic originals
  in reverse order into a fresh durable owner and reproduce the completed audit
  with zero pending operations. The application bundle hashes remain unchanged.

- 2026-09-23: Added [owner-coordinated sync receipt](docs/candidate-owned-sync.md).
  Signed requests and bounded preflighted responses share the semantic/proof queue.
  Outer controls commit before originals; ranges stop on missing prerequisites
  instead of waiting on their own queue. Controls refresh the captured shuffle
  prefix under the same lease. Cancellation releases queued reservations and
  preserves progress from completed active writes. Historical controls have no
  replayed control effects.
  Workspace check passes all types, 99 files / 1,979 tests, and production build.
  The final five-test sync suite also passes after extending queued-sequence
  conflict detection to controls. Both browser builds persist a real signed
  response and confirm an exact historical shuffle duplicate through the owner.

- 2026-09-23: Added owner-queued outgoing sync request authoring and response
  serving from admitted requests. Native authored heads and exact admitted
  predecessors are checked before signing and inside the append transaction.
  Missing or oversized ranges fail before signing; uncertain writes require
  recovery. Nine focused sync tests pass; development and nested-path production
  browser/IndexedDB checks pass with real proofs. Workspace checks pass 99 files /
  1,983 tests. An initial concurrent browser/workspace run hit one existing
  five-second recovery-test timeout; the workspace rerun passed without changes.

- 2026-09-23: Implemented the experimental [first playable round](docs/first-playable-round.md).
  The signed rules hash binds dealer, deal order, beacon use, and the candidate
  profile. The browser owns setup, verified shuffle handoff, private dealing,
  bidding/trump/play inputs, and audited scoring. Generation-bound prefix/ack
  barriers follow full original-author history replay; disconnected peers pause
  new local actions. Reload restores and re-verifies the existing signed history
  and matching private game key. The four-browser WebRTC test completed bidding,
  trump selection, all 36 plays, and valid audits, including a private-hand reload.

Validation passed: 100 files / 1,986 tests, all workspace typechecks, and the
production build. The real four-browser first-round test passed in development
and production; all five production browser tests passed. Work stops at the
user's requested playable-first-round milestone.
The scope remains one experimental round. Independent proof/profile review,
public relay/TURN and cross-browser validation, peer-signed result agreement,
general range-based sync, multiple rounds, and offline transcript export remain
follow-up work; none is claimed complete by the playable first-round milestone.

- 2026-09-26: Introduced `sasku-match-candidate@3` after documenting the
  [round-start performance decision](docs/round-start-performance.md). The live
  match now completes setup after four signed, proof-checked game keys without
  the unused beacon, and accepts four donor-wide 27-share batches instead of
  twelve recipient batches. Each share still has its original Chaum–Pedersen
  proof; every shuffle remains proved and verified. A reusable verifier worker
  avoids repeated WASM startup while proof workers remain disposable.
  Invitations and rules hashes separate the new transcript from `@2`. Workspace
  typechecks, 1,994 unit tests, build, and six production browser scenarios pass,
  including a full four-browser match with reload. In a same-browser comparison,
  local startup to bidding measured 18.3–18.4 s versus 25.6–26.4 s for the prior
  beacon and deal schedule. One four-browser startup measured 8.6 s from the
  final ready click. Acknowledgement timing was not changed.
