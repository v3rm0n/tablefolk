# Tablefolk

Good company, good cards. A browser-based, peer-to-peer platform for multiplayer
card games, starting with Sasku. Three-player games such as 500 and 1000 are planned.

[Play Tablefolk](https://cards.maido.io/) · [GitHub](https://github.com/v3rm0n/tablefolk)
The first playable rules module is Sasku.

The browser now plays one complete four-player Sasku round: authenticated lobby,
verified candidate shuffles, private hands, bidding, nine tricks, and audited
scoring. Reloading restores the same private hand and signed history.
The proof backend remains experimental and awaits independent review.
See [the first playable round](docs/first-playable-round.md).

## Documents

- `p2p-card-game-platform-spec.20260903124812.c0fadb623e0bf2f6.md`: technical
  specification
- `RULES.md`: Sasku rules source
- `IMPLEMENTATION_PLAN.md`: living roadmap and progress log
- `docs/decisions.md`: accepted architecture, trust-model, and delivery-scope decisions
- `docs/shuffle-backend-assessment.md`: pinned implementation candidates and unresolved proof/backend compatibility
- `docs/protocol-profile.md`: byte-level implementation decisions
- `docs/sasku-profile.md`: confirmed deck/following rules, scoring, and outstanding game decisions

The first-round milestone is implemented. Further rounds, general catch-up,
offline transcript export, cross-browser deployment, and independent security
review remain separate follow-up work.

The isolated [shuffle-backend evaluation](experiments/shuffle-backend/README.md)
now supports experimental Ristretto255 adapters as well as upstream secp256k1.
Ristretto passes 256 native/browser proof checks and 190 adapter cases compared
with the TypeScript primitives in both runtimes. Candidate deterministic
generators, a bounded proof codec, and a SHA-512/CBOR transcript are implemented.
A bounded candidate statement/prover/verifier API is also implemented. Independent review and a production profile freeze remain open. The candidate
profile is integrated into the experimental first-round browser path.

A [candidate deterministic 4×9 CRS](docs/shuffle-crs-profile.md) is now implemented
as `deriveShuffleCrs36` in `@p2pcards/deck`, with fixed SHA-512/CBOR generator
derivation and regression/rejection fixtures. The experimental browser path consumes these bases. The isolated Rust/WASM `candidate-crs` mode now uses these
bases, with all eleven vectors matching independent Rust hashing/group mapping
in both runtimes and 128 cross-runtime proof checks passing. The complete
production profile and independent review remain pending.

The [candidate proof codec](docs/shuffle-proof-codec.md) fixes the 4×9 proof to
106 strictly validated elements in exactly 3,650 canonical CBOR bytes. Its 373
shared acceptance/rejection cases agree across TypeScript, native Rust, and WASM.
Candidate proof assessment now round-trips through that codec. Structural
decoding does not verify a proof or enable browser gameplay.

The isolated `candidate-transcript` mode now proves and verifies using the
[candidate SHA-512/CBOR transcript](docs/shuffle-transcript.md), preserving the
application's game/round/phase hash framing. Python reference vectors agree with
TypeScript/Rust/WASM, and TypeScript reconstructs all eight challenge steps from
real proof traces. This uses an attributed local adaptation of the pinned proof
core; it is now used by the experimental first-round path and is not independently reviewed.

The [bounded shuffle API](docs/shuffle-api.md) binds the game, round, shuffle
seat, roster hash, aggregate key, and ordered decks. Native Rust and browser WASM
prove and verify TypeScript-prepared shuffles through fixed statement/proof
decoders, with private witness validation before proof randomness. Four sequential
shuffles pass 144 verification checks and 84 shared statement-admission comparisons.
A [cancellable application worker and signed shuffle ledger](docs/shuffle-worker.md)
now enforce context and preceding-deck consistency against completed setup.
The [durable shuffle receiver](docs/shuffle-durability.md) now adds sender-chain
admission, guarded local authoring, and recovery that re-verifies each stored proof.
The [shuffle-backed Sasku recovery entry point](docs/shuffled-sasku-round.md)
now connects that deck to private dealing, play, and audit. The browser harness
completes and restores a full hand with real proofs. Four-browser WebRTC tests also
play the entire first round and recover a private hand after reload. A
[bounded semantic phase owner](docs/candidate-round-owner.md) now serializes
incoming shuffle/deal/play/audit traffic and local authoring across the handoff;
[sync receipt and authoring](docs/candidate-owned-sync.md) now shares that ownership boundary.
The first-round browser path uses generation-bound original-history replay and
acknowledgements; general range-based sync remains separate.

## Requirements

- Node.js `^22.12.0` or `>=24.0.0`
- npm 11 or a compatible npm release with workspace support
- A modern browser with WebRTC, Web Crypto, IndexedDB, and Web Locks, served over
  HTTPS or localhost

## Commands

```sh
npm install
# First build the candidate WASM artifacts; see docs/first-playable-round.md.
npm run dev
npm run check
```

`npm run check` runs every workspace type check, the unit test suite, and the
production build.

## Play the First Round

1. Run `npm run dev` and open the displayed application URL.
2. Choose **Open a table**, then share its invitation with three other devices or
   isolated browser profiles. Another tab uses the same identity and cannot open
   the same table concurrently.
3. Guests open or paste the invitation and choose **Join this table**.
4. Once all four identities and their lobby histories are present, each player
   chooses **Mark ready**, accepting the displayed first-round policy.
5. Each player chooses **Play first round**. After automatic setup and dealing,
   bid or pass, choose trump, and play highlighted legal cards. The round ends
   after nine tricks and four verified audit disclosures.

Blank relay settings use the pinned Nostr adapter's public defaults. Custom relay
lists must match on every device. STUN is configured; TURN is not, so some NATs or
restricted networks will fail to connect. Public relays may reject subscriptions
or publications according to their own policies. The browser integration tests
use a local Nostr-compatible relay and real WebRTC, not public relay availability.

The current browser identity implementation stores a raw Ed25519 signing seed in
IndexedDB. It is not a non-extractable WebCrypto key. Clearing site data loses
that identity; malformed stored keys are never silently replaced.

## Browser Tests

```sh
npm exec playwright install chromium
npm run test:browser
```

`PLAYWRIGHT_EXECUTABLE_PATH` can select an installed Chromium-family browser.
The current machine was verified with Brave using:

```sh
PLAYWRIGHT_EXECUTABLE_PATH="/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" npm run test:browser
```

Tests cover four isolated identities, real full-mesh WebRTC, identical persisted
lobby transcripts, joiner reload, same-identity tab exclusion, local roster
snapshot recovery, private-hand reload, bidding/trump choice, all 36 live plays,
valid final audits, malformed invitations, and 320/390-pixel layouts. Screenshots
and failure diagnostics default to `test-results/browser`; `PLAYWRIGHT_OUTPUT_DIR`
can override that location. Browser-test TypeScript is checked by `npm run check`.

## Sasku Scoring Reference

Open **Scoring reference** from the landing page, or visit `scoring.html`, to try completed-hand totals,
named trumps, pokk, karvane, and pass-round scoring. The same deterministic
`scoreSaskuHand` function is exported by `@p2pcards/rules-sasku`. It rejects
inconsistent point/trick totals and distinguishes named diamonds from diamonds
by default. These manual examples are not played or verified game results and
do not modify the lobby or transcript.

The rules package also provides `SaskuPublicHandController({ dealer })` for public
progression without opponents' hidden cards. It enforces public turns, auction
constraints, unique plays, and trick resolution, exposing only a `provisionalScore`.
`auditSaskuHand(setup, actions)` checks that history against a supplied disclosed
deal and returns a complete valid result, an incomplete prefix, or the first
hidden-hand violation. These helpers are not yet wired to network gameplay and
do not verify signatures, a cryptographic deal, or position ownership proofs.

The next protocol boundary is available through `encodeActionBody` /
`decodeActionBody` and `encodeAuditDiscloseBody` / `decodeAuditDiscloseBody` in
`@p2pcards/deck`, plus `decodeActionEnvelope` in `@p2pcards/engine`. The latter
authenticates a bounded signed action against its game, round, action phase, and
expected roster senders. `decodeSaskuAction` maps public action fields and an
engine-verified reveal map to a local hand action; plays name encrypted-deck
positions, not claimed card IDs. These are stateless boundaries, not a durable
game receiver, proof/ownership validator, or a new network gameplay path.

`RoundRevealLedger` in `@p2pcards/engine` adds stateful validation against a
supplied ciphertext deck and explicit private-deal schedule. It verifies signed
deal batches and owner reveal proofs, rejects undealt/repeated/wrong-owner
positions, and returns opened card IDs for rules validation. `classify` does not
mutate state; callers must persist and validate rules before `commit`. It does
not verify shuffle provenance, store private hands, or act as the production
durable game receiver. Its snapshot and exact-replay handling are covered by
unit tests and a supplied-deck IndexedDB/Sasku integration test.

`PersistentSaskuRoundReceiver` in `@p2pcards/game-sasku` now owns the durable
composition: it privately holds the ledger and public hand controller, validates
before persistence, and publishes a joint snapshot only after successful durable
receipt and both state updates. Its bounded FIFO handles concurrent messages,
exact replay, storage failures, and queued cancellation. Corrupt receipts or
internal commit failures stop the instance and require recovery. It requires
explicit trusted round inputs and remains unwired to browser gameplay.

After a complete hand, the same receiver durably collects all four signed
`AUDIT_DISCLOSE` contributions. All cards have already been played, so each body
is `{items: []}`. It reconstructs the original hands from verified openings and
scheduled ownership, then publishes `snapshot.audit.result`: an audited hand
score or the first hidden-rule violation. Partial disclosures do not complete an
audit, and a violation is attributed to the earlier action, not the last
discloser. Recovery replays both pending and completed audits from original signed
envelopes. This local result is not peer-signed result agreement or match
finalization; shuffle verification and full game integration remain separate work.

`readPrivateHand(identity, secretKey)` on the durable receiver now provides
explicit local-only access after the entire initial deal commits. It verifies
the key against that identity's setup key and derives frozen position-to-card
maps for the original `dealt` cards and those `remaining` after committed reveals.
Private reads never add cards to the public snapshot or receive results. The
reader retains no secret or private-hand cache, writes no plaintext records, and
generates no owner-share proofs. Restart callers load the existing game key and
replay verified durable history; missing or corrupt keys are not silently
regenerated. Browser private-hand rendering/input and automatic game recovery
are still separate integration work.

`authorAction(author, secretKey, expectedSnapshot, intent)` now provides headless
local action authoring. It checks private bid/following legality, creates a fresh
proof for a played position, guards signing against stale snapshots and unmatched
authored/accepted heads, then commits the original signed action through local
receipt. It shares the bounded incoming queue and returns an artifact only after
both commits. Uncertain append outcomes or failed local receipt require recovery
from original bytes, not re-signing. This does not broadcast messages or enable
browser gameplay; shuffle provenance, readiness-aware delivery, and broader game
coordination remain prerequisites.

`authorDealShares(author, secretKey, expectedSnapshot)` now generates the local
nonrecipient's exact scheduled batch, and
`authorAuditDisclose(author, expectedSnapshot)` authors the completed-hand empty
disclosure without needing the game key. Both reuse guarded durable authoring and
local receipt. Other participants may contribute first within the same phase,
but a consumed local obligation or later phase cannot trigger re-signing.

Four independent peer databases are tested through dealing, all 36 plays, and
audit, including recovery of stored-but-unapplied deal and audit contributions
using their original bytes. All peers reproduce the same 65-envelope canonical
set and audited result. These supplied-deck tests do not verify a shuffle,
implement live delivery, or enable browser gameplay.

`PersistentSaskuRoundReceiver.recover(options, limits?)` now rebuilds a round
directly from an already restored session registry without signing or touching
persistence. It reverifies complete sender prefixes and recorded setup, preserves
sender-sequence order during semantic replay, and rejects corrupt or impossible
histories instead of sorting them into an apparently valid game. It restores
partial deals/play/audits as well as completed results and exact-replay handling.
Defaults bound recovery to 1,024 envelopes and 16 MiB. Callers must settle old live
work first; other-round gameplay records are rejected, and control-state recovery,
shuffle provenance, and session readiness remain separate responsibilities.

`SaskuRoundInbox` adds bounded incoming prerequisite scheduling. It checks a signed
message against its authenticated direct-peer source and holds future-phase or
gapped messages without writing them. Other senders can supply prerequisites;
eligible originals then pass through the existing durable receiver. Callers must
already enforce transport readiness and explicitly call `processPending()` after
external local/control progress. Inbox idleness is not readiness and may leave
deferred messages pending. Reordered four-peer tests cover dealing, consecutive
plays, and audit arriving before the final card, without re-signing messages.

Setup-beacon randomness now has a durable preparation boundary too.
`IndexedDbSetupBeaconSecretStore` atomically preserves one 32-byte secret per game,
bound to the explicit setup round, local sender, and full ordered roster.
`prepareLocalBeaconContribution` exposes private commitment material only after
that storage commit. After a restart, `restoreLocalBeaconContribution` loads the
existing value and checks it against the accepted commitment; missing, corrupt,
or mismatched values are never silently regenerated. Four-peer tests reach the
same joint seed after a commit-to-reveal restart and exact signed-message replay.
These private helpers do not themselves authorize signing or reveal.

`PersistentSetupReceiver` now privately owns setup state and provides guarded
`authorKeyShare`, `authorRandCommit`, and `authorRandReveal` operations. It binds
the local identity to a concrete session, shares a bounded author/receive queue,
and checks native versus accepted heads before private preparation and again at
signing. Reveals use only the saved preimage matching the accepted commitment,
after all players have committed. Construction restores setup from captured
history without writes; completed, idle setup is handed off through
`getCompletedSetup()`. Failed post-authoring receipt requires original-history
recovery, not fresh proofs or signatures. Live delivery, setup prerequisite
scheduling, and browser integration remain unfinished.

## Current Workspaces

- `apps/web`: playable first-round Sasku, authenticated lobby, invitations, public identity
  fingerprints, signed readiness, relay/peer diagnostics, and a separate scoring reference
- `packages/encoding`: strict RFC 8949 Core Deterministic CBOR boundary
- `packages/crypto`: audited-library-backed hashes, randomness, and Ed25519
  identity primitives
- `packages/protocol`: fixed wire fields, strict message bodies, domain
  separators, hash layouts, and signed channel `HELLO` artifacts
- `packages/session`: durable lobby/finalized-session receipt, restart recovery,
  bounded readonly history capture, accepted-witness planning, guarded envelope
  authoring and native-head inspection, anchored authored-history
  replay, and durable requested-range receipt through semantic validation
- `packages/deck`: card derivation, ElGamal masking, key/share proofs, and wire
  codecs including bounded action/audit share bodies; local unproven deck shuffle
  preparation with a private permutation/remasking witness
- `packages/engine`: privately owned durable setup receipt and guarded authoring,
  commit/reveal beacon,
  durable local beacon preparation and load-only commitment recovery,
  deterministic setup recovery, scoped signed-action decoding, and a stateful
  initial private-deal/reveal ledger with key-bound local hand reads, scheduled
  share-batch preparation, and owner-share preparation
- `packages/game-sasku`: bounded serialized durable receipt owning Sasku's reveal
  ledger, public hand state, signed disclosures, and local hand audit, with separate
  private-hand access, guarded local action/deal/audit authoring, read-only
  single-round recovery, a bounded direct-peer inbox, strict session binding, and
  receipt correlation
- `packages/rules-sasku`: canonical 36-card deck, fixed partnerships, effective-suit
  following, confirmed auction, reference/public-only hand execution, disclosed-hand
  audit, positional action mapping, and scoring
- `packages/storage`: IndexedDB transcripts, monotonic lobby snapshots, atomic
  envelope authoring with checkpoint consistency checks, bounded authored-history
  pages, canonical envelope-set reads, durable browser identity, per-game keys,
  and scope-bound setup-beacon secrets
- `packages/transport`: encrypted signaling-only Nostr adapter, deterministic
  test signaling, strict SDP/ICE messages, full-mesh perfect negotiation, an
  authenticated mesh facade, reciprocal DTLS channel authentication, relay/ICE
  diagnostics, generation-scoped peer replacement, explicit synchronization
  readiness, canonical 16 KiB frames, bounded reassembly, and backpressure

## Transport Boundary

`TrysteroNostrSignalingAdapter` uses pinned Trystero Nostr event signing with
dedicated relay WebSockets, not Trystero-managed peer connections. It provides
subscription readiness, publication acknowledgements, relay reconnection,
bounded recent-event replay, and room-key AES-GCM signaling encryption.
Production use requires Web Crypto in a secure context and a reviewed relay
configuration shared by peers.

Applications compose it through `AuthenticatedMeshTransport`; no game payload
is sent or delivered before reciprocal signed `HELLO` authentication and the
required `synchronizePeer(context)` hook completes. Relay
acknowledgements are not peer receipts, and room-key encryption is not identity
authentication. `relayDiagnostics` reports Nostr relay state, while
`connectionPath(remote)` reports direct, relayed, or unknown WebRTC paths without
revealing candidate addresses or TURN credentials.

The browser UI composes the same mesh and `HELLO` primitives across lobby and
first-round traffic. The application owns the generation-bound history barrier
and gates new game contributions on it. Dynamic transport admission remains
provisional until the host durably validates a join and publishes the roster.
See [first-round readiness](docs/first-playable-round.md#readiness-exchange).

`reconnectPeer(remote)` replaces only that roster peer's connection and repeats
authentication and synchronization. `readyFor(remote)`, `readyPeers`, and
`onPeerReady` expose session readiness separately from authentication. Pending
readiness and synchronization capabilities are cancelled on disconnect, failure,
timeout, or replacement; stale work cannot unlock a new connection.

The synchronizer is a required session-owned boundary, not a built-in automatic
catch-up exchange. `planWitnessSyncRequests` plans bounded requests only from an
already accepted witness. `PersistentSyncReceiver` validates and commits an
admissible outer response before dispatching its requested history through a
semantic-capable durable receiver. It reports partial progress and stops on
failure; a received range is not whole-session readiness.

`replayAuthoredHistory` verifies a captured local authored prefix before sending,
then revalidates bounded pages and submits the original signed bytes. It does
not allocate sequences, re-sign records, repair a lost authored checkpoint, or
grant session readiness. This supports predecessor delivery before fresh chained
controls without adding a chain exemption.

Exact reconnect head discovery/completion and chained-control bootstrap rules
must still be profiled before implementing the automatic `SYNC_REQ` / `SYNC_RESP`
controller. Live public-relay testing and cross-browser WebRTC/TURN validation
also remain follow-up work.

Security-sensitive protocol work must include known-answer and rejection tests.
Passing local tests is not a substitute for independent cryptographic review.

## GitHub Pages deployment

The public site is hosted at https://cards.maido.io/, the repository’s custom
GitHub Pages domain. The default `v3rm0n.github.io/tablefolk/` address
redirects there. Every push to
`main` runs `.github/workflows/pages.yml`: install locked npm dependencies, check
types and tests, compile the pinned Rust/WASM shuffle backend, and build the static
Vite app. The deploy job publishes only `apps/web/dist` through GitHub Pages.
Pull requests run the build checks without publishing. The workflow can also be
started manually from GitHub Actions.

Repository **Settings → Pages → Source** must be **GitHub Actions**. The relative
Vite base (`./`) supports both the custom domain root and project paths, including
workers and WASM.
No application server or deployment secrets are required. Browser identities and
game secrets remain in each browser's IndexedDB; generated build output and local
workspace databases are excluded from Git. Signaling still uses external Nostr
relays and game messages use peer-to-peer WebRTC.
