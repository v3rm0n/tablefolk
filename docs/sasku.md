# Sasku Match Profile & Live Architecture

This document defines how Tablefolk implements and runs four-player Sasku in
the browser under the active **`sasku-match-candidate@3`** profile.

- **Game rules & scoring tables:** [RULES.md](../RULES.md)
- **Wire & storage formats:** [protocol.md](protocol.md)
- **Shuffle proof format:** [shuffle.md](shuffle.md)

> **Experimental status:** The browser runs complete four-player Sasku matches
> over WebRTC with verified candidate Bayer–Groth proofs, private dealing, and
> audited scoring. The cryptography has not undergone an independent external
> audit; see [decisions.md](decisions.md#2026-11-27-pragmatic-card-game-scope--re-ordered-roadmap)
> for the soundness-vector and self-audit release criteria.

---

## 1. Canonical Deck & Rules Engine

- **Deck ID:** `sasku-36/v1` (36 cards).
- **Card identifiers:** rank (`6`, `7`, `8`, `9`, `10`, `J`, `Q`, `K`, `A`) +
  suit letter (`C`, `S`, `H`, `D`), e.g. `6C`, `10H`, `AD`. Suit-major canonical
  order: clubs, spades, hearts, diamonds; `6` through `A` within each suit
  (serialization order, not trick-taking strength).
- **Seats & partnerships:** zero-based `0..3` in code (displayed as 1–4);
  partnerships are `{0, 2}` and `{1, 3}`.
- **Following rule:** effective-suit following with free discard and no
  overtake requirement (all 12 courts belong exclusively to the `trump`
  effective suit).
- **Deterministic controllers (`@p2pcards/rules-sasku`):**
  - `SaskuPublicHandController({ dealer })` tracks public auction/play state
    without hidden hands and exposes `provisionalScore`.
  - `SaskuHandController` is the complete-information reference controller used
    for replay and auditing.
  - `auditSaskuHand(setup, actions)` validates a complete 36-card disclosed
    deal and up to 64 actions, returning `{status: "valid", score}`,
    `{status: "incomplete"}`, or `{status: "violation", seat, at, rule}` where
    `rule` is `bid_strength`, `card_ownership`, or `follow_suit`.
  - `scoreSaskuHand` enforces card-point/trick subset-sum feasibility (120
    points across 9 four-card tricks) and implements the scoring precedence in
    [RULES.md](../RULES.md#scoring). The standalone `scoring.html` page runs
    this same pure function with no lobby, storage, or network effects.

---

## 2. Positional Action & Audit Mapping

Sasku uses the generic `ACTION {kind, data, reveal, shares}` body in phase
`round.<r>.play.<t>` (`t` = zero-based accepted hand-action count, including
auction actions and trump choice):

| `kind` | `data` | `reveal` / `shares` |
| --- | --- | --- |
| `pass` | `{}` | Empty |
| `diamonds` | `{}` | Empty |
| `bid` | `{value}` (`3..9`) | Empty |
| `choose_trump` | `{suit}` (`clubs` \| `spades` \| `hearts` \| `diamonds`) | Empty |
| `play` | `{}` | One owned, unrevealed position `0..35` + owner DLEQ share |

The actor is always derived from the signed envelope's `from` identity and the
finalized roster; played cards come exclusively from decrypting the scheduled
ciphertext with verified shares and looking up the card point—never from a
claimed card ID in the message.

After the ninth trick (all 36 positions opened), every seat signs
`AUDIT_DISCLOSE` with `{items: []}` in `round.<r>.audit`. Once all four
disclosures commit durably, each browser reconstructs the original nine-card
hands from verified openings and scheduled ownership and runs `auditSaskuHand`.
Violations attribute blame to the earlier offending action, not the final
discloser.

---

## 3. Match Profile (`sasku-match-candidate@3`)

The signed roster's `rules_hash` ([apps/web/src/live-profile.ts](../apps/web/src/live-profile.ts))
commits every player to the exact rules implementation and match parameters:

- **Invitation profile:** `r=sasku-match-candidate@3`, `s=trystero-nostr`
  (older `@1` / `@2` invitations and transcripts are incompatible).
- **Match progression:** initial dealer is seat 4 (index `3`), opening bidder
  is seat 1 (index `0`), dealer rotates by `+1 mod 4` each audited round until
  a partnership reaches **12 P** (hard cap of **32 hands** per table; an
  invalid audit stops without awarding points or starting a new hand).
- **Key-only setup (`round: 0`, `phase: "setup.keys"`):** requires four signed,
  proof-checked `KEY_SHARE` envelopes and a non-identity aggregate key. The
  unused commit/reveal randomness beacon is omitted in `@3` because dealer and
  deal order are fixed while each player independently shuffles with a verified
  proof. (The beacon-capable setup engine remains available for future
  profiles.)
- **Four-donor private deal (`round.<r>.deal.0`):** positions `0..8`, `9..17`,
  `18..26`, `27..35` belong to seats `0..3`. Instead of 12 per-recipient
  envelopes across four serial phases, each seat publishes **one** signed
  `SHARES` envelope with `to: 4` containing the 27 ascending positions owned by
  the other three seats, each with its individual Chaum–Pedersen proof bound to
  `round.<r>.deal.0`. All four valid batches must commit before any private
  hand or bid is available.
- **Measured effect (2026-09-26 desktop benchmark, non-guarantee):** local
  four-player demo startup to bidding dropped from 25.6–26.4 s to 18.3–18.4 s;
  one four-browser WebRTC run reached bidding 8.6 s after the final ready click.

---

## 4. Live Ownership, Workers & Recovery

### Phase ownership & serialization

On `main`, `LiveRound` coordinates setup and hands off each round to
`CandidateSaskuRoundOwner` (`@p2pcards/game-sasku`), which keeps the mutable
shuffle and round receivers private behind one serialized, bounded queue
(defaults: **32 operations**, **1 MiB** total, **64 KiB** per envelope):

1. **Setup** (`PersistentSetupReceiver`): collects four `KEY_SHARE` proofs and
   builds the aggregate key.
2. **Sequential shuffles** (`PersistentCandidateShuffleReceiver` +
   `CandidateShuffleLedger`): admits seats `0..3` in order, verifying every
   proof before durable commit.
3. **Deal, play & audit** (`PersistentSaskuRoundReceiver` +
   `RoundRevealLedger`): opens only after all four shuffle proofs commit;
   defers missing sender predecessors and future phases in memory without
   persisting them early.
4. **Local authoring & private hands:** `authorShuffle`, `authorDealShares`,
   `authorAction`, and `authorAuditDisclose` share the same queue, check
   snapshot/phase freshness and native-vs-accepted head agreement immediately
   before signing, and persist before returning bytes. Private hands are
   derived on demand from the local IndexedDB game secret and committed donor
   shares (`readPrivateHand`); they never enter public snapshots, logs, or
   storage.

*(Planned simplification in `#3` & `#5`: consolidate the nested `LiveRound` /
`CandidateSaskuRoundOwner` / persistent receiver queues into a single-owner
round coordinator, verify envelopes once at untrusted boundaries, and cache the
decrypted 9-card private hand per round.)*

### Worker lifecycle

On `main`, `CandidateShuffleClient` runs WASM proofs off the main thread using
artifacts staged into `apps/web/public/shuffle-candidate/`:

- **Proving** runs in a **disposable worker**; permutation and remasking
  scalars never leave the worker, and temporary buffers are cleared before
  termination.
- **Verification** reuses a warmed worker between successful calls to avoid
  repeated WASM initialization.
- Cancellation, failure, timeout (default 30 s local limit), or close
  terminates the active worker immediately; stale results cannot settle later
  calls. Missing WASM artifacts fail closed at build/startup.

*(Planned in `#2`: move shuffle remasking and batched Chaum–Pedersen DLEQ into
Rust/WASM and reuse a single persistent crypto worker across prove, verify, and
DLEQ calls, zeroizing private witness buffers in `finally` and respawning only
on timeout or error.)*

### Readiness barrier & sync boundaries

- **Browser readiness exchange (current `main` vs. target `#4`):** on `main`,
  each new authenticated connection replays its full original authored history
  (and only the verified, acknowledged suffix while that connection stays
  alive), then exchanges ephemeral generation-bound **prefix/ack** markers
  (`PeerHistoryBarrier`) outside the signed transcript. All three peers must
  satisfy this barrier before local drivers author new contributions.
  Disconnecting pauses new local actions; reconnecting replays original signed
  bytes instead of re-signing. In `#4`, ephemeral unchained `HEADS` /
  `SYNC_REQ` / `SYNC_RESP` replace both chained `WITNESS`/`SYNC_*` and
  per-message `PeerHistoryBarrier` RTT stalls, enabling automatic mid-round
  reconnect and relay-assisted catch-up.
- **Reload recovery (current `main` vs. target `#3`):** on `main`, restoring a
  table validates the finalized roster, re-verifies complete sender chains,
  setup, and every stored shuffle proof without writing to storage, and checks
  that the local IndexedDB game key matches its signed `KEY_SHARE`. In `#3`, a
  trusted local IndexedDB reload checkpoint keyed by the four
  `(seat, seq, hash)` transcript heads enables immediate restore while keeping
  the full signed transcript for peer sync and on-demand full verification.
- **Owner-coordinated `SYNC_REQ`/`SYNC_RESP` (current `main`):**
  `CandidateSaskuRoundOwner` currently supports bounded chained control-scope
  sync receipt and serving (`phase: "control.sync"`, `<= 32` originals,
  `<= 64 KiB` per envelope) on the same queue; automatic ephemeral catch-up is
  tracked in `#4`.

---

## 5. Known Limitations & Remaining Work

- **Performance (`#2`, `#3`, `#5`, `#6`):** shuffle remasking and DLEQ still run
  in JS, envelopes are re-verified across internal layers and on reload, and
  `SHUFFLE` still transmits the full statement alongside the proof.
- **Connectivity & reconnect (`#4`, `#7`):** STUN is configured without TURN,
  so strict NATs/firewalls can block direct WebRTC links; all four original
  authors must currently stay online because ephemeral `HEADS`/`SYNC_*`
  catch-up and human-triggered abort voting are not yet wired into the browser.
- **Offline verification & CSP (`#8`):** in-browser CBOR transcript export and
  verification (omitting `HELLO`) and strict static CSP headers are not yet
  implemented.
- **Cryptographic assurance & cross-browser validation (`#6`, `#7`):** freezing
  the parameterized `(m, n)` shuffle profile, expanding cross-runtime/mutation/
  soundness vectors, completing a focused self-audit (with a transparent
  no-external-audit disclaimer), and validating Chrome/Firefox/Safari/mobile
  remain tracked in [IMPLEMENTATION_PLAN.md](../IMPLEMENTATION_PLAN.md).
