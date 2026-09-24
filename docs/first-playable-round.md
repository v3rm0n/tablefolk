# First playable Sasku round

The browser now supports one complete four-player round using real WebRTC,
IndexedDB, and candidate Bayer–Groth shuffle proofs in disposable WASM workers.
This is an experimental playable build, not a reviewed cryptographic release.

## Play

Run `npm run dev`. Open a table and share the invitation with three devices or
isolated browser profiles. Players are ready by default and can opt out. Once
all four are ready, player 1 chooses **Play first round**. Setup, the four sequential shuffles, and private
shares run automatically. Players bid or pass, choose trump, and click legal
cards on their own turns. After nine tricks, every browser verifies all four
audit disclosures and displays its audited score. No second round starts.

During play, the live table replaces the lobby as the main view. Your seat stays
at the bottom, your partner sits opposite, and the active player is highlighted.
Cards are ordered by strength, then suit, with legal plays marked; the last completed trick stays
visible until the next card is played. Scores, turn instructions, and completed
trick history are available in the round view. Invitation, connection retry, and
leaving controls remain under **Table & connections**.

The signed roster binds the first-round rules hash: the Sasku card, hand, and
scoring implementations, setup round 0, game round 1, dealer seat 4, opening seat
1, and nine consecutive shuffled positions per seat in seat order. All four
players commit and reveal beacon contributions; this profile records the seed
but deliberately fixes dealer and deal order. Invitations identify
`sasku-first-round-candidate@1`; old connection-check invitations are unsupported.

## Ownership and recovery

`LiveRound` serializes setup and the handoff to `CandidateSaskuRoundOwner`.
A bounded prerequisite inbox holds signed originals that arrive before their
sender predecessor or semantic phase. The browser drives only its own local
contributions. Other players' private cards never enter the local hand view.
Game-key and beacon secrets stay in their durable local stores; private shuffle
witnesses remain inside disposable workers. UI snapshots contain the local
player's renderable cards, not private keys or shuffle witnesses.

On reload, lobby recovery validates the finalized roster, then restores complete
sender chains from signed stored records. Setup and every shuffle proof are
reverified before recovering deal/play/audit state. The existing local game key
must match its signed setup key. A missing or mismatched key is never replaced.
Web Locks prevent a second tab with the same identity from writing the table.

## Readiness exchange

The first-round browser path uses full original-author replay, not automatic
`SYNC_REQ`/`SYNC_RESP` range discovery. Each authenticated peer connection has a
fresh random readiness token. After replay, it announces a sender-prefix
sequence/hash. The receiver acknowledges only after that exact prefix has been
durably and semantically admitted. Both incoming-prefix admission and an
acknowledgement of the current outgoing prefix are required. All three peers must
satisfy this barrier before the local driver starts another contribution or user
action. Catch-up originals can be admitted while this barrier is incomplete.

Prefix/ack markers are bounded ephemeral transport messages, outside the signed
transcript; they are accepted only on a mutually authenticated, generation-bound
channel. They are not peer-signed result agreement or durable evidence. Replaced
connections discard their barriers, and old tokens/heads cannot satisfy a new
barrier. Disconnects pause new local actions. Submitted durable operations finish;
reconnect replays original signatures instead of creating replacements.

This intentionally limited exchange needs all four original authors online. It
does not claim general relay-assisted catch-up, timeout attribution, multi-round
recovery, or complete synchronization of an unannounced hidden peer history.

## Build and validation

Development and production builds stage the candidate JS/WASM from
`experiments/shuffle-backend/pkg-transcript`. These generated artifacts are ignored.
For a fresh checkout, first build them following the candidate-transcript commands
in [the backend README](../experiments/shuffle-backend/README.md), using
`wasm-bindgen-cli` 0.2.100. Then `npm run dev` or `npm run check` stages them locally.
A missing backend fails at startup/build rather than offering a broken shuffle.

`tests/browser/lobby.e2e.ts` uses a local Nostr-compatible relay and four isolated
browser contexts with actual WebRTC and proofs. It verifies unique identities,
roster agreement, nine private cards per browser, reload/recovery of the same
private hand, bidding and trump choice, all 36 plays, and valid final audits.
`PLAYWRIGHT_PRODUCTION=1 npm run test:browser` tests the built application after
`npm run build`. Public relay availability, TURN, other browser engines, and
independent proof/profile review remain release work.

Validated on 2026-09-23: 1,986 unit/integration tests, workspace typechecks,
production build, and five production browser tests passed. The complete
four-browser round also passed against the development server.
