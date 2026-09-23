# Candidate durable shuffle receipt and recovery

`PersistentCandidateShuffleReceiver` connects the candidate signed shuffle ledger
to the existing session registry, durable receiver, and envelope author. It keeps
the proof-backed deck behind a storage commit barrier and reconstructs it by
re-verifying stored contributions. It remains a candidate integration path; no
live-game UI or reviewed production profile is enabled.

## Opening and recovery

Call `PersistentCandidateShuffleReceiver.open(options)` after restoring complete
sender prefixes from durable storage into `SessionChainRegistry`. The supplied
`PersistentSessionReceiver` must be bound to that exact registry. Options identify
the admitted roster body, local identity, setup round, shuffle round, agreed deck
specification, proof verifier, and optional history limits.

Opening captures bounded, authenticated sender histories, reconstructs key/beacon
setup from those histories, and checks the roster against the registry. It then
replays this round's signed `SHUFFLE` contributions in seat order. Every proof is
verified again, starting from the agreed card-point table; no stored final deck or
previous verification boolean is trusted. More than four contributions, skipped
seats, malformed statements, inconsistent deck links, invalid proofs, and local
sender ordering violations fail recovery. Stored deal/play/audit activity requires
a complete shuffle chain and must follow that sender's shuffle.

Recovery writes nothing. A history change during asynchronous proof verification
invalidates opening. Partial prefixes are valid and expose only the next public
preparation statement. `finalDeck` is available only when all four contributions
have been verified. The admitted roster and agreed deck/deal policy still come
from the application; recovery does not establish lobby readiness.

## Receipt and commit order

`receive(artifact)` captures canonical bytes and permits one active operation,
with no pending queue. Sender gaps and forks are rejected before proof work.
The candidate ledger then validates envelope scope, body, context, and input-deck
provenance and verifies the proof. Its commit barrier calls the bound durable
session receiver, validates the receipt and resulting registry state, and only
then advances the deck and immutable snapshot.

Exact replays remain idempotent and confirm durable storage. A rejected chain or
proof cannot advance the deck. A storage exception with an unchanged registry
allows retry of the same bytes. Registry changes or inconsistent receipts require
recovery. Closing during a commit can leave a durable envelope without an in-memory
shuffle transition; reopening discovers and verifies those committed bytes. No
success artifact should be broadcast from a failed operation.

This receiver expects exclusive ownership of session changes while an operation
or recovery is running. External changes invalidate its history checkpoint. The
application must coordinate control/sync receipt with this owner; this is not yet
a general multiphase inbox.

## Local authoring

Prepare a public statement/proof with the application worker, then call
`author(author, prepared, expectedSnapshot)`. The receiver requires its own current
snapshot object, the expected local seat, matching context/input deck, and a valid
proof. It checks the durable authored head against the admitted sender prefix both
before verification and inside the signing transaction. Only then does the existing
`PersistentEnvelopeAuthor` allocate a sequence, sign, and append the public bytes.
The authored envelope passes through durable receipt before success is returned.

An ambiguous append or any post-signing failure blocks further authoring until
recovery. It never generates a replacement for a potentially committed sequence.
Restore/replay the original authored history with the existing author-history
facilities before opening a new shuffle receiver. The receiver does not accept
or persist private permutations, remasking scalars, or worker state.

## Verification

Tests cover partial and complete replay, commit barriers, retries, chain rejection
before proof work, proof rejection before writes, concurrent operation rejection,
close during commit, registry races, missing contributions, malformed recovered
semantics, stale author heads, and ambiguous append recovery. The IndexedDB
integration test reopens a fresh connection after each contribution and verifies
that recovery writes no envelopes.

`run-web-shuffle.mjs` additionally uses real WASM proofs and browser IndexedDB in
both development and a production build under a nested path. It authors the local
shuffle durably, receives the other three, reopens storage after each contribution,
re-verifies each prefix, and checks exact replay and the final 36-card deck.

The [shuffle-backed Sasku entry point](shuffled-sasku-round.md) now connects the
recovered deck to private dealing, play, and round recovery using an explicit
caller-agreed policy. Coordinated ready/control delivery and live UI wiring remain.
Profile freeze, independent vectors, and cryptographic review remain release gates.
