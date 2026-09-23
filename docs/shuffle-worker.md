# Candidate application shuffle worker and ledger

The application now has a cancellable `CandidateShuffleClient` and worker, backed
by the bounded Rust/WASM API. The engine's `CandidateShuffleLedger` checks signed
shuffle envelopes against completed setup and the preceding verified deck. These
components are executable candidates; the lobby UI does not start a live game.

## Worker boundary

`CandidateShuffleClient.prove(template, signal?)` takes a public statement whose
input and output decks both equal the preceding deck. The worker generates a
fresh permutation and remasking scalars, constructs the output, and invokes the
self-verifying native prover. It returns only the public statement and proof.
No private witness is sent to the main thread. Temporary encoded witness arrays
are cleared; this is not a guarantee that all JavaScript/WASM secret copies have
been erased.

`verify(statement, proof, signal?)` validates fixed statement/proof framing before
dispatch, then returns the WASM verifier's boolean result. The client permits one
operation at a time, creates a fresh worker per operation, and terminates it on
success, failure, cancellation, timeout, or close. Cancellation terminates the
worker even while synchronous WASM is running. Late events cannot settle a later
request. The default timeout is 30 seconds; it is a local resource limit and does
not establish peer fault or protocol timeout attribution.

Generated WASM is not a source dependency. Build `candidate-transcript` and its
`pkg-transcript` bindings using the experiment README, then explicitly stage them:

```sh
node experiments/shuffle-backend/stage-web-candidate.mjs
PLAYWRIGHT_EXECUTABLE_PATH=/path/to/chromium \
  node experiments/shuffle-backend/run-web-shuffle.mjs
```

Staging writes ignored files under `apps/web/public/shuffle-candidate/`, including
a manifest of sizes and SHA-256 hashes. These hashes record the local artifacts;
they are not a release signature or independent review. Vite copies staged public
files into builds. Without staging, operations fail closed when the backend cannot
load. No remote backend URL is accepted. Development uses the configured base URL;
built workers resolve the staged files adjacent to the application's `assets/`
directory. The browser harness checks development and a relative production build
served under `/nested/`, including real proofs and cancellation followed by reuse.

## Ordered statement admission

The ledger requires a completed `SetupEnvelopeCoordinator`, the application's
admitted roster body, a safe round no earlier than setup, an agreed 36-card deck
specification, and a verifier. It checks the roster's game and four ordered seats
against setup, derives the roster hash itself, and takes the aggregate key from
setup. The caller still establishes agreement on roster, round, and deck policy.

The first input deck is derived from `CardPointTable` with identity A components;
it cannot be supplied by a peer. Seats contribute in order 0, 1, 2, 3. The candidate
signed `SHUFFLE` body has exactly two byte-string fields, `statement` and `proof`.
This body format is a candidate integration contract, not a frozen protocol profile.
The ledger rechecks the signature and game/round/phase/sender, validates bounded
body encodings, then checks game, round, seat, roster hash, aggregate key, and every
ordered input ciphertext against its current state before starting verification.
Only a true verifier result advances the deck. Backend errors, false results,
concurrent calls, and closure during verification cannot advance it. Exact signed
replays are idempotent. The final deck is available only after all four proofs.

The verifier is a trusted local dependency: tests can inject a fake verifier, while
the application adapter performs the actual candidate proof verification. A typed
ledger or its final deck is not a transferable cryptographic attestation.

## Remaining integration boundary

Signature and proof validation do not establish durable sender-chain admission.
The [durable shuffle receiver](shuffle-durability.md) now supplies sender-chain
admission, persistence, guarded local authoring, and proof-verifying recovery around
this ledger. Direct use of the ledger alone still lacks these guarantees.
The caller must close both ledger/receiver and client when abandoning a round:
ledger closure prevents stale state commits, while client
closure stops outstanding computation.

The existing reveal ledger can consume the final deck, but agreed dealer/deal
policies, coordinated readiness/control delivery, and reviewed profile
selection still gate live gameplay. Independent proof vectors and cryptographic
review remain required.
