# Candidate bounded 36-card shuffle API

Status: executable candidate, isolated from live gameplay. This is not a frozen
profile or an independently reviewed proof implementation. The Rust/WASM exports
require the `candidate-transcript` feature and bypass the experimental `Fixture`
decoder entirely.

## Public statement

`encodeCandidateShuffleStatement36` and `decodeCandidateShuffleStatement36` in
`@p2pcards/deck` implement this fixed canonical CBOR array:

```
[
  "bg-ristretto255-36-4x9-statement-candidate-v1", // text
  gameId,       // bstr16
  round,        // unsigned safe integer, minimal encoding
  seat,         // unsigned integer 0..3
  rosterHash,   // bstr32
  aggregateKey, // bstr32, canonical nonidentity Ristretto point
  inputDeck,    // bstr2304
  outputDeck    // bstr2304
]
```

Each deck contains exactly 36 ordered ciphertexts, each encoded as A32 || B32.
Components must be canonical Ristretto encodings; identity components are allowed
for the initial deck. Arrays, lengths, types, profile, and point encodings are
checked with a fixed grammar before calling the proof core. No general-purpose
CBOR decoder receives peer-controlled vector lengths. Round-zero statements use
4,749 bytes; the maximum safe round uses 4,757 bytes. There are no optional fields,
trailing bytes, peer-selected generators, dimensions, or phases.

The derived phase is `round.${round}.shuffle.${seat}`. The
[candidate transcript](shuffle-transcript.md) root is canonical CBOR of:

```
[bstr(statementProfile), bstr(crsProfile), bstr(proofCodecProfile),
 bstr(transcriptProfile), bstr(rosterHash), seat, bstr(G), bstr(proofGenerator)]
```

Game ID, round, and phase enter the existing application hash prefix. The proof
core appends the aggregate key, ordered input/output decks, and proof commitments
as specified by the transcript profile. This root differs intentionally from the
old evaluation fixture root; fixture proofs are not API proofs.

## Private prover input and results

Native Rust and WASM expose:

- `validate_candidate_shuffle_statement36(statement)`: structural admission only.
- `prove_candidate_shuffle36(statement, permutation, randomizers)`: returns the
  3,650-byte candidate proof after self-verification.
- `verify_candidate_shuffle36(statement, proof)`: returns true for a valid proof,
  false for a well-formed invalid proof, and an error for malformed input.

`encodeCandidateShuffleWitness36` converts a local `DeckShuffleWitness` into
36 permutation bytes and 1,152 randomizer bytes. Output position j uses input
position `permutation[j]`, with its own canonical nonzero scalar in little-endian
form. Rust checks lengths, bijection, scalars, and every ciphertext remasking
relation before drawing proof randomness. Proof randomness uses the OS/browser
cryptographic RNG. Private witnesses must stay local and never enter network
messages, logs, or transcript artifacts. This API does not guarantee memory
zeroization; worker lifecycle and private-material handling still need integration.

A valid proof does not establish roster membership, key ownership, the agreed
round/seat, or input-deck provenance. Callers must compare these against admitted
session state and the preceding verified shuffle before accepting output. The
initial deck must come from the agreed card-point table. The API accepts any
well-formed mathematical statement, including one with an untrusted roster hash.

## Verification and reproduction

`shuffle-statement.test.ts` covers fixed framing, integer boundaries, all
truncations, malformed headers/points, identity-key rejection, detached buffers,
and private witness encoding. Native tests also ensure invalid witnesses fail
before RNG access, and verify context/deck binding with a nonsymmetric permutation.

After building the native and `pkg-transcript` WASM artifacts using the experiment
README, run from `experiments/shuffle-backend`:

```sh
CARGO_TARGET_DIR=/path/to/target \
PLAYWRIGHT_EXECUTABLE_PATH=/path/to/chromium \
node run-shuffle-api.mjs
```

The runner prepares four sequential shuffles using TypeScript, proves each in
native Rust and a browser worker, and verifies both proofs in both runtimes. It
checks seven field mutations per proof/runtime, malformed proofs, invalid private
inputs, and shared statement admission cases. Private requests remain in memory;
the runner prints only counts. The `shuffle-api` CLI is a bounded local test
transport, not a peer-facing service.

Observed result: 8 proofs, 144 verification checks, 84 public-admission comparisons,
and 16 private-input rejections. This establishes compatibility and regression
coverage, not independent cryptographic correctness. Profile freeze, independent
proof vectors/review, and durable application integration remain open. The
[candidate application worker and signed ledger](shuffle-worker.md) now provide
cancellation and ordered statement checks against completed setup and prior decks.
