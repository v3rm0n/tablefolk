# Candidate SHA-512/CBOR Shuffle Transcript

Status: an executable, isolated candidate for the 36-card 4×9 Ristretto proof.
It is not a frozen production profile or independently reviewed implementation.
The `candidate-transcript` feature selects it explicitly; existing modes retain
`ark-transcript`. Proofs are intentionally incompatible between the two modes.

## Exact challenge framing

Profile bytes: ASCII `bg-ristretto255-36-4x9-fs-candidate-v1`.
Every challenge uses the existing application `proofChallengeInput("shuffle", …)`
framing:

```
ASCII("p2pcards/v1/shuffle") || game_id[16] || CBOR(round) || CBOR(phase) ||
CBOR([bstr(profile), bstr(root), events, [2, bstr(challenge_label), index]])
```

All CBOR is Core Deterministic encoding. `round` is an unsigned safe integer,
`phase` is a nonempty ASCII text string of at most 64 bytes, and `game_id` is
exactly 16 bytes. Labels and profile identifiers inside the statement are byte
strings, not CBOR text. Root and all event buffers are captured on admission.

Hash the complete input with SHA-512. Interpret all 64 digest bytes as one
little-endian integer and reduce modulo the Ristretto scalar order. Zero is
allowed, as with the existing wide-reduction challenge primitive. This is not
upstream's `read_uniform` algorithm, despite preserving that internal method name.

Before returning the scalar, append the response event:

```
[2, bstr(challenge_label), index, bstr(canonical_scalar_le32)]
```

The next read of the same challenge increments the index, starting at zero.
Every later challenge includes all preceding labels, public values, and responses.
The public event types are `[0, bstr(label)]` and `[1, bstr(serialized_value)]`.
The verifier recomputes responses; none are trusted from a peer.

## Root and public serialization

The legacy evaluation fixture root is canonical CBOR of five byte strings, in order:

1. The candidate CRS profile identifier.
2. The candidate proof codec identifier.
3. The complete local evaluation context string.
4. The compressed encryption generator G.
5. The compressed additional proof generator.

The bounded prover/verifier API uses the separate eight-field root and derived
round/seat phase specified in [shuffle-api.md](shuffle-api.md). It directly admits
the 16-byte game ID and safe round; the local text conversion below applies only
to legacy fixture evaluation. The two roots intentionally produce different proofs.

The local context has form `shuffle-evaluation/game-a/round-0/shuffle-0`.
The harness obtains the 16-byte test game ID from the first 16 bytes of SHA-256
of `game-a`, parses the unsigned round, and uses `shuffle-0` as phase. Changed
game/round/seat tests alter these components. This conversion is a **local fixture
adapter**, not a live invitation, roster, or signed-envelope context parser.
Final production context/seat/statement admission remains required.

The root explicitly binds the two generators omitted by upstream's outer
shuffle transcript appends. The proof core appends the aggregate key, commitment
key, ordered decks, dimensions, commitments, and derived subproof statements.

This candidate deliberately preserves each pinned upstream compressed public
serialization **inside a CBOR byte string**. It does not silently treat that
serialization as canonical CBOR. Its byte grammar is:

- Ristretto points: canonical 32-byte encodings; ciphertexts: A then B.
- Scalars: canonical 32-byte little-endian values, when present in responses.
- `u32` dimensions: four little-endian bytes. Fixed arrays concatenate elements.
- Vectors: eight-byte little-endian count, then ordered encoded elements.
- Commitment key: h, vector count 9, then the nine g bases (328 bytes).
- Ciphertext matrices: outer vector count followed by each encoded row vector.

Input and output decks each encode to 2,312 bytes. The 4×9 shuffled matrix
encodes to 2,344 bytes. These inner encodings are explicitly part of this
candidate; changing them requires a different transcript profile.

## Exact proof sequence

The table lists every public append between challenge reads. Earlier events and
responses always remain in the transcript. All field names refer to the pinned
upstream argument definitions. The additional `matrix_elements_product` label
precedes `hadamard_product_argument` without intervening public appends.

| Label(s) added | Public values appended, in order | Challenge reads |
| --- | --- | --- |
| `shuffle_argument` | aggregate key, commitment key, input deck, output deck, m=4, n=9, `a_commits` | `x[0]` |
| none | `b_commits` | `yz[0]`, then `yz[1]` |
| `matrix_elements_product`, `hadamard_product_argument` | commitment key, m, n, Hadamard `b_commits` | `xy[0]`, then `xy[1]` |
| `zero_argument` | commitment key, m, n, `a_0_commit`, `b_m_commit`, statement commitments to A, statement commitments to B, committed diagonals | `x[0]` |
| `single_value_product_argument` | commitment key, statement `a_commit`, `d_commit`, `delta_commit`, `diff_commit` | `x[0]` |
| `multi-exponentiation` | aggregate key, commitment key, commitments to exponents, product ciphertext, shuffled matrix, fixed `[m,n,2m-1]`, `a_0_commit`, `commit_b_k`, `vector_e_k` | `x_powers[0]` |

There are eight scalar challenge reads. The pinned equations derive and verify
the subproof statements; TypeScript transcript replay alone does not independently
verify those equations or their soundness.

## Implementation boundary and randomness

`CandidateShuffleTranscript` in `@p2pcards/deck` implements framing, reduction,
response absorption, mutation isolation, and stale-reader rejection. Limits are
1,024 root bytes, 64 label bytes, 8,192 bytes per append, 128 events, 32,768 total
encoded event bytes, and 16 reads per challenge. Fixed candidate proofs stay
within these bounds. Rust applies corresponding invariant checks to the trusted
proof-core call sequence; this is not an untrusted generic event interpreter.

The attributed copy under `experiments/shuffle-backend/vendor/cards-proofs`
changes the transcript export and adds this transcript. It disables unrelated
Schnorr/Chaum-Pedersen modules. The one matrix-product private blinder previously
sampled with `fork(...).witness(...)` is now sampled directly with `Scalar::rand`
from the supplied `Rng + CryptoRng`; it is never derived as a public challenge.
Other randomness and all proof equations/append call sites are unchanged.
The source hash manifest identifies the exact local changes and upstream origin.

Generation checks that prover and verifier produce byte-identical eight-step
challenge histories. Consequently, this mode's preparation-plus-proving timing
also includes that verification, unlike the older experiment timings.

## Evidence and remaining gates

- Python standard-library CBOR framing, hashlib SHA-512, and integer arithmetic
  independently produce eight fixed challenge vectors. TypeScript, native Rust,
  and browser WASM match them.
- TypeScript reconstructs all events and responses for 64 actual proof challenge
  records from eight native/browser assessments, matching input, hash, and scalar.
- The adapted mode passes 128 proof acceptance/rejection checks, 373 codec cases
  in three runtimes, 22 CRS comparisons, and 380 arithmetic adapter comparisons.
- Genuine proofs are accepted by their own transcript profile and rejected by
  the other profile in both directions, for initial and masked decks.

This is independent challenge derivation agreement, not independent proof
implementation or cryptographic review. The outer fixture parser remains
experimental. Before live integration, replace fixture context/statement handling
with bounded typed admission, freeze the complete profile, produce independent
proof vectors, and review the adaptation and secret-dependent operations. Decoding
or hashing a transcript cannot establish verified shuffle provenance by itself.
