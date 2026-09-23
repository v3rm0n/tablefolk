# Candidate 36-card Proof Encoding

Status: implemented candidate codec for the pinned 4×9 Ristretto proof structure.
This is not the final SHUFFLE message or a proof verifier. The production
Fiat-Shamir transcript now has an [executable candidate](shuffle-transcript.md).
Production statement/context admission, full-profile freeze, independent proof
vectors, and review remain outstanding.

## Wire grammar

Exactly one deterministic CBOR value:

```
["bg-ristretto255-36-4x9-proof-candidate-v1", [element[0], ..., element[105]]]
```

Each element is a canonical 32-byte byte string, holding either a compressed
Ristretto point or a canonical little-endian scalar below the group order.
Identity points and zero scalars are allowed: the proof algebra uses both.
Scalar encodings are checked, never reduced. Point encodings are validated,
never interpreted as Edwards encodings. Proof equations impose additional
constraints separately.

The outer array uses `82`, the 41-byte ASCII profile uses `78 29`, the inner
106-element array uses `98 6a`, and every byte string uses `58 20`. The total
encoding is exactly **3,650 bytes**. No optional fields, tags, indefinite lengths,
alternative integer/length encodings, suffixes, or other layouts are accepted.

## Exact element order

Indices are zero-based and correspond to the declaration/serialization order in
Parity `cards-proofs` revision `ac4fb67b612aa89f37f6be72ea74a3c13eff66ca`.

| Indices | Nested field(s), in order | Encoding |
| --- | --- | --- |
| 0–3 | shuffle `a_commits` | 4 points |
| 4–7 | shuffle `b_commits` | 4 points |
| 8 | product `b_commit` | point |
| 9–12 | Hadamard `b_commits` | 4 points |
| 13–14 | zero `a_0_commit`, `b_m_commit` | 2 points |
| 15–23 | zero `vector_of_committed_diagonals` | 9 points |
| 24–32 | zero `a_blinded` | 9 scalars |
| 33–41 | zero `b_blinded` | 9 scalars |
| 42–44 | zero `r_blinded`, `s_blinded`, `t_blinded` | 3 scalars |
| 45–47 | single product `d_commit`, `delta_commit`, `diff_commit` | 3 points |
| 48–56 | single product `a_blinded` | 9 scalars |
| 57–65 | single product `b_blinded` | 9 scalars |
| 66–67 | single product `r_blinded`, `s_blinded` | 2 scalars |
| 68 | multi-exponentiation `a_0_commit` | point |
| 69–76 | multi-exponentiation `commit_b_k` | 8 points |
| 77–92 | multi-exponentiation `vector_e_k` | 8 ciphertexts, each A then B |
| 93–96 | multi-exponentiation `r_blinded`, `b_blinded`, `s_blinded`, `tau_blinded` | 4 scalars |
| 97–105 | multi-exponentiation `a_blinded` | 9 scalars |

Ciphertext components are points. Vector order is preserved exactly. Nothing is
sorted, omitted, or inferred from a peer-supplied size. The profile identifier
selects the fixed dimensions and schema; it does not claim cryptographic validity.

## Implementations and bounds

`encodeCandidateShuffleProof36` / `decodeCandidateShuffleProof36` in
`@p2pcards/deck` operate on the 106 encoded elements. The decoder checks the exact
size before allocation, then checks the literal CBOR grammar and validates each
field. It does not pass attacker-selected nesting or lengths to the generic CBOR
decoder. Both directions detach buffers; the returned array is frozen, and its
byte buffers are caller-owned.

`experiments/shuffle-backend/src/proof_codec.rs` independently implements this
grammar. It translates to the pinned Arkworks representation only after checking
the wire size, headers, and encodings. All eleven Arkworks vector counts are
inserted from constants, producing exactly 3,480 bytes before invoking the generic
proof deserializer. Encoding checks those same vector counts before removing
their prefixes. This also covers the backend's crate-private subproof fields
without modifying upstream proof code.

The `candidate-crs` harness round-trips each proof through this codec before
assessment. Native/WASM `roundtrip_candidate_proof36` is a bounded structural
codec API. `candidate_proof_from_fixture` remains a conversion helper for trusted
local fixtures: its outer experimental fixture decoder is still generic and is
**not** an untrusted-input entry point.

## Verification

- 115 TypeScript cases cover canonical-CBOR equivalence, exact field types,
  every truncation, malformed headers/encodings, scalar modulus boundaries,
  unknown profiles, counts, buffer isolation, and zero/identity support.
- Four additional native tests cover the grammar, all truncations, every invalid
  field/header, and all eleven forged Arkworks vector lengths before decoding.
- 373 shared cases agree in TypeScript, native Rust, and browser WASM (1,119
  comparisons), including genuine proofs, structural-only zero fixtures, and
  malformed encodings. Browser-generated proofs also round-trip in TypeScript.
- The candidate's 128 cross-runtime proof acceptance/rejection checks still pass
  after codec round-tripping. These use the same upstream proof implementation
  in native and WASM, not independent proof implementations.

Generated public fixtures and full case results are recorded under the ignored
`experiments/shuffle-backend/results-crs/` directory. Changes to field semantics,
ordering, dimensions, or grammar require a new codec profile identifier. The
final production profile must identify its transcript as well as its encoding;
this candidate identifier is not sufficient to negotiate a live protocol.
