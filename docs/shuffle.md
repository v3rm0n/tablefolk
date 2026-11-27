# Bayer–Groth Shuffle Profile v2

The executable candidate profile supports matrices with integer dimensions
`m, n >= 2` and `m * n <= 128`. Regression coverage includes 4×9 (36 cards)
and 4×13 (52 cards). The Sasku browser match uses 4×9 in
`sasku-match-candidate@4`. This profile and its Rust/WASM implementation
have yet to undergo an independent cryptographic audit.
See [D6 in decisions.md](decisions.md#d6--replace-external-audit--second-reference-gate-with-soundness-vectors-self-audit-and-disclaimer).

For build, staging, and cross-runtime verification commands, see
[crates/shuffle-wasm/README.md](../crates/shuffle-wasm/README.md).

---

## 1. Backend Selection Summary

Evaluation of candidate shuffle-proof libraries (pinned revisions assessed
2026-09-17):

| Candidate | Assessment & disposition |
| --- | --- |
| **Parity `mental-poker` (`ac4fb67b`)** | **Selected candidate.** MIT OR Apache-2.0; concrete Bayer–Groth `cards-proofs` core with WASM feasibility. Upstream `play` uses secp256k1 + `ark-transcript`; adapted locally with a `curve25519-dalek` 4.1.3 / `ark-ed25519` 0.5.0 Ristretto255 backend, dimension-scoped deterministic CRS, strict CBOR proof codec, and SHA-512/CBOR transcript (`crates/shuffle-wasm/vendor/cards-proofs`). |
| Swiss Post `crypto-primitives` (`94a84386`) | Apache-2.0, documented vectors and external review history, but Java + finite-field ElGamal + SHA3-256. Kept as an algorithmic reference only; upstream review does not transfer to a port. |
| Geometry `proof-toolbox` (`ada58736`) | MIT OR Apache-2.0, older fork without Ristretto and with open transcript-serialization issue (#7). Superseded by Parity's newer fork. |
| `ercembu/elgamal-shuffle` (`5c1addd9`) | GPLv3; **rejected**—`CommonRef::new` clones one sampled point across commitment bases and `append_cipher_vec` drops bytes from the transcript. |

### Exact adaptation boundary

`crates/shuffle-wasm/vendor/cards-proofs` keeps all upstream proof
equations and transcript append call sites unchanged (verified by
`source-manifest.json` via `node crates/shuffle-wasm/verify-vendor.mjs`).
Local changes are documented in
[UPSTREAM.md](../crates/shuffle-wasm/vendor/cards-proofs/UPSTREAM.md):
replacing `ark-transcript` with the SHA-512/CBOR transcript below, disabling
unused Schnorr/DLEQ modules, and sampling the matrix-product private blinder
directly from `Rng + CryptoRng` via `Scalar::rand`.

---

## 2. Deterministic CRS

- **Profile ID:** `bg-ristretto255-crs-candidate-v2`
- **Encryption generator:** canonical Ristretto255 base `G`.
- **Derived bases (`n + 2` total, in order):**
  1. `role = "proof", index = 0` — backend's additional proof generator
  2. `role = "blinding", index = 0` — Pedersen randomness base `h`
  3. `role = "message", index = 0..n-1` — Pedersen bases `g[0]..g[n-1]`
- **Derivation:**
  ```text
  digest = SHA-512(
    ASCII("p2pcards/v1/shuffle") ||
    cbor(["crs", "bg-ristretto255-crs-candidate-v2", m, n, role, index])
  )
  point  = RistrettoPoint.fromUniformBytes(digest)
  ```
- **Rejection rule:** reject the entire CRS if any base is identity, equals
  `±G`, or equals any preceding base or its negation (never retry or fall back).
- **Vector commitment:** `r*h + sum(x[i]*g[i])` for up to `n` scalars (shorter
  vectors use the matching prefix).
- **Implementation & fixtures:** `deriveShuffleCrs` in `@p2pcards/deck`,
  independent Rust implementation in `crates/shuffle-wasm/src/crs.rs`,
  regression vectors in `packages/deck/test-vectors/shuffle-crs-{36,52}.json`.

---

## 3. Wire Proof Codec

- **Profile ID:** `bg-ristretto255-proof-candidate-v2`
- **Grammar** (Core Deterministic CBOR):
  ```text
  ["bg-ristretto255-proof-candidate-v2", m, n, [element[0], ..., element[k-1]]]
  ```
  With `k = 11m + 5n + 17`, a 4×9 proof contains 106 elements (3,645 bytes)
  and a 4×13 proof contains 126 elements (4,325 bytes).
- Every element is a canonical 32-byte Ristretto point or canonical LE scalar
  `< q`. Identity points and zero scalars are allowed by the proof algebra.
  The decoder checks the proof dimensions against the statement, the exact
  length, and the canonical element encoding. The Rust codec supplies the
  11 Arkworks vector lengths from the validated dimensions.

### Element order (matching Parity `cards-proofs` `ac4fb67b`)

| Subproof / field(s) | Encoding |
| --- | --- |
| Shuffle `a_commits` | `m` points |
| Shuffle `b_commits` | `m` points |
| Product `b_commit` | 1 point |
| Hadamard `b_commits` | `m` points |
| Zero `a_0_commit`, `b_m_commit` | 2 points |
| Zero `vector_of_committed_diagonals` | `2m + 1` points |
| Zero `a_blinded` | `n` scalars |
| Zero `b_blinded` | `n` scalars |
| Zero `r_blinded`, `s_blinded`, `t_blinded` | 3 scalars |
| Single product `d_commit`, `delta_commit`, `diff_commit` | 3 points |
| Single product `a_blinded` | `n` scalars |
| Single product `b_blinded` | `n` scalars |
| Single product `r_blinded`, `s_blinded` | 2 scalars |
| Multi-exponentiation `a_0_commit` | 1 point |
| Multi-exponentiation `commit_b_k` | `2m` points |
| Multi-exponentiation `vector_e_k` | `2m` ciphertexts, each `A` then `B` |
| Multi-exponentiation `r_blinded`, `b_blinded`, `s_blinded`, `tau_blinded` | 4 scalars |
| Multi-exponentiation `a_blinded` | `n` scalars |

---

## 4. SHA-512/CBOR Fiat–Shamir Transcript

- **Profile ID:** `bg-ristretto255-fs-candidate-v2`
- **Challenge derivation:** uses the protocol's `p2pcards/v1/shuffle` prefix:
  ```text
  input = ASCII("p2pcards/v1/shuffle") || game_id[16] || cbor(round) || cbor(phase) ||
          cbor([bstr(profile), bstr(root), events, [2, bstr(label), index]])
  scalar = LE512_TO_INT(SHA-512(input)) mod q
  ```
- **Event types:** `[0, bstr(label)]` (label), `[1, bstr(value)]` (public value),
  and `[2, bstr(label), index, bstr(scalar_le32)]` (response absorbed
  immediately after each challenge read; `index` starts at `0` per label).
- **Inner public serialization** (carried inside CBOR byte strings): 32-byte
  Ristretto points, ciphertexts as `A32 || B32`, `u32` as 4-byte LE, vector
  lengths as 8-byte LE counts (commitment key = 328 B, decks = 2,312 B each,
  4×9 shuffled matrix = 2,344 B).
- **Bounds:** `<= 1,024` root bytes, `<= 64` label bytes, `<= 8,712` bytes per
  append, `<= 128` events, `<= 65,536` total event bytes, `<= 16` reads per
  challenge.
- **Reference vectors:** `packages/deck/test-vectors/shuffle-transcript.json`
  (generated independently in Python stdlib).

### Exact 8-step challenge sequence

| Label(s) added | Public values appended (in order) | Challenge reads |
| --- | --- | --- |
| `shuffle_argument` | aggregate key, commitment key, input deck, output deck, `m`, `n`, `a_commits` | `x[0]` |
| *(none)* | `b_commits` | `yz[0]`, `yz[1]` |
| `matrix_elements_product`, `hadamard_product_argument` | commitment key, `m`, `n`, Hadamard `b_commits` | `xy[0]`, `xy[1]` |
| `zero_argument` | commitment key, `m`, `n`, `a_0_commit`, `b_m_commit`, statement `A` commits, statement `B` commits, committed diagonals | `x[0]` |
| `single_value_product_argument` | commitment key, statement `a_commit`, `d_commit`, `delta_commit`, `diff_commit` | `x[0]` |
| `multi-exponentiation` | aggregate key, commitment key, exponent commits, product ciphertext, shuffled matrix, `[m, n, 2m-1]`, `a_0_commit`, `commit_b_k`, `vector_e_k` | `x_powers[0]` |

---

## 5. Bounded Statement & Rust/WASM API

- **Profile ID:** `bg-ristretto255-statement-candidate-v2`
- **Public statement** (canonical CBOR array):
  ```text
  [
    "bg-ristretto255-statement-candidate-v2",
    m, n,          // unsigned dimensions
    gameId,        // bstr(16)
    round,         // unsigned safe integer
    seat,          // 0..3
    rosterHash,    // bstr(32)
    aggregateKey,  // bstr(32), canonical non-identity Ristretto point
    inputDeck,     // bstr(64*m*n), ordered A32 || B32 pairs
    outputDeck     // same encoding as inputDeck
  ]
  ```
- **Derived phase:** `round.${round}.shuffle.${seat}`.
- **API transcript root** (binds generators omitted by upstream):
  ```text
  cbor([
    bstr(statementProfile), bstr(crsProfile), bstr(proofCodecProfile),
    bstr(transcriptProfile), [m, n], bstr(rosterHash), seat, bstr(G), bstr(proofGenerator)
  ])
  ```
- **Private witness** is local. The permutation contains `m*n` bytes, where
  `output[j]` comes from `input[permutation[j]]`. The randomizers contain
  `m*n` canonical non-zero LE scalars. Rust checks bijection, scalars, and
  every remasking equation before accessing RNG and self-verifies each proof.
- **Rust/WASM exports:**
  - `validate_candidate_shuffle_statement(statement)` checks structural admission.
  - `prove_candidate_shuffle(statement, permutation, randomizers)` returns
    a proof for the statement dimensions.
  - `verify_candidate_shuffle(statement, proof)` returns whether the proof
    verifies and raises an error on malformed input.
- **Signed envelope body** is `{outputDeck, proof}`. Both fields are byte
  strings. The prover and verifier construct the full canonical statement
  from the agreed matrix, game, round, expected seat, roster hash, aggregate
  key, and preceding verified deck. The first input deck comes from the
  agreed card table with identity `A` components. The 36-card v2 body is
  5,973 bytes, down 2,449 bytes (29%) from the minimum-sized v1 body.
  Legacy full-statement bodies and v1 proofs are rejected by the v2 profile.

---

## 6. Open Cryptographic Gates

1. Expand cross-runtime (native Rust, browser WASM, and independent Python/TS
   challenge-derivation checks), mutation, and soundness test vectors covering
   positive proofs and negative/tampered-statement rejections.
2. Complete a focused self-audit of the `vendor/cards-proofs` adaptation,
   secret-memory zeroization, and RNG usage, and keep a transparent disclaimer
   that the cryptography has not undergone an independent external audit.
