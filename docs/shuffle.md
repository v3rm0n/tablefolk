# Candidate 36-Card Bayer–Groth Shuffle Profile

Status: **executable candidate, integrated into the experimental Sasku match
path (`sasku-match-candidate@3`).** This profile and its Rust/WASM
implementation are **not** frozen for production and have **not** undergone
independent cryptographic review.

For build, staging, and cross-runtime verification commands, see
[experiments/shuffle-backend/README.md](../experiments/shuffle-backend/README.md).

---

## 1. Backend Selection Summary

Evaluation of candidate shuffle-proof libraries (pinned revisions assessed
2026-09-17):

| Candidate | Assessment & disposition |
| --- | --- |
| **Parity `mental-poker` (`ac4fb67b`)** | **Selected candidate.** MIT OR Apache-2.0; concrete Bayer–Groth `cards-proofs` core with WASM feasibility. Upstream `play` uses secp256k1 + `ark-transcript`; adapted locally with a `curve25519-dalek` 4.1.3 / `ark-ed25519` 0.5.0 Ristretto255 backend, deterministic 4×9 CRS, strict CBOR proof codec, and SHA-512/CBOR transcript (`experiments/shuffle-backend/vendor/cards-proofs`). |
| Swiss Post `crypto-primitives` (`94a84386`) | Apache-2.0, documented vectors and external review history, but Java + finite-field ElGamal + SHA3-256. Kept as an algorithmic reference only; upstream review does not transfer to a port. |
| Geometry `proof-toolbox` (`ada58736`) | MIT OR Apache-2.0, older fork without Ristretto and with open transcript-serialization issue (#7). Superseded by Parity's newer fork. |
| `ercembu/elgamal-shuffle` (`5c1addd9`) | GPLv3; **rejected**—`CommonRef::new` clones one sampled point across commitment bases and `append_cipher_vec` drops bytes from the transcript. |

### Exact adaptation boundary

`experiments/shuffle-backend/vendor/cards-proofs` keeps all upstream proof
equations and transcript append call sites unchanged (verified by
`source-manifest.json` via `node experiments/shuffle-backend/verify-vendor.mjs`).
Local changes are documented in
[UPSTREAM.md](../experiments/shuffle-backend/vendor/cards-proofs/UPSTREAM.md):
replacing `ark-transcript` with the SHA-512/CBOR transcript below, disabling
unused Schnorr/DLEQ modules, and sampling the matrix-product private blinder
directly from `Rng + CryptoRng` via `Scalar::rand`.

---

## 2. Deterministic 4×9 CRS

- **Profile ID:** `bg-ristretto255-36-4x9-crs-candidate-v1`
- **Matrix:** `m = 4`, `n = 9` (36 cards). Encryption generator is canonical
  Ristretto255 base `G`.
- **Derived bases (11 total, in order):**
  1. `role = "proof", index = 0` — backend's additional proof generator
  2. `role = "blinding", index = 0` — Pedersen randomness base `h`
  3. `role = "message", index = 0..8` — Pedersen bases `g[0]..g[8]`
- **Derivation:**
  ```text
  digest = SHA-512(
    ASCII("p2pcards/v1/shuffle") ||
    cbor(["crs", "bg-ristretto255-36-4x9-crs-candidate-v1", 4, 9, role, index])
  )
  point  = RistrettoPoint.fromUniformBytes(digest)
  ```
- **Rejection rule:** reject the entire CRS if any base is identity, equals
  `±G`, or equals any preceding base or its negation (never retry or fall back).
- **Vector commitment:** `r*h + sum(x[i]*g[i])` for up to 9 scalars (shorter
  vectors use the matching prefix).
- **Implementation & fixtures:** `deriveShuffleCrs36` in `@p2pcards/deck`,
  independent Rust implementation in `experiments/shuffle-backend/src/crs.rs`,
  regression vectors in `packages/deck/test-vectors/shuffle-crs-36.json`.

---

## 3. Wire Proof Codec (3,650 Bytes)

- **Profile ID:** `bg-ristretto255-36-4x9-proof-candidate-v1`
- **Grammar:** one Core Deterministic CBOR value, **exact length 3,650 bytes**
  (fixed headers `82`, `78 29`, `98 6a`, and 106 × `58 20` 32-byte strings):
  ```text
  ["bg-ristretto255-36-4x9-proof-candidate-v1", [element[0], ..., element[105]]]
  ```
- Every element is a canonical 32-byte Ristretto point or canonical LE scalar
  `< q` (identity points and zero scalars are permitted by the proof algebra).
  Decoders validate the fixed grammar and every element before allocating or
  translating to the 3,480-byte internal Arkworks representation (where all 11
  vector lengths are inserted from constants).

### Element order (matching Parity `cards-proofs` `ac4fb67b`)

| Indices | Subproof / field(s) | Encoding |
| --- | --- | --- |
| 0–3 | shuffle `a_commits` | 4 points |
| 4–7 | shuffle `b_commits` | 4 points |
| 8 | product `b_commit` | 1 point |
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
| 68 | multi-exponentiation `a_0_commit` | 1 point |
| 69–76 | multi-exponentiation `commit_b_k` | 8 points |
| 77–92 | multi-exponentiation `vector_e_k` | 8 ciphertexts (`A`, then `B`) |
| 93–96 | multi-exponentiation `r_blinded`, `b_blinded`, `s_blinded`, `tau_blinded` | 4 scalars |
| 97–105 | multi-exponentiation `a_blinded` | 9 scalars |

---

## 4. SHA-512/CBOR Fiat–Shamir Transcript

- **Profile ID:** `bg-ristretto255-36-4x9-fs-candidate-v1`
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
- **Bounds:** `<= 1,024` root bytes, `<= 64` label bytes, `<= 8,192` bytes per
  append, `<= 128` events, `<= 32,768` total event bytes, `<= 16` reads per
  challenge.
- **Reference vectors:** `packages/deck/test-vectors/shuffle-transcript.json`
  (generated independently in Python stdlib).

### Exact 8-step challenge sequence

| Label(s) added | Public values appended (in order) | Challenge reads |
| --- | --- | --- |
| `shuffle_argument` | aggregate key, commitment key, input deck, output deck, `m=4`, `n=9`, `a_commits` | `x[0]` |
| *(none)* | `b_commits` | `yz[0]`, `yz[1]` |
| `matrix_elements_product`, `hadamard_product_argument` | commitment key, `m`, `n`, Hadamard `b_commits` | `xy[0]`, `xy[1]` |
| `zero_argument` | commitment key, `m`, `n`, `a_0_commit`, `b_m_commit`, statement `A` commits, statement `B` commits, committed diagonals | `x[0]` |
| `single_value_product_argument` | commitment key, statement `a_commit`, `d_commit`, `delta_commit`, `diff_commit` | `x[0]` |
| `multi-exponentiation` | aggregate key, commitment key, exponent commits, product ciphertext, shuffled matrix, `[m, n, 2m-1]`, `a_0_commit`, `commit_b_k`, `vector_e_k` | `x_powers[0]` |

---

## 5. Bounded Statement & Rust/WASM API

- **Profile ID:** `bg-ristretto255-36-4x9-statement-candidate-v1`
- **Public statement** (canonical CBOR array, 4,749–4,757 bytes, no optional
  fields):
  ```text
  [
    "bg-ristretto255-36-4x9-statement-candidate-v1",
    gameId,        // bstr(16)
    round,         // unsigned safe integer
    seat,          // 0..3
    rosterHash,    // bstr(32)
    aggregateKey,  // bstr(32), canonical non-identity Ristretto point
    inputDeck,     // bstr(2304), 36 × (A32 || B32)
    outputDeck     // bstr(2304), 36 × (A32 || B32)
  ]
  ```
- **Derived phase:** `round.${round}.shuffle.${seat}`.
- **API transcript root** (binds generators omitted by upstream):
  ```text
  cbor([
    bstr(statementProfile), bstr(crsProfile), bstr(proofCodecProfile),
    bstr(transcriptProfile), bstr(rosterHash), seat, bstr(G), bstr(proofGenerator)
  ])
  ```
- **Private witness** (local only; never transmitted, logged, or persisted):
  36-byte permutation (`output[j]` comes from `input[permutation[j]]`) +
  1,152-byte randomizers (36 canonical non-zero LE scalars). Rust checks
  bijection, scalars, and all 36 remasking equations before accessing RNG, and
  self-verifies every generated proof.
- **Rust/WASM exports** (`candidate-transcript` feature):
  - `validate_candidate_shuffle_statement36(statement)` — structural admission
  - `prove_candidate_shuffle36(statement, permutation, randomizers)` — returns 3,650-byte proof
  - `verify_candidate_shuffle36(statement, proof)` — returns boolean (or error on malformed input)
- **Signed envelope body:** `SHUFFLE` carries `{statement, proof}` (two byte
  strings). Mathematical validity does not prove roster membership, key
  ownership, or input-deck provenance; `CandidateShuffleLedger` checks those
  against completed setup and the preceding verified deck (starting from
  `CardPointTable` with identity `A` components).

---

## 6. Open Cryptographic Gates

1. Freeze the complete profile (and specify layouts beyond 4×9 if supporting
   other deck sizes).
2. Produce implementation-independent positive and rejection proof vectors
   (current cross-runtime tests exercise the same adapted Rust core natively
   and in WASM, plus independent Python/TS challenge-derivation checks).
3. Independently review the `vendor/cards-proofs` adaptation, constant-time /
   secret-memory behavior, and RNG usage before making public security claims.
