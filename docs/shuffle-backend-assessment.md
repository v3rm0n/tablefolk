# Verifiable-Shuffle Backend Assessment

Date: 2026-09-17. Status: **No production backend selected.**

## Required Compatibility

The selected protocol uses ElGamal over Ristretto255, canonical 32-byte point and
scalar encodings, and Bayer-Groth with a fully specified SHA-512/CBOR Fiat-Shamir
transcript. The first target is a 36-card deck, proved and verified off-main-thread
in a browser. The proof must bind the aggregate key, exact ordered input/output
decks, agreed parameters, game, round, and shuffle phase.

The generic challenge framing does not specify Bayer-Groth's individual rounds,
matrix ordering, Pedersen generators, or proof serialization. A library with the
same proof-system name is not sufficient for byte-level compatibility.

## Source-Based Findings

These findings concern the pinned revisions below. Parity's proof core has now
been exercised natively and in browser WASM as described below; other candidates
remain source-only assessments. This is not a cryptographic audit or proof that
no other suitable implementation exists.

| Candidate | Useful evidence | Compatibility gap / disposition |
| --- | --- | --- |
| [Parity mental-poker, `ac4fb67b`](https://github.com/paritytech/mental-poker/tree/ac4fb67b612aa89f37f6be72ea74a3c13eff66ca) | MIT OR Apache-2.0; concrete Bayer-Groth composition, proof serialization, WASM shuffle exports, and reported browser use. | Best implementation-feasibility candidate. Browser-facing `play` uses secp256k1, Arkworks serialization, and `ark-transcript`; no supplied Ristretto backend or independent review covering the intended adaptation was established. Dimension selection gives 6×6 for 36 cards. |
| [Swiss Post crypto-primitives, `94a84386`](https://gitlab.com/swisspost-evoting/crypto-primitives/crypto-primitives/-/tree/94a843861b0f876a194cb16f09c9a800e16d0ebd) | Apache-2.0; concrete shuffle argument, documented independently generated vectors, and a changelog recording named external expert feedback. | Useful separate algorithmic/rejection-test reference. Java, multiplicative finite-field ElGamal, and recursive SHA3-256 hashing; not browser/Ristretto-compatible. Upstream review does not transfer to a port. |
| [Geometry proof-toolbox, `ada58736`](https://github.com/geometryxyz/proof-toolbox/tree/ada587360d8630942f474c53000cb24212c6a300) | MIT OR Apache-2.0; concrete Bayer-Groth verifier and WASM-related configuration. | Older reference, no supplied Ristretto instance. [Issue #7](https://github.com/geometryxyz/proof-toolbox/issues/7) reports projective-coordinate transcript-serialization concerns. Prefer evaluating the newer fork, without assuming every inherited issue is fixed. |
| [ercembu/elgamal-shuffle, `5c1addd9`](https://github.com/ercembu/elgamal-shuffle/tree/5c1addd95224eb1505865cb40307fa4e415c32d9) | Actual Ristretto/Bayer-Groth-style code; GPLv3 license text. | Not an adoption candidate: the inspected `CommonRef::new` clones a single sampled point across vector commitment bases, and `append_cipher_vec` computes bytes without appending them to the transcript. Matching the group does not establish soundness. |

Relevant implementation entry points:

- [Parity curve choice](https://github.com/paritytech/mental-poker/blob/ac4fb67b612aa89f37f6be72ea74a3c13eff66ca/play/src/lib.rs)
  and [WASM shuffle exports](https://github.com/paritytech/mental-poker/blob/ac4fb67b612aa89f37f6be72ea74a3c13eff66ca/play/src/shuffle.rs).
- [Swiss Post ShuffleArgumentService](https://gitlab.com/swisspost-evoting/crypto-primitives/crypto-primitives/-/blob/94a843861b0f876a194cb16f09c9a800e16d0ebd/src/main/java/ch/post/it/evoting/cryptoprimitives/internal/mixnet/ShuffleArgumentService.java)
  and [review/change history](https://gitlab.com/swisspost-evoting/crypto-primitives/crypto-primitives/-/blob/94a843861b0f876a194cb16f09c9a800e16d0ebd/CHANGELOG.md).
- [Ristretto candidate commitment bases](https://github.com/ercembu/elgamal-shuffle/blob/5c1addd95224eb1505865cb40307fa4e415c32d9/src/arguers.rs)
  and [transcript helpers](https://github.com/ercembu/elgamal-shuffle/blob/5c1addd95224eb1505865cb40307fa4e415c32d9/src/utils/transcript.rs).

## Initial secp256k1 Native/Browser Feasibility

The standalone [evaluation harness](../experiments/shuffle-backend/README.md)
pins the upstream revision, Rust 1.90.0, wasm-bindgen 0.2.100, and Cargo dependency
lockfile. It invokes the unchanged generic `cards-proofs` core using secp256k1,
matching the curve used by upstream `play`. It does not test every `cards-play`
wrapper or the complete upstream game protocol.

On 2026-09-17, native macOS ARM64 and Brave/Chromium 153.0.8010.37 passed:

- 36-card 4×9 and 6×6 layouts, each with initial `(O, M)` and already masked input;
- native proofs verified in a browser module worker, and worker-generated proofs
  verified natively, with identical complete assessment reports in both directions;
- **256 expected acceptance/rejection results** across four configurations and
  four assessment paths. Checks cover deck content/order, key, encryption/proof
  generators, commitment parameters, proof commitment, statement length, context,
  and proof byte truncation/exact consumption.

Representative timings from that initial evaluation (milliseconds):

| Matrix / input | Proof bytes | Native prepare + prove | Browser prepare + prove | Native assessment | Browser assessment |
| --- | ---: | ---: | ---: | ---: | ---: |
| 4×9 / initial | 3,532 | 50.6 | 99.0 | 50.1 | 96.1 |
| 4×9 / masked | 3,532 | 54.3 | 106.2 | 56.9 | 110.4 |
| 6×6 / initial | 3,778 | 62.5 | 117.8 | 55.2 | 105.1 |
| 6×6 / masked | 3,778 | 68.3 | 125.9 | 63.0 | 119.5 |

Preparation includes local evaluation key/parameter/card generation and remasking.
Assessment runs the complete positive/negative matrix, **not one verification**.
These are one-host observations, not performance guarantees or mobile results.
The generated WASM, including this test adapter, prover, and verifier, is 540,300
bytes. This supports evaluating 4×9 first for the Ristretto adaptation; it does
not freeze a production matrix or transfer timings to that adaptation.

Build provenance for this run:

- WASM SHA-256: `e4b6fd9c2797812edbc292ec1bad1453ec1827ebd661572bf2b8d37e9f3a7203`
- Cargo.lock SHA-256: `1ba3f8ea2df44993e79df7404e82c3964e0387bccfc46c4148e2e316412dc9b7`
- Local reports/public binary fixtures: `experiments/shuffle-backend/results/`
  (generated and ignored; subsequent runs replace them). The hashes above identify
  the initial build, before the Ristretto feature and its dependencies were added.

The upstream Arkworks decoder permits a decoded object to be followed by unread
bytes. The harness's exact-consumption decoder rejects that suffix separately.
A production parser still needs explicit vector/byte bounds and canonicality;
these local fixtures are not an adversarial-decoder audit. Positive interoperability
uses the same upstream implementation in two runtimes, not independent proof
implementations or independent known-answer vectors. No Ristretto security claim
or reviewed zero-knowledge/soundness claim follows from these checks.

## Ristretto Adaptation Implemented and Evaluated

The generic proof composition depends on
[`HomomorphicEncryptionScheme<Scalar>`](https://github.com/paritytech/mental-poker/blob/ac4fb67b612aa89f37f6be72ea74a3c13eff66ca/proofs/src/homomorphic_encryption/mod.rs)
and [`HomomorphicCommitmentScheme<Scalar>`](https://github.com/paritytech/mental-poker/blob/ac4fb67b612aa89f37f6be72ea74a3c13eff66ca/proofs/src/vector_commitment/mod.rs).
The optional `ristretto` feature now implements these interfaces with
`curve25519-dalek` 4.1.3 group operations and the `ark-ed25519` 0.5.0 scalar field.
The adapter wraps abstract Ristretto points, not Edwards point encodings. It uses
RFC-canonical 32-byte group encoding for both Arkworks serialization modes and
validates every decode, including `Validate::No`. The scalar bridge preserves the
exact Ristretto group order and 32-byte little-endian canonical representation.

ElGamal uses the canonical Ristretto base. Fresh keys/masks are nonzero; the
underlying proof algebra permits zero terms and identity ciphertext components.
Pedersen bases are independently mapped from random 64-byte strings, excluding
identity/repetition, rather than sampled as known scalar multiples of G. This is
local evaluation parameter generation, not a frozen production CRS derivation.

Verified on native macOS ARM64 and a Brave/Chromium 153.0.8010.37 module worker:

- **Five native Rust tests pass**, covering all 56 RFC 9496 Appendix A.1–A.3 group
  vectors, scalar modulus/codec boundaries, ElGamal algebra, Pedersen behavior,
  and the four shuffle configurations.
- **190 adapter cases match the actual TypeScript primitives in both runtimes**
  (380 result comparisons). Cases include all 36 Sasku card mappings, masking,
  remasking, four-share decryption, full-width arithmetic, and codec rejection.
  Card hashes are supplied by TypeScript; this does not validate a Rust protocol
  hash implementation or port the application proof transcript.
- **256 Ristretto shuffle acceptance/rejection checks pass**, including native
  proofs in WASM and WASM proofs natively, across both layouts and input forms.
- The default secp256k1 native test and its 256 browser/native checks still pass.

Final Ristretto run (milliseconds, after adapter checks warm the browser module):

| Matrix / input | Proof bytes | Native prepare + prove | Browser prepare + prove | Native assessment | Browser assessment |
| --- | ---: | ---: | ---: | ---: | ---: |
| 4×9 / initial | 3,480 | 26.6 | 46.7 | 28.5 | 55.2 |
| 4×9 / masked | 3,480 | 20.6 | 41.4 | 28.3 | 55.0 |
| 6×6 / initial | 3,704 | 24.2 | 47.5 | 29.0 | 54.7 |
| 6×6 / masked | 3,704 | 24.1 | 48.1 | 28.6 | 55.4 |

The timing definitions and one-host limitations above still apply. These are
experimental upstream-transcript proofs, not the final SHA-512/CBOR profile.
WASM including the adapter test API is 547,014 bytes. Build provenance:

- Ristretto WASM SHA-256: `8f902ef76d17c1cf54f93a47dd5f222f8464842e7963fbc97fac88ae676fd455`
- Current Cargo.lock SHA-256: `960b3c7822136e433407b999d0d31573f27ef5122786513c8eac60e50bce647c`
- Artifacts: `experiments/shuffle-backend/results-ristretto/`, including the
  public proof fixtures and deterministic adapter test vectors.

This clears the arithmetic/browser compatibility experiment. It does not establish
independent review of the adapted proof, secret-dependent timing behavior, a
production parser, or verified-deck provenance for the live game.

## Next Implementation Gate: Transcript, CRS, and Proof Codec

2026-09-23 transcript progress: the optional `candidate-transcript` mode now
proves/verifies with the [explicit SHA-512/CBOR event profile](shuffle-transcript.md),
using the existing game/round/phase hash prefix and absorbing every challenge
response. Public append values retain the documented pinned compressed inner
serialization inside CBOR byte strings. The attributed local proof-core copy
preserves all equations and append call sites; its exact changes and hashes are
recorded in `vendor/cards-proofs/UPSTREAM.md` and `source-manifest.json`.

Fifteen native tests pass. Python's independent CBOR/hashlib/integer implementation
agrees with TypeScript, native Rust, and browser WASM on eight fixed challenge
vectors. TypeScript reconstructs 64 real proof challenge records, and 128 proof
checks, 1,119 codec comparisons, 22 CRS comparisons, and 380 adapter comparisons
pass. Four genuine proofs are accepted under their own transcript profile and
rejected under the other profile. Independent challenge derivation is not
independent proof implementation or cryptographic review.

The adapted WASM is 626,562 bytes, SHA-256
`a3f7cf3f8201cd43552c57614dfa93a1e57d68dc579999620b7bdf435d70b6ae`.
Cargo.lock SHA-256 is
`eefd72fa5f57e73fe850409f165a9f0a8c62980621222f463d9e11420eb1fc47`.
These pre-API artifact measurements were recorded under `results-transcript/`.
The later [bounded candidate API](shuffle-api.md) bypasses the experimental outer
fixture parser and admits fixed statements and private witnesses. Four sequential
shuffles pass 144 native/browser verification checks, 84 shared statement-admission
comparisons, and 16 private-input rejection checks. Application provenance/worker
integration, full-profile freeze, independent proof vectors, and review remain open.

2026-09-22 progress: a [candidate 36-card deterministic CRS](shuffle-crs-profile.md)
is implemented in TypeScript and independently in Rust with byte-level fixtures.
The optional `candidate-crs` mode uses the fixed proof, blinding, and nine vector
commitment bases for 4×9 proofs, enforcing exact parameters at verification.
Native and browser WASM agree with all eleven TypeScript fixtures (22 comparisons),
and 128 bidirectional proof checks plus 380 adapter comparisons pass in Brave.
Eight native tests pass, including parameter and matrix rejection. The original
random-parameter modes remain available.

The candidate run produced 3,480-byte proofs and a 568,837-byte WASM module.
Browser preparation-plus-proving measured about 41–44 ms on this desktop; the
same timing limitations as the preceding runs apply. Build provenance:

- WASM SHA-256: `8e7ca6564df51fa79eb1d003547a6755020d7f7eb7280d4a9063b9e126a9ef8e`
- Cargo.lock SHA-256: `3eecda493c400faac687be3e5398e876a0e578770019a898f37f5a25a15feb02`
- Generated reports and public vectors: `experiments/shuffle-backend/results-crs/`.

Independent CRS derivation agreement is not independent proof implementation.
The proof still uses upstream hashing. This narrows the derivation work below
without freezing the full proof profile.

2026-09-22 codec progress: the [candidate CBOR codec](shuffle-proof-codec.md)
strictly validates the fixed 106-element 4×9 proof layout before reconstructing
the internal Arkworks representation with constant vector lengths. All 373 shared
cases agree in TypeScript, native Rust, and browser WASM (1,119 comparisons).
Twelve native tests and all 128 proof checks pass with codec round-tripping.
The candidate wire form is 3,650 bytes; the internal form remains 3,480 bytes.
The new WASM is 578,813 bytes, SHA-256
`9d15c3c158985766dc0c79a4c5baab0c3d84c1a2141e92ac41128c63e3c6fa1c`.
The lockfile hash above is unchanged. This hardens proof decoding, not the
experimental outer fixture parser, and does not adapt the Fiat-Shamir transcript.

1. Profile the transcript adaptation explicitly. Upstream reexports the concrete
   `ark-transcript` transcript; swapping the group does not supply this project's
   SHA-512/CBOR Fiat-Shamir framing. A reviewed transcript change or explicit
   profile decision is still required. No implicit switch to upstream hashing.
2. Freeze the 36-card matrix, flattening/permutation convention,
   independently derived Pedersen generators, each transcript round, proof codec,
   and point/scalar/identity rules. Initial ciphertexts `(O, M)` must remain valid.
   Define every nested proof vector length and enforce allocation bounds before
   untrusted proof decoding. The current generic fixture reader is not that codec.
3. Require independent positive/rejection vectors and cross-runtime agreement for
   the exact adapted implementation. Cover changed decks/key/context/parameters,
   malformed encodings, resource bounds, secret-dependent operations, and RNG use.
4. Establish independent review of that exact profile and implementation before
   enabling a public verified-game security claim.

Swiss Post remains a separate algorithmic reference; its vectors are not
byte-compatible with the adaptation. This isolates the remaining cryptographic
work instead of expanding gameplay/recovery orchestration around an absent verifier.

No step authorizes a silent curve/proof-system switch or a structure-only verifier.
If compatibility cannot be achieved economically, revisit the selected profile
explicitly with the project owner.

## Implemented Prerequisite

`createUnprovenDeckShuffle` in `packages/deck/src/shuffle.ts` implements only the
already specified relation:

```
output[j] = input[permutation[j]] + (randomizers[j] * G, randomizers[j] * H)
```

It captures the key/input before RNG use, obtains a private unbiased permutation
and fresh non-zero randomizers from the existing random boundary, and returns the
output together with the private prover witness. Tests cover a coefficient-level
example, four sequential 36-card shuffles followed by recipient-only openings,
rejection sampling, invalid inputs, mutation isolation, and entropy failure.

The witness stays local and out of messages, logs, and transcripts. The helper
provides neither a proof nor shuffle provenance; its 2–128-card operation bound
does not choose Bayer-Groth matrix support. The blocker is the backend/profile,
not this arithmetic preparation step.
