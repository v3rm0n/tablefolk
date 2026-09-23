# Attributed upstream copy

Source: https://github.com/paritytech/mental-poker/tree/ac4fb67b612aa89f37f6be72ea74a3c13eff66ca/proofs

Upstream authors: Jeffrey Burdges and Geometry Research, as listed in the pinned
workspace manifest. The upstream package declares MIT OR Apache-2.0 licensing;
this distribution includes the Apache-2.0 license in `LICENSE-APACHE`.

Local changes made 2026-09-23 for the isolated `candidate-transcript` experiment:

- Standalone manifest preserves attribution and pins the arithmetic dependencies.
- `src/lib.rs` exports the added local transcript instead of `ark-transcript`.
- `src/zkp/mod.rs` excludes unrelated Schnorr/Chaum-Pedersen modules from this
  shuffle-only adaptation. Their original files are retained unchanged.
- `src/zkp/arguments/matrix_elements_product/prover.rs` samples its private scalar
  directly from the supplied `Rng + CryptoRng`, instead of the upstream transcript
  witness RNG. This value is never a public challenge.
- `src/transcript.rs` implements the candidate SHA-512/CBOR event framing,
  response absorption, challenge reduction, and bounds.

All other source files, including proof equations and transcript append call
sites, match the pinned upstream bytes. `source-manifest.json` records original
and local source hashes; `node ../../verify-vendor.mjs` checks the local snapshot.
The parent experiment tests the adaptation with concrete Ristretto types; this
copy is excluded from workspace-wide upstream unit tests. It is not a general
replacement for the upstream crate and has not received independent review.
