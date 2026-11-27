# Bayer–Groth Shuffle Backend (Rust / WASM)

Standalone Cargo workspace (outside npm workspaces) that builds and tests the
candidate 36-card 4×9 Ristretto255 Bayer–Groth prover and verifier used by
`apps/web`, based on Parity `cards-proofs` (`ac4fb67b612aa89f37f6be72ea74a3c13eff66ca`).

- **Candidate profile specification:** [docs/shuffle.md](../../docs/shuffle.md)
- **Local proof-core changes & attribution:** [vendor/cards-proofs/UPSTREAM.md](vendor/cards-proofs/UPSTREAM.md)

> This backend is an experimental candidate and has not undergone independent
> cryptographic review.

## Prerequisites

- Rust `1.90.0` with `wasm32-unknown-unknown` (pinned by `rust-toolchain.toml`)
- `wasm-bindgen-cli` `0.2.100` (must match the pinned `wasm-bindgen` crate):
  ```sh
  cargo install wasm-bindgen-cli --version 0.2.100 --locked
  ```
- Root npm dependencies installed (`npm install`), plus Playwright Chromium (or
  `PLAYWRIGHT_EXECUTABLE_PATH`) for browser verification scripts

## Build & Stage for `apps/web`

Run from `experiments/shuffle-backend`:

```sh
node verify-vendor.mjs
cargo build --release --locked --features candidate-transcript --lib --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/release/shuffle_backend_evaluation.wasm --target web --out-dir pkg-transcript
node stage-web-candidate.mjs
```

`stage-web-candidate.mjs` copies the generated JS/WASM bundle (ignored by Git)
and a SHA-256 manifest into `apps/web/public/shuffle-candidate/`. `npm run dev`
and `npm run build` in `@p2pcards/web` automatically run this staging script and
fail closed if `pkg-transcript/` has not been built yet.

## Verification Harnesses

All commands run from `experiments/shuffle-backend` (use `--locked` to keep
`Cargo.lock` pinned). Runners honor `CARGO_TARGET_DIR` and
`PLAYWRIGHT_EXECUTABLE_PATH`.

### 1. Candidate transcript + bounded API (active mode)

```sh
node verify-vendor.mjs
cargo test --release --locked --features candidate-transcript
cargo build --release --locked --features candidate-transcript
cargo build --release --locked --features candidate-transcript --lib --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/release/shuffle_backend_evaluation.wasm --target web --out-dir pkg-transcript

# Native/WASM cross-runtime proof, codec, CRS, adapter, and transcript checks
SHUFFLE_EVAL_CURVE=ristretto255 \
SHUFFLE_EVAL_CRS=bg-ristretto255-36-4x9-crs-candidate-v1 \
SHUFFLE_EVAL_TRANSCRIPT=bg-ristretto255-36-4x9-fs-candidate-v1 \
SHUFFLE_EVAL_PKG_DIR=pkg-transcript \
SHUFFLE_EVAL_OUTPUT_DIR=results-transcript \
node run-browser.mjs

# Bounded 36-card statement/witness API across TS, native Rust, and WASM worker
node run-shuffle-api.mjs

# Cross-runtime DLEQ interoperability and shuffle/deal arithmetic timings
node benchmark-crypto.mjs

# Full browser worker + IndexedDB shuffle/deal/play/audit/owner/sync integration
node stage-web-candidate.mjs
node run-web-shuffle.mjs
```

### 2. Legacy evaluation modes

The workspace retains earlier Cargo feature modes for baseline comparisons:

- **Default (`secp256k1`):** unchanged upstream `cards-proofs` with random
  evaluation parameters (`node run-browser.mjs`).
- **`--features ristretto`:** Ristretto255 arithmetic/serialization adapter
  compared against `@p2pcards/crypto` and `@p2pcards/deck` with random
  parameters (`SHUFFLE_EVAL_CURVE=ristretto255`).
- **`--features candidate-crs`:** fixed 4×9 deterministic CRS + 3,650-byte
  proof codec with upstream `ark-transcript`
  (`SHUFFLE_EVAL_CRS=bg-ristretto255-36-4x9-crs-candidate-v1`).
- **Transcript incompatibility check:**
  `node compare-transcripts.mjs UPSTREAM_BINARY ADAPTED_BINARY` verifies that
  `candidate-crs` and `candidate-transcript` proofs mutually reject each other.

## Boundaries

- Only the bounded `candidate-transcript` API (`validate_candidate_shuffle_statement36`,
  `prove_candidate_shuffle36`, `verify_candidate_shuffle36`) is intended for
  application use; the legacy `Fixture` decoder is a local evaluation helper,
  not an untrusted-input parser.
- Cross-runtime checks run the same adapted Rust core natively and in WASM;
  they establish compatibility and regression coverage, not independent proof
  review. Generated `pkg*/` and `results*/` directories are ignored by Git.
