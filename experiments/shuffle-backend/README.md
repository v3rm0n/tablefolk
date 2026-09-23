# Isolated Bayer–Groth Backend Evaluation

Evaluates the **unchanged `cards-proofs` equations and transcript** at Parity
revision `ac4fb67b612aa89f37f6be72ea74a3c13eff66ca`. The default build uses the
upstream secp256k1 instantiation; `--features ristretto` selects local experimental
Ristretto255 arithmetic/serialization adapters. This does not exercise every
`cards-play` wrapper or supply a production `SHUFFLE` verifier.

An optional `candidate-transcript` mode uses an attributed local copy of that
proof core with SHA-512/CBOR transcript framing; see the adaptation section below.

This standalone Cargo workspace is outside the application's npm workspaces.
The git revision, Rust toolchain, bindings version, and dependency lockfile are
pinned. No application dependency or wire format changes are needed to run it.

## Run

Prerequisites: Rust/rustup, the project's existing npm development dependencies,
and a Playwright Chromium installation or `PLAYWRIGHT_EXECUTABLE_PATH`.
Run these commands from `experiments/shuffle-backend`:

```sh
cargo test --release --locked
cargo build --release --locked
cargo build --release --locked --lib --target wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.100 --locked
wasm-bindgen target/wasm32-unknown-unknown/release/shuffle_backend_evaluation.wasm --target web --out-dir pkg
node run-browser.mjs
```

For the Ristretto evaluation, after installing the same bindings CLI:

```sh
cargo test --release --locked --features ristretto
cargo build --release --locked --features ristretto
cargo build --release --locked --features ristretto --lib --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/release/shuffle_backend_evaluation.wasm --target web --out-dir pkg-ristretto
SHUFFLE_EVAL_CURVE=ristretto255 SHUFFLE_EVAL_PKG_DIR=pkg-ristretto SHUFFLE_EVAL_OUTPUT_DIR=results-ristretto node run-browser.mjs
```

Both builds use the same native binary name. Rebuild the matching feature before
running a variant, or use separate target directories. The runner requires the
native and WASM curve to match the explicitly selected evaluation curve.

### Candidate deterministic CRS

`candidate-crs` includes the Ristretto adapter and independently implements the
[candidate 36-card CRS](../../docs/shuffle-crs-profile.md) with fixed-tuple CBOR,
RustCrypto SHA-512 0.10.9, and Dalek's Ristretto group map. It supports only 4×9.
Both proving and verification use the derived parameters; verification rejects
fixture-supplied replacements. The upstream proof equations and Fiat-Shamir
transcript remain unchanged. A strict candidate CBOR codec now converts to/from
the pinned internal compound proof representation before proof assessment.

```sh
cargo test --release --locked --features candidate-crs
cargo build --release --locked --features candidate-crs
cargo build --release --locked --features candidate-crs --lib --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/release/shuffle_backend_evaluation.wasm --target web --out-dir pkg-crs
SHUFFLE_EVAL_CURVE=ristretto255 SHUFFLE_EVAL_CRS=bg-ristretto255-36-4x9-crs-candidate-v1 SHUFFLE_EVAL_PKG_DIR=pkg-crs SHUFFLE_EVAL_OUTPUT_DIR=results-crs node run-browser.mjs
```

Native `crs` and WASM `evaluate_crs_vectors()` expose the eleven public input,
digest, and point vectors. The runner compares all fields with the TypeScript
fixtures in both runtimes (22 comparisons). Twelve native tests cover the adapter,
CRS fixtures, degenerate bases, exact parameter enforcement, unsupported layouts,
proof codec, and proof rejection. Two input forms × four cross-runtime assessment paths ×
16 checks give **128 proof acceptance/rejection checks**, alongside the existing
190 adapter cases in each runtime. Parameter-replacement checks in this mode may
reject at the fixed-CRS guard before reaching proof equations.

Reports include `crs_profile`; the runner rejects native/WASM/profile mismatches.
`SHUFFLE_EVAL_CRS` defaults to `random-evaluation` for the original two modes.
Generated `pkg-crs/` and `results-crs/` are ignored. This establishes independent
CRS derivation agreement, not independent proof implementation or production
transcript compatibility.

The [proof codec](../../docs/shuffle-proof-codec.md) accepts exactly 3,650 bytes
containing 106 canonical point/scalar elements. `roundtrip_candidate_proof36`
exposes structural validation in WASM; the native `codec` command runs bounded
JSON batches for the test harness. The runner compares 373 valid/malformed cases
against the actual TypeScript codec and both Rust runtimes (1,119 comparisons),
saving `proof-codec-vectors.json`. Proofs from both runtimes retain identical
bytes after codec round-trip. Reports distinguish the candidate `proof_codec`
identifier; `proof_bytes` still measures the 3,480-byte internal Arkworks form.
The outer fixture remains experimental and must not receive untrusted traffic.

### Candidate SHA-512/CBOR transcript

`candidate-transcript` includes `candidate-crs` and selects the local
`vendor/cards-proofs` adaptation. Its equation files and append call sites are
unchanged; the transcript export, private matrix-product blinder sampling, and
module scope differ as documented in `vendor/cards-proofs/UPSTREAM.md`.
The new [transcript profile](../../docs/shuffle-transcript.md) specifies every
round, framing byte, inner serialization, and bound. It is deliberately distinct
from `upstream-ark-transcript`, which remains the default.

```sh
node verify-vendor.mjs
cargo test --release --locked --features candidate-transcript
cargo build --release --locked --features candidate-transcript
cargo build --release --locked --features candidate-transcript --lib --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/release/shuffle_backend_evaluation.wasm --target web --out-dir pkg-transcript
SHUFFLE_EVAL_CURVE=ristretto255 SHUFFLE_EVAL_CRS=bg-ristretto255-36-4x9-crs-candidate-v1 SHUFFLE_EVAL_TRANSCRIPT=bg-ristretto255-36-4x9-fs-candidate-v1 SHUFFLE_EVAL_PKG_DIR=pkg-transcript SHUFFLE_EVAL_OUTPUT_DIR=results-transcript node run-browser.mjs
```

All 15 candidate native tests pass. The runner compares eight independently
generated Python/hashlib challenge vectors with native/WASM results and rebuilds
64 real challenge inputs using the TypeScript transcript. The existing 128 proof
checks, 373 codec cases, CRS vectors, and arithmetic adapter comparisons also pass.
Reports expose `transcript_profile` and reject mixed builds.

To check incompatibility, preserve copies of binaries built with `candidate-crs`
and `candidate-transcript`, then run
`node compare-transcripts.mjs UPSTREAM_BINARY ADAPTED_BINARY`. It creates genuine
proofs of both input forms, confirms self-acceptance, and checks rejection under
the other profile in both directions. No witness material is serialized.

Generated `pkg-transcript/` and `results-transcript/` are ignored. This mode checks
prover/verifier challenge agreement during generation; its reported preparation
time includes that extra verification. The fixture context conversion and outer
decoder remain local experiment helpers, not production traffic admission.

The CLI must match the pinned `wasm-bindgen` crate version. An official release
binary of that version can also be used. `rust-toolchain.toml` pins Rust 1.90.0
and the WASM target. `Cargo.lock` is retained; use `--locked` rather than updating
dependencies during comparisons.

`CARGO_HOME`, `RUSTUP_HOME`, and `CARGO_TARGET_DIR` can isolate tools and build
artifacts. With a custom target directory, use that directory in the
`wasm-bindgen` input path too. The browser runner honors `CARGO_TARGET_DIR`,
`PLAYWRIGHT_EXECUTABLE_PATH`, `SHUFFLE_EVAL_OUTPUT_DIR` (default `results`),
`SHUFFLE_EVAL_PKG_DIR` (default `pkg`), and `SHUFFLE_EVAL_CURVE` (default `secp256k1`).

The recorded macOS evaluation used tools under `/tmp/opencode`, without changing
global Rust configuration. It used the official macOS ARM64 wasm-bindgen 0.2.100
archive with published SHA-256
`69f25cb910de7e19777b3f93347f5e62a64c8f81709b41ba7242d00a9543573c`.

## Coverage and Artifacts

The native Rust test assesses four fixtures: 4×9 and 6×6 matrices, each with
public initial `(O, M)` input and already masked input. Fixture preparation also
decrypts every output to check the permutation/remasking relation.

Each assessment checks:

- acceptance of the genuine statement/proof;
- rejection of changed input/output cards and ordering, aggregate key, encryption
  generator, proof generator, commitment parameters, and proof commitment;
- rejection of an invalid statement length and changed game/round/seat context;
- rejection of truncated proof bytes and of trailing bytes by the experiment's
  exact-consumption decoder.

Upstream Arkworks deserialization accepts a valid object followed by unread bytes.
That is recorded separately as a stream-decoder behavior, not presented as an
upstream exact-consumption guarantee. The exact-consumption check is local code.

`run-browser.mjs` serves only evaluation assets on loopback, runs the WASM module
in a dedicated module worker, verifies native fixtures there, generates fresh
browser fixtures, and verifies those with the native binary. It compares the
complete reports across runtimes and exits unsuccessfully on unexpected results.
There are 16 checks × 4 configurations × 4 assessment paths = **256 checks**.

### Ristretto Adapter Checks

The feature pins `curve25519-dalek` 4.1.3 for group operations and `ark-ed25519`
0.5.0 for its scalar field only. Points are always abstract Ristretto elements;
no Edwards point conversion is used. Canonical point serialization is exactly
32 bytes in both Arkworks modes, and decoding validates even with `Validate::No`.
The scalar bridge is checked against the Ristretto order and Dalek's canonical
scalar decoder. Ciphertexts serialize as two 32-byte points.

The five native Rust tests cover shuffle statements plus RFC 9496 Appendix A.1–A.3
(16 multiples, 29 invalid encodings, 11 uniform-byte inputs), scalar boundaries,
zero/wrapping ElGamal algebra, and Pedersen prefix/linearity behavior. Locally
sampled commitment bases use the 64-byte group map, not known scalar multiples
of G; setup excludes identity and repeated bases. This is still evaluation setup,
not the agreed deterministic production CRS.

`adapter-checks.mjs` loads the application's actual TypeScript crypto/deck modules
through Vite, then compares **190 cases** with the native adapter and browser
worker (**380 result comparisons**). These include all 36 Sasku card-point mappings
and masking/remasking/decryption-share round trips, full-width scalar/point
arithmetic, RFC vectors, codec rejection, and Pedersen commitments. Card-derivation
hash inputs come from TypeScript; this does not implement Rust protocol hashing.
The browser adapter checks run before shuffle measurements, warming the module.

`results-ristretto/adapter-vectors.json` records these deterministic public test
inputs and both runtimes' outputs. Its synthetic test scalars are public fixtures;
the runner never loads application identities, game keys, or live private hands.

Ignored `results/` contains `summary.json`, the complete `report.json`, and eight
public binary fixtures with content hashes. The fixtures include parameters,
ordered decks, and proof; no private keys, permutations, or remasking witnesses
are serialized. Proofs are randomly generated; these are interoperability
fixtures, not independent known-answer vectors or byte-identical reproducible runs.

Timings distinguish preparation-plus-proving from assessment of the full rejection
matrix. Assessment time is **not** a single-verification benchmark. WASM size
includes this test adapter and both prover/verifier paths. One desktop run is
not a mobile performance or side-channel assessment.

## Boundary

The experiment consumes its own local fixtures, not network traffic. Its generic
Arkworks fixture decoder is not a hardened untrusted-input parser; the outer byte
limit does not establish safe bounds for every serialized vector allocation.
The random modes use locally sampled parameters; `candidate-crs` implements a
fixed candidate derivation, still pending full-profile review. The transcript is
upstream unless `candidate-transcript` is explicitly selected. Internal proof
serialization remains Arkworks, with the bounded CBOR bridge in both candidate
modes. The bounded API below adds candidate statement/context admission; a
reviewed complete profile and reviewed constant-time prover remain open. See
[the backend assessment](../../docs/shuffle-backend-assessment.md) for measured
results, compatibility deltas, and the next implementation gate.

## Bounded API addition

The `candidate-transcript` build exports a fixed-statement prover/verifier that
bypasses `Fixture`. See [the candidate API specification](../../docs/shuffle-api.md)
for exact framing, private-input handling, and limitations. With native and
`pkg-transcript` artifacts built, run `node run-shuffle-api.mjs` using the same
`CARGO_TARGET_DIR` and `PLAYWRIGHT_EXECUTABLE_PATH` environment variables as the
browser evaluation. The runner keeps private requests in memory and prints only
counts. It tests four sequential shuffles across TypeScript, native Rust, and a
browser worker. This is still isolated evaluation code, not live game integration.

## Application worker integration checks

After building `pkg-transcript`, run `node stage-web-candidate.mjs` to stage the
ignored local backend artifacts, then `node run-web-shuffle.mjs` with
`PLAYWRIGHT_EXECUTABLE_PATH` configured. This exercises the application's disposable
worker and signed four-shuffle ledger in development and a production build under
a nested URL path. It also exercises durable local authoring and receipt with
real browser IndexedDB, reopening storage and re-verifying every shuffle prefix.
The recovered deck then drives private dealing, a complete 36-play Sasku hand,
local audit, and completed-round recovery through the
[shuffle-backed round entry point](../../docs/shuffled-sasku-round.md).
It also replays all 57 semantic originals in reverse arrival order through the
[exclusive phase owner](../../docs/candidate-round-owner.md), checking the same
completed audit and an empty bounded queue.
The same owner also persists a signed sync response and confirms its historical
shuffle original as a duplicate, through [coordinated sync receipt](../../docs/candidate-owned-sync.md).
See [worker boundaries](../../docs/shuffle-worker.md) and
[durable recovery](../../docs/shuffle-durability.md).
