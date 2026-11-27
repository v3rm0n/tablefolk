# Shuffle WASM

This crate implements the dimension-scoped Bayer–Groth Ristretto255 shuffle
profile used by the Sasku browser client. The crate derives its CRS and uses
the bounded v2 statement and proof codecs for every call. See the full
[profile specification](../../docs/shuffle.md) and the
[vendored proof source attribution](vendor/cards-proofs/UPSTREAM.md).

## Build and stage

Run from `crates/shuffle-wasm` after installing Rust and Node dependencies.
The crate pins Rust 1.90.0 and targets `wasm32-unknown-unknown` for the browser.

```sh
cargo install wasm-bindgen-cli --version 0.2.100 --locked
cargo build --release --locked --lib --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/release/shuffle_wasm.wasm --target web --out-dir pkg
node stage-web-candidate.mjs
```

The staging script copies the JavaScript glue and module into
`apps/web/public/shuffle-candidate/` and writes a SHA-256 manifest.
The web workspace also runs staging before development and production builds.

## Verification

```sh
node verify-vendor.mjs
cargo test --release --locked
cargo build --release --locked --example shuffle-api
node run-shuffle-api.mjs
node run-web-shuffle.mjs
```

The JavaScript harnesses require the repository's npm dependencies and Playwright
Chromium (`npx playwright install chromium`). The API harness checks both
4×9 and 4×13 shuffles across TypeScript, native Rust, and browser WASM. It prints
per-seat proving and verification timings including native process startup and
browser worker messaging. The web harness exercises the real worker, durable
shuffle replay, and the Sasku round flow under development and production builds.

Native and WASM checks exercise the same vendored proof equations. The candidate
profile and implementation have yet to receive an independent cryptographic audit.
