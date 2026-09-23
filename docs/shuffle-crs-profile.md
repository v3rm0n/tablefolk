# Candidate 36-card Shuffle CRS

Status: implemented prerequisite, **not a frozen production shuffle profile**.
This selects a concrete 4×9 candidate for the next transcript/backend adaptation.
The [bounded proof codec](shuffle-proof-codec.md) and
[Fiat-Shamir transcript](shuffle-transcript.md) now have executable candidates.
Production statement/context admission, full-profile freeze, independent proof
vectors, and review remain outstanding. No gameplay verifier consumes these parameters.

## Exact derivation

Profile identifier: `bg-ristretto255-36-4x9-crs-candidate-v1`.
The encryption generator is the canonical Ristretto255 base G. Derive eleven
additional bases in this order:

1. `proof`, index 0: the additional generator required by the candidate backend.
2. `blinding`, index 0: the Pedersen randomness base h.
3. `message`, indices 0 through 8: the ordered Pedersen bases g[0]…g[8].

For each role/index pair, the exact input is:

```
ASCII("p2pcards/v1/shuffle") || deterministic-CBOR([
  "crs", "bg-ristretto255-36-4x9-crs-candidate-v1", 4, 9, role, index
])
```

Hash with SHA-512 and map all 64 digest bytes with the existing RFC 9496
Ristretto element derivation (`RistrettoPoint.fromUniformBytes`). Do not reduce
the digest to a scalar and multiply G. There is no participant-selected seed,
game ID, deck content, secret, random draw, retry counter, or optional parameter.
The `crs` tuple is distinct from the context-based proof-challenge framing.

Reject the entire parameter set if a derived base is identity, equals G or -G,
or equals a preceding derived base or its negation. Failure requires a new
profile revision; it never selects a fallback or loops. The fixed derivation
performs eleven hashes/maps and bounded pairwise checks.

The intended vector commitment is `r*h + sum(x[i]*g[i])`, with vectors of at
most nine scalars and shorter vectors using the corresponding prefix. This
matches the evaluated adapter's commitment interface. The derivation alone
does not establish soundness of the composed proof. Matrix flattening,
permutation conventions, and transcript use must be specified together with
that adaptation; other deck sizes and layouts are not covered here.

## Implementation and fixtures

`deriveShuffleCrs36` in `packages/deck/src/shuffle-crs.ts` returns immutable
parameters without shared mutable arrays or encoded-byte caches. The API has
no parameters and cannot accept peer-supplied bases.

`packages/deck/test-vectors/shuffle-crs-36.json` contains every full framed input,
SHA-512 digest, and compressed point. Framing was constructed separately with
explicit CBOR array/text/integer bytes and hashing used Node `createHash`.
Points were generated with the same Noble Ristretto mapping as the application:
these are regression fixtures, **not independent group or proof vectors**.
Tests independently rehash the stored inputs with Node, compare all application
mapping inputs and outputs, and inject degenerate bases and mapping failures to
check fail-closed behavior.

The experiment's `candidate-crs` feature now independently encodes this tuple in
Rust, hashes it with RustCrypto SHA-512, and maps it with curve25519-dalek. Native
and browser WASM outputs match all eleven complete fixtures (22 comparisons).
The independent hash/group implementation comparison supports this derivation;
it does not turn these fixtures into independent shuffle-proof vectors.

Changing any tuple field, role order, derivation rule, or base requires a new
profile identifier and regenerated, reviewed fixtures. The experimental harness
uses the fixed parameters only with `candidate-crs`, rejecting all parameter
substitution and other layouts. The original modes retain random parameters.
`candidate-transcript` additionally selects the SHA-512/CBOR adaptation; otherwise
the transcript remains upstream. Both candidate modes use the bounded proof codec
bridge and pass 128 native/browser proof acceptance/rejection checks each. This
does not freeze the full production profile or establish independent review.
