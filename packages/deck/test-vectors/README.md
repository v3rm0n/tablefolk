# Shuffle CRS regression fixtures

`shuffle-transcript.json` contains eight independently generated SHA-512/CBOR
challenge vectors, including input bytes, digests, and reduced scalars. Reproduce
them with `python3 packages/deck/test-vectors/generate-shuffle-transcript.py` from
the repository root. The script uses Python's standard library and its own small
CBOR encoder; it does not import application or Rust code. These test challenge
framing and reduction, not independent proof equations. See
`docs/shuffle-transcript.md` for the exact candidate profile.

`shuffle-crs-36.json` records eleven public candidate bases in derivation order.
Each entry contains the role/index, full SHA-512 input, digest, and compressed
Ristretto point. See `docs/shuffle-crs-profile.md` at the repository root.

The following Node command reproduces the fixture from the repository root. Its
CBOR framing is deliberately independent of the application's encoder. The group
mapping uses the same Noble implementation, so this is not an independent
cryptographic known-answer vector set.

The experiment's `candidate-crs` mode independently reproduces every input,
SHA-512 digest, and group point using RustCrypto and Dalek, in native and browser
WASM builds. That comparison covers CRS derivation, not shuffle-proof vectors.

```sh
node --input-type=module <<'JS'
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { ristretto255_hasher } from '@noble/curves/ed25519.js';

const text = value => Buffer.concat([
  Buffer.from(value.length < 24 ? [0x60 + value.length] : [0x78, value.length]),
  Buffer.from(value, 'ascii'),
]);
const profile = 'bg-ristretto255-36-4x9-crs-candidate-v1';
const entries = [['proof', 0], ['blinding', 0],
  ...Array.from({ length: 9 }, (_, i) => ['message', i])];
const vectors = entries.map(([role, index]) => {
  const input = Buffer.concat([
    Buffer.from('p2pcards/v1/shuffle'), Buffer.from([0x86]),
    text('crs'), text(profile), Buffer.from([4, 9]), text(role), Buffer.from([index]),
  ]);
  const digest = createHash('sha512').update(input).digest();
  return {
    role, index, input: input.toString('hex'), digest: digest.toString('hex'),
    point: Buffer.from(ristretto255_hasher.deriveToCurve(digest).toBytes()).toString('hex'),
  };
});
writeFileSync('packages/deck/test-vectors/shuffle-crs-36.json',
  JSON.stringify(vectors, null, 2) + '\n');
JS
```
