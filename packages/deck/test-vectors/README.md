# Shuffle CRS regression fixtures

`shuffle-transcript.json` contains eight independently generated SHA-512/CBOR
challenge vectors, including input bytes, digests, and reduced scalars. Reproduce
them with `python3 packages/deck/test-vectors/generate-shuffle-transcript.py` from
the repository root. The script uses Python's standard library and its own small
CBOR encoder; it does not import application or Rust code. These test challenge
framing and reduction, not independent proof equations. See
`docs/shuffle.md` for the exact candidate profile.

`shuffle-crs-36.json` and `shuffle-crs-52.json` record the v2 CRS bases for
4×9 and 4×13 in derivation order.
Each entry contains the role/index, full SHA-512 input, digest, and compressed
Ristretto point. See `docs/shuffle.md` at the repository root.

The following Node command reproduces the fixtures from the repository root. Its
CBOR framing is deliberately independent of the application's encoder. The Rust tests independently reproduce every input,
SHA-512 digest, and group point using RustCrypto and Dalek.

```sh
node --input-type=module <<'JS'
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { ristretto255_hasher } from '@noble/curves/ed25519.js';

const text = value => Buffer.concat([
  Buffer.from(value.length < 24 ? [0x60 + value.length] : [0x78, value.length]),
  Buffer.from(value, 'ascii'),
]);
const profile = 'bg-ristretto255-crs-candidate-v2';
for (const columns of [9, 13]) {
  const entries = [['proof', 0], ['blinding', 0],
    ...Array.from({ length: columns }, (_, i) => ['message', i])];
  const vectors = entries.map(([role, index]) => {
    const input = Buffer.concat([
      Buffer.from('p2pcards/v1/shuffle'), Buffer.from([0x86]),
      text('crs'), text(profile), Buffer.from([4, columns]), text(role), Buffer.from([index]),
    ]);
    const digest = createHash('sha512').update(input).digest();
    return {
      role, index, input: input.toString('hex'), digest: digest.toString('hex'),
      point: Buffer.from(ristretto255_hasher.deriveToCurve(digest).toBytes()).toString('hex'),
    };
  });
  writeFileSync(`packages/deck/test-vectors/shuffle-crs-${4 * columns}.json`,
    JSON.stringify(vectors, null, 2) + '\n');
}
JS
```
