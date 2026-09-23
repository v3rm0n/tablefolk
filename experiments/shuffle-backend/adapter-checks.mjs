import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";

// Use the actual application modules, rather than a second handwritten JS backend.
export async function buildAdapterChecks() {
  const vite = await createServer({
    root: fileURLToPath(new URL("../../", import.meta.url)),
    configFile: false,
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    ssr: { noExternal: [/^@p2pcards\//] },
  });
  try {
    const crypto = await vite.ssrLoadModule("/packages/crypto/src/index.ts");
    const deck = await vite.ssrLoadModule("/packages/deck/src/index.ts");
    const protocol = await vite.ssrLoadModule("/packages/protocol/src/index.ts");
    const { SASKU_DECK_SPEC } = await vite.ssrLoadModule("/packages/rules-sasku/src/index.ts");
    const rfc = JSON.parse(await readFile(new URL("rfc9496.json", import.meta.url), "utf8"));
    assert.deepEqual([rfc.multiples.length, rfc.invalid.length, rfc.uniform.length], [16, 29, 11]);
    const cases = [];
    const add = (name, input, expected) => cases.push({ name, input, expected });
    const hex = crypto.bytesToHex;
    const bytes = crypto.hexToBytes;
    const scalar = (n) => crypto.scalarFromBigInt(n);
    const scalarHex = (n) => hex(crypto.encodeRistrettoScalar(scalar(n)));
    const pointHex = (p) => hex(p.toBytes());
    const q = crypto.RISTRETTO_SCALAR_ORDER;
    const base = crypto.RistrettoPoint.base();
    const zero = crypto.RistrettoPoint.identity();
    const digest = (label) => crypto.sha512(crypto.asciiToBytes(`shuffle-evaluation/${label}`));
    const hashScalar = (label) => crypto.reduceWideRistrettoScalar(digest(label));
    const hashPoint = (label) => crypto.RistrettoPoint.fromUniformBytes(digest(label));
    const decode = (fn, serialize, encoding) => {
      try { return { accepted: true, bytes: serialize(fn(bytes(encoding))) }; }
      catch { return { accepted: false, bytes: null }; }
    };
    const pointCase = (name, a, b, s) => add(name, {
      op: "point", left: pointHex(a), right: pointHex(b), scalar: scalarHex(s),
    }, {
      add: pointHex(a.add(b)), subtract: pointHex(a.subtract(b)),
      negate: pointHex(a.negate()), multiply: pointHex(a.multiply(scalar(s))),
    });

    rfc.multiples.forEach((encoding, i) => {
      const multiple = base.multiply(scalar(BigInt(i)));
      assert.equal(pointHex(multiple), encoding, `TypeScript RFC generator multiple ${i}`);
      add(`rfc-multiple-${i}`, { op: "decode_point", bytes: encoding }, { accepted: true, bytes: encoding });
      pointCase(`point-edges-${i}`, multiple, base, i % 2 === 0 ? 0n : q - 1n);
    });
    rfc.invalid.forEach((encoding, i) => {
      const expected = decode(crypto.RistrettoPoint.fromBytes, pointHex, encoding);
      assert.equal(expected.accepted, false, `TypeScript RFC invalid point ${i}`);
      add(`rfc-invalid-${i}`, { op: "decode_point", bytes: encoding }, expected);
    });
    rfc.uniform.forEach((vector, i) => {
      assert.equal(pointHex(crypto.RistrettoPoint.fromUniformBytes(bytes(vector.input))), vector.output);
      add(`rfc-uniform-${i}`, { op: "uniform", bytes: vector.input }, vector.output);
    });
    for (const size of [0, 31, 33]) {
      for (const op of ["decode_point", "decode_scalar"]) {
        add(`${op}-length-${size}`, { op, bytes: "00".repeat(size) }, { accepted: false, bytes: null });
      }
    }
    for (const n of [0n, 1n, 7n, q - 1n, q, q + 1n, 1n << 255n, (1n << 256n) - 1n]) {
      const encoding = integerHex(n, 32);
      const expected = decode(crypto.decodeRistrettoScalar, (s) => scalarHex(s), encoding);
      assert.equal(expected.accepted, n < q);
      add(`scalar-decoding-${n}`, { op: "decode_scalar", bytes: encoding }, expected);
    }
    const scalars = [0n, 1n, 2n, q - 2n, q - 1n, 1n << 251n,
      ...Array.from({ length: 8 }, (_, i) => hashScalar(`scalar-${i}`))];
    scalars.forEach((a, i) => {
      const b = scalars[(i + 4) % scalars.length];
      const wide = i === 0 ? "ff".repeat(64) : i === 1 ? integerHex(q + 5n, 64) : hex(digest(`wide-${i}`));
      add(`scalar-arithmetic-${i}`, { op: "scalar", left: scalarHex(a), right: scalarHex(b), wide }, {
        add: scalarHex(crypto.addRistrettoScalars(scalar(a), scalar(b))),
        subtract: scalarHex(crypto.subtractRistrettoScalars(scalar(a), scalar(b))),
        negate: scalarHex(crypto.negateRistrettoScalar(scalar(a))),
        multiply: scalarHex(crypto.multiplyRistrettoScalars(scalar(a), scalar(b))),
        reduce: scalarHex(crypto.reduceWideRistrettoScalar(bytes(wide))),
      });
    });
    for (let i = 0; i < 12; i += 1) {
      pointCase(`point-full-width-${i}`, hashPoint(`left-${i}`), hashPoint(`right-${i}`), hashScalar(`point-scalar-${i}`));
    }

    SASKU_DECK_SPEC.cards.forEach((id, i) => {
      const message = deck.deriveCardPoint(SASKU_DECK_SPEC.id, id);
      add(`sasku-map-${id}`, { op: "uniform", bytes: hex(protocol.cardDerivationHash(SASKU_DECK_SPEC.id, id)) }, pointHex(message));
      const keys = [3n, 5n, 7n, i % 2 === 0 ? q - 1n : hashScalar(`key-${i}`)].map(scalar);
      const mask = scalar(i === 0 ? q - 1n : hashScalar(`mask-${i}`));
      const remask = scalar(i === 0 ? 1n : hashScalar(`remask-${i}`));
      const key = deck.aggregatePublicKeys(keys.map((secret) => base.multiply(secret)));
      const masked = deck.maskCard(message, mask, key);
      const remasked = deck.remaskCard(masked, remask, key);
      const shares = keys.map((secret) => deck.decryptionShare(secret, remasked.A));
      const opened = deck.removeDecryptionShares(remasked, shares);
      assert.equal(pointHex(opened), pointHex(message));
      add(`sasku-elgamal-${id}`, {
        op: "elgamal", message: pointHex(message), keys: keys.map(scalarHex),
        mask: scalarHex(mask), remask: scalarHex(remask),
      }, {
        key: pointHex(key), masked: [pointHex(masked.A), pointHex(masked.B)],
        remasked: [pointHex(remasked.A), pointHex(remasked.B)],
        shares: shares.map(pointHex), decrypted: pointHex(opened),
      });
    });

    const h = hashPoint("commitment-h");
    const bases = Array.from({ length: 9 }, (_, i) => hashPoint(`commitment-${i}`));
    for (const length of [0, 1, 2, 6, 9, 10]) {
      const values = Array.from({ length }, (_, i) => hashScalar(`commitment-value-${i}`));
      const blind = length === 0 ? 0n : q - 1n;
      const accepted = length <= bases.length;
      const expected = accepted ? values.reduce((sum, x, i) => sum.add(bases[i].multiply(scalar(x))), h.multiply(scalar(blind))) : zero;
      add(`commitment-prefix-${length}`, {
        op: "commitment", h: pointHex(h), bases: bases.map(pointHex), values: values.map(scalarHex), blind: scalarHex(blind),
      }, { accepted, bytes: accepted ? pointHex(expected) : null });
    }
    return cases;
  } finally {
    await vite.close();
  }
}

export function assertAdapterChecks(cases, actual, runtime) {
  assert.equal(actual.length, cases.length, `${runtime} adapter result count`);
  cases.forEach((test, i) => assert.deepEqual(actual[i], test.expected, `${runtime}: ${test.name}`));
}

function integerHex(value, length) {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    bytes[i] = Number(value & 255n);
    value >>= 8n;
  }
  assert.equal(value, 0n);
  return Buffer.from(bytes).toString("hex");
}
