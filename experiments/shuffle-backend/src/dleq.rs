//! Chaum–Pedersen proofs with the same transcript as packages/deck/src/proofs.ts.
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint as Point},
    scalar::Scalar,
    traits::{IsIdentity, VartimeMultiscalarMul},
};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"p2pcards/v1/dleq";
const CARD_BYTES: usize = 1 + 32; // position, A
const SHARE_BYTES: usize = 4 * 32; // S, R1, R2, z
const MAX_CARDS: usize = 128;

fn point(bytes: &[u8]) -> Result<Point, String> {
    CompressedRistretto(bytes.try_into().map_err(|_| "Invalid DLEQ point length")?)
        .decompress().ok_or_else(|| "Invalid DLEQ point".into())
}

fn scalar(bytes: &[u8]) -> Result<Scalar, String> {
    Option::from(Scalar::from_canonical_bytes(bytes.try_into().map_err(|_| "Invalid DLEQ scalar length")?))
        .ok_or_else(|| "Noncanonical DLEQ scalar".into())
}

fn random_nonzero(rng: &mut OsRng) -> Zeroizing<Scalar> {
    let mut bytes = Zeroizing::new([0; 32]);
    loop {
        rng.fill_bytes(&mut bytes[..]);
        bytes[31] &= 0x1f;
        if let Some(value) = Option::from(Scalar::from_canonical_bytes(*bytes)) {
            if value != Scalar::ZERO {
                return Zeroizing::new(value);
            }
        }
    }
}

fn cards(context: &[u8], packed: &[u8]) -> Result<Vec<(u8, Point)>, String> {
    if !context.starts_with(DOMAIN) || context.len() > 256 ||
        packed.is_empty() || packed.len() > MAX_CARDS * CARD_BYTES || packed.len() % CARD_BYTES != 0 {
        return Err("Invalid DLEQ batch size or context".into());
    }
    packed.chunks_exact(CARD_BYTES).map(|card| {
        if card[0] >= MAX_CARDS as u8 {
            return Err("Invalid DLEQ card position".into());
        }
        Ok((card[0], point(&card[1..])?))
    }).collect()
}

fn challenge(prefix: &[u8], position: u8, key: &[u8], a: &[u8], share: &[u8]) -> Scalar {
    // Canonical CBOR map ordered by the encoded keys A, H, S, R1, R2, pos.
    let mut hash = Sha512::new();
    hash.update(prefix);
    hash.update(b"\xa6\x61A\x58\x20");
    hash.update(a);
    hash.update(b"\x61H\x58\x20");
    hash.update(key);
    hash.update(b"\x61S\x58\x20");
    hash.update(&share[..32]);
    hash.update(b"\x62R1\x58\x20");
    hash.update(&share[32..64]);
    hash.update(b"\x62R2\x58\x20");
    hash.update(&share[64..96]);
    hash.update(b"\x63pos");
    if position >= 24 {
        hash.update([24]);
    }
    hash.update([position]);
    Scalar::from_bytes_mod_order_wide(&hash.finalize().into())
}

pub fn create(context: &[u8], secret: &[u8], packed_cards: &[u8]) -> Result<Vec<u8>, String> {
    let secret = Zeroizing::new(scalar(secret)?);
    if *secret == Scalar::ZERO {
        return Err("Zero DLEQ secret".into());
    }
    let cards = cards(context, packed_cards)?;
    let key = Point::mul_base(&secret).compress();
    let mut rng = OsRng;
    let mut shares = Vec::with_capacity(cards.len() * SHARE_BYTES);
    for ((position, a), packed) in cards.into_iter().zip(packed_cards.chunks_exact(CARD_BYTES)) {
        let nonce = random_nonzero(&mut rng);
        let start = shares.len();
        shares.extend_from_slice((a * *secret).compress().as_bytes());
        shares.extend_from_slice(Point::mul_base(&nonce).compress().as_bytes());
        shares.extend_from_slice((a * *nonce).compress().as_bytes());
        let c = challenge(context, position, key.as_bytes(), &packed[1..], &shares[start..]);
        shares.extend_from_slice(&(*nonce + c * *secret).to_bytes());
    }
    Ok(shares)
}

struct Equation {
    a: Point,
    s: Point,
    r1: Point,
    r2: Point,
    z: Scalar,
    c: Scalar,
}

impl Equation {
    fn verify(&self, key: &Point) -> bool {
        Point::mul_base(&self.z) == self.r1 + key * self.c
            && self.a * self.z == self.r2 + self.s * self.c
    }
}

pub fn verify(context: &[u8], key_bytes: &[u8], packed_cards: &[u8], shares: &[u8]) -> Result<bool, String> {
    let cards = cards(context, packed_cards)?;
    let key = point(key_bytes)?;
    if key.is_identity() {
        return Ok(false);
    }
    if shares.len() != cards.len() * SHARE_BYTES {
        return Err("Invalid packed DLEQ share length".into());
    }
    let equations = cards.into_iter().zip(packed_cards.chunks_exact(CARD_BYTES))
        .zip(shares.chunks_exact(SHARE_BYTES))
        .map(|(((position, a), packed), share)| Ok(Equation {
            a,
            s: point(&share[..32])?,
            r1: point(&share[32..64])?,
            r2: point(&share[64..96])?,
            z: scalar(&share[96..])?,
            c: challenge(context, position, key_bytes, &packed[1..], share),
        })).collect::<Result<Vec<_>, String>>()?;
    Ok(verify_batch(&key, &equations) || equations.iter().all(|equation| equation.verify(&key)))
}

fn verify_batch(key: &Point, equations: &[Equation]) -> bool {
    let mut rng = OsRng;
    let mut scalars = Vec::with_capacity(2 + 4 * equations.len());
    let mut points = Vec::with_capacity(scalars.capacity());
    let mut g_coefficient = Scalar::ZERO;
    let mut key_coefficient = Scalar::ZERO;
    // Independent weights for both equations prevent cancellation within or
    // across proofs. All points and scalars are admitted before sampling.
    for e in equations {
        let first = *random_nonzero(&mut rng);
        let second = *random_nonzero(&mut rng);
        g_coefficient += first * e.z;
        key_coefficient -= first * e.c;
        scalars.extend([-first, second * e.z, -second, -(second * e.c)]);
        points.extend([e.r1, e.a, e.r2, e.s]);
    }
    scalars.extend([g_coefficient, key_coefficient]);
    points.extend([G, *key]);
    Point::vartime_multiscalar_mul(scalars, points).is_identity()
}
