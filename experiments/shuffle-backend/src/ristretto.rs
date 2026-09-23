//! Experimental arithmetic adapters for the upstream scheme traits.
//! The upstream proof equations/transcript remain unchanged.
use std::{iter::Sum, ops::{Add, Mul, Neg}};
use ark_ff::{UniformRand, Zero};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError,
    Valid, Validate, Write,
};
use cards_proofs::{
    error::{CryptoError, CryptoResult},
    homomorphic_encryption::HomomorphicEncryptionScheme,
    vector_commitment::HomomorphicCommitmentScheme,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as DalekScalar,
    traits::Identity,
};
use rand::{Rng, distributions::{Distribution, Standard}};

// Only the scalar field is reused: no Edwards point representation or encoding.
pub type Scalar = ark_ed25519::Fr;
pub const CURVE_NAME: &str = "ristretto255";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point(pub RistrettoPoint);

impl Point {
    pub fn base() -> Self { Self(RISTRETTO_BASEPOINT_POINT) }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| SerializationError::InvalidData)?;
        let point = CompressedRistretto(bytes).decompress().ok_or(SerializationError::InvalidData)?;
        if point.compress().to_bytes() != bytes {
            return Err(SerializationError::InvalidData);
        }
        Ok(Self(point))
    }

    pub fn from_uniform_bytes(bytes: &[u8; 64]) -> Self {
        Self(RistrettoPoint::from_uniform_bytes(bytes))
    }

    pub fn to_bytes(self) -> [u8; 32] { self.0.compress().to_bytes() }
}

pub fn scalar_bytes(value: Scalar) -> [u8; 32] {
    let mut bytes = [0; 32];
    value.serialize_compressed(&mut bytes[..]).expect("32-byte scalar encoding");
    bytes
}

fn dalek_scalar(value: Scalar) -> DalekScalar {
    // Reject rather than reduce if the selected Arkworks field ever disagrees.
    Option::<DalekScalar>::from(DalekScalar::from_canonical_bytes(scalar_bytes(value)))
        .expect("Arkworks and Dalek scalar fields must agree")
}

impl Distribution<Point> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Point {
        let mut bytes = [0; 64];
        rng.fill_bytes(&mut bytes);
        // Map uniform bytes; do not construct Pedersen bases as known scalars * G.
        Point::from_uniform_bytes(&bytes)
    }
}

impl Add for Point {
    type Output = Self;
    fn add(self, other: Self) -> Self { Self(self.0 + other.0) }
}
impl Neg for Point {
    type Output = Self;
    fn neg(self) -> Self { Self(-self.0) }
}
impl Mul<Scalar> for Point {
    type Output = Self;
    fn mul(self, scalar: Scalar) -> Self { Self(self.0 * dalek_scalar(scalar)) }
}
impl Zero for Point {
    fn zero() -> Self { Self(RistrettoPoint::identity()) }
    fn is_zero(&self) -> bool { self.0 == RistrettoPoint::identity() }
}
impl Sum for Point {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self { iter.fold(Self::zero(), |a, b| a + b) }
}
impl Valid for Point {
    // Dalek's RistrettoPoint only represents valid abstract group elements.
    fn check(&self) -> Result<(), SerializationError> { Ok(()) }
}
impl CanonicalSerialize for Point {
    fn serialize_with_mode<W: Write>(&self, mut writer: W, _: Compress) -> Result<(), SerializationError> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }
    fn serialized_size(&self, _: Compress) -> usize { 32 }
}
impl CanonicalDeserialize for Point {
    fn deserialize_with_mode<R: Read>(mut reader: R, _: Compress, _: Validate) -> Result<Self, SerializationError> {
        let mut bytes = [0; 32];
        reader.read_exact(&mut bytes)?;
        // Even Validate::No cannot create an invalid point. Both modes use RFC encoding.
        Self::from_bytes(&bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Ciphertext(pub Point, pub Point);

impl Add for Ciphertext {
    type Output = Self;
    fn add(self, other: Self) -> Self { Self(self.0 + other.0, self.1 + other.1) }
}
impl Mul<Scalar> for Ciphertext {
    type Output = Self;
    fn mul(self, scalar: Scalar) -> Self { Self(self.0 * scalar, self.1 * scalar) }
}
impl Zero for Ciphertext {
    fn zero() -> Self { Self(Point::zero(), Point::zero()) }
    fn is_zero(&self) -> bool { self.0.is_zero() && self.1.is_zero() }
}
impl Sum for Ciphertext {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self { iter.fold(Self::zero(), |a, b| a + b) }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Parameters { pub generator: Point }

#[derive(Clone, Copy)]
pub struct Enc;

impl HomomorphicEncryptionScheme<Scalar> for Enc {
    type Parameters = Parameters;
    type PublicKey = Point;
    type SecretKey = Scalar;
    type Generator = Point;
    type Plaintext = Point;
    type Ciphertext = Ciphertext;

    fn setup<R: Rng>(_: &mut R) -> Parameters { Parameters { generator: Point::base() } }
    fn generator<R: Rng>(rng: &mut R) -> Point { nonidentity_point(rng) }
    fn keygen<R: Rng>(pp: &Parameters, rng: &mut R) -> (Point, Scalar) {
        let secret = super::nonzero_scalar(rng);
        (pp.generator * secret, secret)
    }
    // This is the algebra used inside proofs. Zero scalars/plaintexts are valid;
    // fresh private mask/key generation has separate nonzero constraints.
    fn encrypt(pp: &Parameters, pk: &Point, message: &Point, r: &Scalar) -> Ciphertext {
        Ciphertext(pp.generator * *r, *message + *pk * *r)
    }
    fn decrypt(_: &Parameters, sk: &Scalar, cipher: &Ciphertext) -> Point {
        cipher.1 + -(cipher.0 * *sk)
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct CommitKey {
    pub h: Point,
    pub g: Vec<Point>,
}

#[derive(Clone, Copy)]
pub struct Comm;

impl HomomorphicCommitmentScheme<Scalar> for Comm {
    type CommitKey = CommitKey;
    type Commitment = Point;

    fn setup<R: Rng>(rng: &mut R, len: usize) -> CommitKey {
        let h = nonidentity_point(rng);
        let mut g = Vec::with_capacity(len);
        while g.len() < len {
            let point = nonidentity_point(rng);
            if point != h && !g.contains(&point) { g.push(point); }
        }
        // Local evaluation parameters only; no production CRS derivation is implied.
        CommitKey { h, g }
    }
    fn commit(key: &CommitKey, values: &[Scalar], randomness: Scalar) -> CryptoResult<Point> {
        if values.len() > key.g.len() {
            return Err(CryptoError::CommitmentLengthError("Ristretto Pedersen", values.len(), key.g.len()));
        }
        Ok(key.h * randomness + key.g.iter().zip(values).map(|(g, x)| *g * *x).sum())
    }
}

fn nonidentity_point<R: Rng>(rng: &mut R) -> Point {
    loop {
        let point = Point::rand(rng);
        if !point.is_zero() { return point; }
    }
}

#[cfg(test)]
#[path = "ristretto-tests.rs"]
mod tests;
