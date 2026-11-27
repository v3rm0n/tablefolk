use crate::homomorphic_encryption::HomomorphicEncryptionScheme;

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Mul, marker::PhantomData, hash::Hash, vec::Vec, rand::Rng};

pub mod arithmetic_definitions;
mod tests;

#[derive(Copy, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct ElGamal<C: CurveGroup> {
    _group: PhantomData<C>,
}

#[derive(Copy, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Parameters<C: CurveGroup> {
    pub generator: C::Affine,
}

pub type PublicKey<C> = <C as CurveGroup>::Affine;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[repr(transparent)]
pub struct Plaintext<C: CurveGroup>(pub C::Affine);

pub type Generator<C> = Plaintext<C>;

pub type SecretKey<C> = <C as PrimeGroup>::ScalarField;

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Ciphertext<C: CurveGroup>(pub C::Affine, pub C::Affine);

impl<C: CurveGroup> HomomorphicEncryptionScheme<C::ScalarField> for ElGamal<C> {
    type Parameters = Parameters<C>;
    type Generator = Generator<C>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Plaintext = Plaintext<C>;
    type Ciphertext = Ciphertext<C>;

    fn setup<R: Rng>(rng: &mut R) -> Self::Parameters {
        Parameters { generator: C::rand(rng).into() }
    }

    fn generator<R: Rng>(rng: &mut R) -> Self::Generator {
        Generator::rand(rng)
    }

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> (Self::PublicKey, Self::SecretKey) {
        // get a random element from the scalar field
        let secret_key: <C as PrimeGroup>::ScalarField = C::ScalarField::rand(rng);

        // compute secret_key*generator to derive the public key
        let public_key = pp.generator.mul(secret_key).into();

        (public_key, secret_key)
    }

    fn encrypt(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
        r: &C::ScalarField,
    ) -> Self::Ciphertext {
        // compute s = r*pk
        let s = Plaintext(pk.mul(r).into_affine());

        // compute c1 = r*generator
        let c1 = pp.generator.mul(r).into();

        // compute c2 = m + s
        let c2 = *message + s;

        Ciphertext(c1, c2.0)
    }

    fn decrypt(
        _pp: &Self::Parameters,
        sk: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Self::Plaintext {
        let c1: <C as CurveGroup>::Affine = ciphertext.0;
        let c2: <C as CurveGroup>::Affine = ciphertext.1;

        // compute s = secret_key * c1
        let s = c1.mul(sk);
        let s_inv = -s;

        // compute message = c2 - s
        let m = c2 + s_inv;

        Plaintext(m.into_affine())
    }
}
