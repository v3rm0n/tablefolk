pub mod proof;
#[cfg(feature="prover")]
pub mod prover;
mod tests;

use crate::{
    IntoTranscript, error::*,
    homomorphic_encryption::HomomorphicEncryptionScheme,
    utils::permutation::Permutation,
    vector_commitment::HomomorphicCommitmentScheme,
    zkp::*,
};

use ark_ff::Field;
use ark_std::{marker::PhantomData};

pub struct ShuffleArgument<
    'a,
    F: Field,
    Enc: HomomorphicEncryptionScheme<F>,
    Comm: HomomorphicCommitmentScheme<F>,
> {
    _field: PhantomData<&'a F>,
    _encryption_scheme: PhantomData<&'a Enc>,
    _commitment_scheme: PhantomData<&'a Comm>,
}

impl<'a, F, Enc, Comm> ArgumentOfKnowledge for ShuffleArgument<'a, F, Enc, Comm>
where
    F: Field,
    Enc: HomomorphicEncryptionScheme<F>,
    Comm: HomomorphicCommitmentScheme<F>,
{
    type CommonReferenceString = Parameters<'a, F, Enc, Comm>;
    type Statement = Statement<'a, F, Enc>;
    type Witness = Witness<'a, F>;
    type Proof = proof::Proof<F, Enc, Comm>;

    #[cfg(feature="prover")]
    fn prove<R: Rng+CryptoRng>(
        rng: &mut R,
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        witness: &Self::Witness,
        t: impl IntoTranscript,
    ) -> CryptoResult<Self::Proof> {
        let prover = prover::Prover::new(&common_reference_string, &statement, &witness);
        let proof = prover.prove(rng, t)?;
        Ok(proof)
    }

    fn verify(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        proof: &Self::Proof,
        t: impl IntoTranscript,
    ) -> CryptoResult<()> {
        proof.verify(&common_reference_string, &statement, t)
    }
}

/// Parameters for the product argument
pub struct Parameters<'a, Scalar, Enc, Comm>
where
    Scalar: Field,
    Enc: HomomorphicEncryptionScheme<Scalar>,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub encrypt_parameters: &'a Enc::Parameters,
    pub public_key: &'a Enc::PublicKey,
    pub commit_key: &'a Comm::CommitKey,
    pub generator: &'a Enc::Generator,
}

impl<'a, Scalar, Enc, Comm> Parameters<'a, Scalar, Enc, Comm>
where
    Scalar: Field,
    Enc: HomomorphicEncryptionScheme<Scalar>,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub fn new(
        encrypt_parameters: &'a Enc::Parameters,
        public_key: &'a Enc::PublicKey,
        commit_key: &'a Comm::CommitKey,
        generator: &'a Enc::Generator,
    ) -> Self {
        Self {
            encrypt_parameters,
            public_key,
            commit_key,
            generator,
        }
    }
}

/// Statement of a shuffle. Contains the input ciphertexts, the output ciphertexts and the matrix dimensions
pub struct Statement<'a, Scalar, Enc>
where
    Scalar: Field,
    Enc: HomomorphicEncryptionScheme<Scalar>,
{
    pub input_ciphers: &'a [Enc::Ciphertext],
    pub shuffled_ciphers: &'a [Enc::Ciphertext],
    pub m: usize,
    pub n: usize,
}

impl<'a, Scalar, Enc> Statement<'a, Scalar, Enc>
where
    Scalar: Field,
    Enc: HomomorphicEncryptionScheme<Scalar>,
{
    pub fn new(
        input_ciphers: &'a [Enc::Ciphertext],
        shuffled_ciphers: &'a [Enc::Ciphertext],
        m: usize,
        n: usize,
    ) -> Self {
        Self {
            input_ciphers,
            shuffled_ciphers,
            m,
            n,
        }
    }

    pub fn is_valid(&self) -> CryptoResult<()> {
        if self.input_ciphers.len() != self.shuffled_ciphers.len()
            || self.input_ciphers.len() != self.m * self.n
            || self.shuffled_ciphers.len() != self.m * self.n
        {
            return Err(CryptoError::InvalidShuffleStatement);
        }
        Ok(())
    }

    pub fn transcript_append(&self, t: &mut crate::Transcript) {
        t.append(self.input_ciphers);
        t.append(self.shuffled_ciphers);
        // TODO:  We should change these usize to u32 probably.
        let m = self.m as u32;
        t.append(&m);
        let n = self.n as u32;
        t.append(&n);
    }
}

/// Witness
pub struct Witness<'a, Scalar: Field> {
    pub permutation: &'a Permutation,
    pub rho: &'a [Scalar],
}

impl<'a, Scalar: Field> Witness<'a, Scalar> {
    pub fn new(permutation: &'a Permutation, rho: &'a [Scalar]) -> Self {
        Self { permutation, rho }
    }
}
