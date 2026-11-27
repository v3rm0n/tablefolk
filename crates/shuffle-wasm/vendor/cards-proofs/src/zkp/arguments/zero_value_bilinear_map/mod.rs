pub mod proof;
#[cfg(feature="prover")]
pub mod prover;
pub mod tests;

use crate::{
    IntoTranscript, error::*, 
    vector_commitment::HomomorphicCommitmentScheme,
    zkp::{*, arguments::scalar_powers}, 
};
use ark_ff::Field;
use ark_std::{marker::PhantomData, vec::Vec};

pub struct ZeroValueArgument<'a, F, Comm>
where
    F: Field,
    Comm: HomomorphicCommitmentScheme<F>,
{
    _field: PhantomData<&'a F>,
    _commitment_scheme: PhantomData<&'a Comm>,
}

impl<'a, Scalar, Comm> ArgumentOfKnowledge for ZeroValueArgument<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    type CommonReferenceString = Parameters<'a, Scalar, Comm>;
    type Statement = Statement<'a, Scalar, Comm>;
    type Witness = Witness<'a, Scalar>;
    type Proof = proof::Proof<Scalar, Comm>;

    #[cfg(feature="prover")]
    fn prove<R: Rng+CryptoRng>(
        rng: &mut R,
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        witness: &Self::Witness,
        t: impl IntoTranscript,
    ) -> CryptoResult<Self::Proof> {
        let prover = prover::Prover::new(common_reference_string, statement, witness);
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

/// Parameters for the zero argument for a bilinear map. Contains a commitment key and the matrix dimensions.
pub struct Parameters<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub commit_key: &'a Comm::CommitKey,
    pub m: usize,
    pub n: usize,
}

impl<'a, Scalar, Comm> Parameters<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub fn new(m: usize, n: usize, commit_key: &'a Comm::CommitKey) -> Self {
        Self { commit_key, m, n }
    }

    pub fn transcript_append(&self, t: &mut crate::Transcript) {
        t.append(self.commit_key);
        // TODO:  We should change these usize to u32 probably.
        let m = self.m as u32;
        t.append(&m);
        let n = self.n as u32;
        t.append(&n);
    }
}

/// Witness for the zero argument for a bilinear map. Contains a matrix A, a vector r, a matrix B and a vector s such that:
/// `commitment_to_a` (see `Statement`) is a vector of commitments to the columns of A using randoms r, `commitment_to_b`
/// (see `Statement`) is a vector of commitments to the columns of B using randoms s and the sum of the column-wise application
/// of the bilinear map to A and B is 0.
pub struct Witness<'a, Scalar>
where
    Scalar: Field,
{
    pub matrix_a: &'a Vec<Vec<Scalar>>,
    pub randoms_for_a_commit: &'a Vec<Scalar>,
    pub matrix_b: &'a Vec<Vec<Scalar>>,
    pub randoms_for_b_commit: &'a Vec<Scalar>,
}

impl<'a, Scalar: Field> Witness<'a, Scalar> {
    pub fn new(
        matrix_a: &'a Vec<Vec<Scalar>>,
        randoms_for_a_commit: &'a Vec<Scalar>,
        matrix_b: &'a Vec<Vec<Scalar>>,
        randoms_for_b_commit: &'a Vec<Scalar>,
    ) -> Self {
        Self {
            matrix_a,
            randoms_for_a_commit,
            matrix_b,
            randoms_for_b_commit,
        }
    }
}

/// Statement for the zero argument for a bilinear map. Contains a vector `commitment_to_a` of commitments to the columns
/// of matrix `A` using the randoms `r` (see `Witness`), a vector `commitment_to_b` of commitments to the columns of matrix
/// B using the randoms `s` (see `Witness`) and a bilinear map Z^n x Z^n -> Z.
pub struct Statement<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub commitment_to_a: &'a Vec<Comm::Commitment>,
    pub commitment_to_b: &'a Vec<Comm::Commitment>,
    pub bilinear_map: &'a YMapping<Scalar>,
}

impl<'a, Scalar, Comm> Statement<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub fn new(
        commitment_to_a: &'a Vec<Comm::Commitment>,
        commitment_to_b: &'a Vec<Comm::Commitment>,
        bilinear_map: &'a YMapping<Scalar>,
    ) -> Self {
        Self {
            commitment_to_a,
            commitment_to_b,
            bilinear_map,
        }
    }
}

pub trait BilinearMap<Scalar: Field> {
    fn compute_mapping(&self, a: &[Scalar], b: &[Scalar]) -> CryptoResult<Scalar>;
}

pub struct YMapping<Scalar: Field> {
    powers: Vec<Scalar>,
}

impl<F: Field> YMapping<F> {
    pub fn new(y: F, n: usize) -> Self {
        let powers = scalar_powers(y, n);
        Self { powers: powers[1..].to_vec() }
    }
}

impl<Scalar: Field> BilinearMap<Scalar> for YMapping<Scalar> {
    fn compute_mapping(&self, a: &[Scalar], b: &[Scalar]) -> CryptoResult<Scalar> {
        if a.len() != b.len() || a.len() != self.powers.len() {
            return Err(CryptoError::BilinearMapLengthError(a.len(), b.len()));
        }

        let result: Scalar = a
            .iter()
            .zip(b.iter())
            .enumerate()
            .map(|(i, (&a_i, &b_i))| a_i * b_i * self.powers[i])
            .sum();

        Ok(result)
    }
}
