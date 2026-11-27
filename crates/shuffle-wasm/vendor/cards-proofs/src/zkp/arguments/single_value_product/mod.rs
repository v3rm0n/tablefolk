pub mod proof;
#[cfg(feature="prover")]
pub mod prover;
mod tests;

use crate::{
    IntoTranscript, error::*,
    vector_commitment::HomomorphicCommitmentScheme,
    zkp::*,
};
use ark_ff::Field;
use ark_std::{marker::PhantomData, vec::Vec};

pub struct SingleValueProductArgument<'a, F, Comm>
where
    F: Field,
    Comm: HomomorphicCommitmentScheme<F>,
{
    _field: PhantomData<&'a F>,
    _commitment_scheme: PhantomData<&'a Comm>,
}

impl<'a, Scalar, Comm> ArgumentOfKnowledge for SingleValueProductArgument<'a, Scalar, Comm>
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

/// Parameters
pub struct Parameters<'a, F, Comm>
where
    F: Field,
    Comm: HomomorphicCommitmentScheme<F>,
{
    pub commit_key: &'a Comm::CommitKey,
    pub n: usize,
}

impl<'a, F, Comm> Parameters<'a, F, Comm>
where
    F: Field,
    Comm: HomomorphicCommitmentScheme<F>,
{
    pub fn new(n: usize, commit_key: &'a Comm::CommitKey) -> Self {
        Self { commit_key, n }
    }
}

/// Witness
pub struct Witness<'a, Scalar: Field> {
    pub a: &'a Vec<Scalar>,
    pub random_for_a_commit: &'a Scalar,
}

impl<'a, Scalar: Field> Witness<'a, Scalar> {
    pub fn new(a: &'a Vec<Scalar>, random_for_a_commit: &'a Scalar) -> Self {
        Self { a, random_for_a_commit }
    }
}

/// Statement
pub struct Statement<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub a_commit: &'a Comm::Commitment,
    pub b: Scalar,
}

impl<'a, Scalar, Comm> Statement<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub fn new(a_commit: &'a Comm::Commitment, b: Scalar) -> Self {
        Self { a_commit, b }
    }
}
