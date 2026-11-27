pub mod proof;
#[cfg(feature="prover")]
pub mod prover;

#[cfg(test)]
mod test;

const NAME: &'static [u8] = b"Schnorr Identification";
const ERROR: &'static str = "Schnorr Identification";

use crate::{IntoTranscript, error::*, zkp::*};
use ark_ec::{CurveGroup,PrimeGroup};
use ark_std::marker::PhantomData;

pub struct SchnorrIdentification<C: CurveGroup> {
    _group: PhantomData<C>,
}

pub type Parameters<C> = <C as CurveGroup>::Affine;

pub type Statement<C> = <C as CurveGroup>::Affine;

pub type Witness<C> = <C as PrimeGroup>::ScalarField;

impl<C: CurveGroup> ArgumentOfKnowledge for SchnorrIdentification<C> {
    type CommonReferenceString = Parameters<C>;
    type Statement = Statement<C>;
    type Witness = Witness<C>;
    type Proof = proof::Proof<C>;

    #[cfg(feature="prover")]
    fn prove<R: Rng+CryptoRng>(
        system_rng: &mut R,
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        witness: &Self::Witness,
        t: impl IntoTranscript,
    ) -> CryptoResult<Self::Proof> {
        Ok(prover::Prover::create_proof(system_rng, common_reference_string, statement, witness, t))
    }

    fn verify(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        proof: &Self::Proof,
        t: impl IntoTranscript,
    ) -> CryptoResult<()> {
        proof.verify(common_reference_string, statement, t)
    }
}

/*
TODO: How should NAME and ERROR be exposed?
impl<C: CurveGroup> SchnorrIdentification<C> {
    pub const PROTOCOL_NAME: &'static [u8] = b"Schnorr Identification Scheme";
}
*/
