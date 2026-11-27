pub mod proof;
#[cfg(feature="prover")]
pub mod prover;

#[cfg(test)]
mod test;

const NAME: &'static [u8] = b"Chaum-Pedersen";
const ERROR: &'static str = "Chaum-Pedersen";
const LENGTH_ERROR: &'static str = "Chaum-Pedersen, wrong statemeent length";

use crate::{IntoTranscript, transcript::Transcript, error::*, zkp::*};
use ark_ec::{CurveGroup,PrimeGroup};
use ark_std::{array::from_ref as one, marker::PhantomData, vec::Vec};

pub struct DLEquality<'a, C: CurveGroup> {
    _group: PhantomData<&'a C>,
}

#[derive(Copy, Clone)]
pub struct Parameters<'a, C: CurveGroup> {
    pub g: &'a C::Affine,
    pub h: &'a [C::Affine],
}

impl<'a, C: CurveGroup> Parameters<'a, C> {
    pub fn new(g: &'a C::Affine, h: &'a C::Affine) -> Self {
        Self { g, h: one(h) }
    }
}

/// Statement for a Chaum-Pedersen proof of discrete logarithm equality.
/// Expects two points $A$ and $B$ such that for some secret $x$ and parameters
/// $G$ and $H$, $A = xG$ and $B=xH$
#[derive(Copy, Clone)]
pub struct Statement<'a, C: CurveGroup>(pub &'a C::Affine, pub &'a [C::Affine]);

impl<'a, C: CurveGroup> Statement<'a, C> {
    pub fn new(point_a: &'a C::Affine, point_b: &'a C::Affine) -> Self {
        Self(point_a, one(point_b))
    }
}

pub(crate) fn append_n_merge<'a,C: CurveGroup>(
    t: &mut Transcript,
    parameters: &Parameters<'a,C>,
    statement: &Statement<'a,C>
) -> CryptoResult<Vec<C::ScalarField>>
{
    let l = parameters.h.len();
    if l != statement.1.len() {
        return Err(CryptoError::ProofVerificationError(LENGTH_ERROR.into()));
    }

    t.label(NAME);
    t.append(parameters.g);
    t.append(parameters.h);
    t.append(statement.0);
    t.append(statement.1);
    Ok(if l == 1 { Vec::new() } else {
        let mut alphas = t.challenge(b"merge");
        // 128 bit scalers appears secure here since we're scaling all of them,
        // except the public key base point. 
        (0..l).map(|_| alphas.read_128bit_scalar::<C::ScalarField>()).collect()
    })
}

type Witness<C> = <C as PrimeGroup>::ScalarField;

impl<'a, C: CurveGroup> ArgumentOfKnowledge for DLEquality<'a, C> {
    type CommonReferenceString = Parameters<'a, C>;
    type Statement = Statement<'a, C>;
    type Witness = Witness<C>;
    type Proof = proof::Proof<C>;

    #[cfg(feature="prover")]
    fn prove<R: Rng+CryptoRng>(
        rng: &mut R,
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        witness: &Self::Witness,
        t: impl IntoTranscript,
    ) -> CryptoResult<Self::Proof> {
        prover::Prover::create_proof(rng, common_reference_string, statement, witness, t)
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


