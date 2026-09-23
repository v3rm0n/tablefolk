use crate::{IntoTranscript, error::CryptoResult};

#[cfg(feature="prover")]
use ark_std::rand::{Rng, CryptoRng};

pub mod arguments;
// Local adaptation is restricted to shuffle arguments. The application's
// Schnorr/Chaum-Pedersen implementations are separate and unchanged.

pub trait ArgumentOfKnowledge {
    type CommonReferenceString;
    type Statement;
    type Witness;
    type Proof;

    #[cfg(feature="prover")]
    fn prove<R: Rng+CryptoRng>(
        system_rng: &mut R,
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        witness: &Self::Witness,
        t: impl IntoTranscript,
    ) -> CryptoResult<Self::Proof>;

    fn verify(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        proof: &Self::Proof,
        t: impl IntoTranscript,
    ) -> CryptoResult<()>;
}
