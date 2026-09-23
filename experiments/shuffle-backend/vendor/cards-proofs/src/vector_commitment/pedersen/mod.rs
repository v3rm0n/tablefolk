use crate::{
    error::*,
    utils::cow::CowVec,
    vector_commitment::HomomorphicCommitmentScheme,
};

use ark_ec::{CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{marker::PhantomData, vec::Vec, rand::Rng};

#[cfg(feature = "std")]
use std::io::{self, Write};

pub mod arithmetic_definitions;
mod tests;

#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct PedersenCommitment<C: CurveGroup> {
    _curve: PhantomData<C>,
}

pub fn new_pedersen_commitment<C: CurveGroup>() -> PedersenCommitment<C> {
    PedersenCommitment { _curve: PhantomData }
}

#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct CommitKey<C: CurveGroup> {
    h: C::Affine,
    g: CowVec<C::Affine>,
}

impl<C: CurveGroup> CommitKey<C> {
    pub const fn new(h: C::Affine, g: CowVec<C::Affine>) -> Self {
        Self { h, g }
    }

    pub fn len(&self) -> usize {
        self.g.0.len()
    }

    #[cfg(feature = "std")]
    pub fn to_code_second<W: Write>(&self, w: &mut W, affine: &str) -> io::Result<()> {
        // name: &str, affine: Option<&str>
        // let affine = affine.unwrap_or(std::any::type_name::<<C as CurveGroup>::Affine>());
        // writeln!(w, "pub static {}: &'static CommitKey<{}> = &CommitKey::new(", name, affine )?;
        writeln!(w, "cards_proofs::vector_commitment::pedersen::CommitKey::new(")?;
        crate::utils::write_point(w, affine, &self.h)?;
        writeln!(w, "CowVec::borrowed(TMP) ),")
    }

    #[cfg(feature = "std")]
    pub fn to_code_first<W: Write>(&self, w: &mut W, affine: &str) -> io::Result<()> {
        write!(w, "static TMP: &'static [{}; {}] = &[", affine, self.g.len())?;
        for p in &self.g {
            crate::utils::write_point(w, affine, p)?;
        }
        writeln!(w, "];")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Commitment<C: CurveGroup>(pub C::Affine);

impl<C: CurveGroup> HomomorphicCommitmentScheme<C::ScalarField> for PedersenCommitment<C> {
    type CommitKey = CommitKey<C>;
    type Commitment = Commitment<C>;

    fn setup<R: Rng>(public_randomess: &mut R, len: usize) -> CommitKey<C> {
        let mut g = Vec::with_capacity(len);
        for _ in 0..len {
            g.push(C::rand(public_randomess).into_affine());
        }
        let h = C::rand(public_randomess).into_affine();
        CommitKey::<C> { h, g: CowVec::owned(g) }
    }

    fn commit(
        commit_key: &CommitKey<C>,
        x: &[C::ScalarField],
        r: C::ScalarField,
    ) -> CryptoResult<Self::Commitment> {
        if x.len() > commit_key.g.len() {
            return Err(CryptoError::CommitmentLengthError(
                "Pedersen",
                x.len(),
                commit_key.g.len(),
            ));
        }

        let scalars = [&[r], x].concat();

        let bases = [&[commit_key.h], &commit_key.g[..]].concat();

        // TODO: Here msm_unchecked chops at the shortest length of bases
        // and scalars, which the short_commitment test suggests is the
        // desired behavior, but maybe worth checking on this further.
        Ok(Commitment(
            C::msm_unchecked(&bases, &scalars[..]).into_affine(),
        ))
    }
}
