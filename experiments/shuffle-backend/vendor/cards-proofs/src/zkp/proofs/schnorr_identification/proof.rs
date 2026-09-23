use crate::{IntoTranscript, error::*};
use super::{Parameters, Statement, NAME, ERROR};

use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::BorrowMut, vec::Vec};


#[derive(Copy, Clone, CanonicalDeserialize, CanonicalSerialize, Debug, PartialEq, Eq)]
pub struct Proof<C: CurveGroup> {
    pub(crate) random_commit: C,
    pub(crate) opening: C::ScalarField,
}

impl<C: CurveGroup> Proof<C> {
    pub fn verify(
        &self,
        pp: &Parameters<C>,
        statement: &Statement<C>,
        t: impl IntoTranscript,
    ) -> CryptoResult<()> {
        use ark_std::ops::Mul;

        let mut t = t.into_transcript();
        let t = t.borrow_mut();

        t.label(NAME);
        t.append(pp);
        t.append(statement);
        t.append(&self.random_commit);

        let c: C::ScalarField = t.challenge(b"ch").read_reduce();

        if pp.mul(self.opening) + statement.mul(c) != self.random_commit {
            return Err(CryptoError::ProofVerificationError(ERROR.into()));
        }

        Ok(())
    }
}
