use crate::{IntoTranscript, error::*};

use super::{Parameters, Statement, ERROR};

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::BorrowMut, One, vec::Vec};

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize, Debug)]
pub struct Proof<C>
where
    C: CurveGroup,
{
    pub(crate) a: C::Affine,
    pub(crate) b: C::Affine,
    pub(crate) r: C::ScalarField,
}

fn slice_mul<F: ark_ff::Field>(v: F, i: &[F]) -> impl Iterator<Item=F>
    {  i.iter().map(move |z| v * z)  }

impl<C: CurveGroup> Proof<C> {
    pub fn verify(
        &self,
        parameters: &Parameters<C>,
        statement: &Statement<C>,
        t: impl IntoTranscript,
    ) -> CryptoResult<()> {
        let mut t = t.into_transcript();
        let t = t.borrow_mut();

        let alphas = super::append_n_merge(t,parameters,statement)?;
        let alphas: &[C::ScalarField] = if alphas.len() == 0 { &[One::one()] } else { &alphas };

        t.append(&self.a);
        t.append(&self.b);

        let c: C::ScalarField = t.challenge(b"ch").read_reduce();

        /*
        use ark_std::ops::Mul;

        // g * r ==? a + x*c
        if parameters.g.mul(self.r) != self.a + statement.0.mul(c) {
            return Err(CryptoError::ProofVerificationError(ERROR.into()));
        }

        // h * r ==? b + y*c
        if parameters.h[0].mul(self.r) + statement.1[0].mul(-c) != self.b.into_group() {
            return Err(CryptoError::ProofVerificationError(ERROR.into()));
        }
        */

        // We could merge the g equation more simply in VRFs using all
        // independent hash-to-curves, but in mental poker though
        // we handle base points where all parties together know the
        // relationship to g, so lets seperate the g equation only
        // after hashing r.
        let mut t = t.fork(b"g");  // Avoid mutating the passed t
        t.append(&self.r);
        // TODO:  Ain't so clear read_128bit_scalar would be secure here..
        let c_g: C::ScalarField = t.challenge(b"c_g").read_reduce();

        // g * r ==? a + x*c   -by-   c_h
        // h[i] * r ==? b[i] + y[i]*c   -by-  alphas[i]
        //    sum_i h[i] * (r * alpha[i]) ==? b + sum_i y[i] * (c * alpha[i])

        // g * (r * c_g) + sum_i h[i] * (r * alpha[i])
        //  == a * c_g + x * (c * c_g)
        //     b + sum_i y[i] * (c * alpha[i])

        let points: Vec<C::Affine> = 
            parameters.h.iter().cloned().chain(statement.1.iter().cloned())
            .chain([*parameters.g, self.a, *statement.0])
            .collect();
        let scalars: Vec<C::ScalarField> =
            slice_mul(self.r,alphas).chain(slice_mul(-c,alphas))
            .chain([-self.r * c_g, c_g, c * c_g])
            .collect();

        let m = <C as VariableBaseMSM>::msm(&points,&scalars).expect("already checked above");
        if m != self.b.into_group() {
            return Err(CryptoError::ProofVerificationError(ERROR.into()));
        }
        
        Ok(())
    }
}
