use crate::{IntoTranscript, error::*};

use super::{Parameters, Statement, Witness, proof::Proof};


use ark_ec::{CurveGroup, VariableBaseMSM}; // ark_ec::scalar_mul::variable_base
use ark_std::{borrow::BorrowMut, marker::PhantomData, rand::{Rng, CryptoRng}};



pub struct Prover<C: CurveGroup> {
    phantom: PhantomData<C>,
}

impl<C: CurveGroup> Prover<C> {
    pub fn create_proof<R: Rng+CryptoRng>(
        system_rng: &mut R,
        parameters: &Parameters<C>,
        statement: &Statement<C>,
        witness: &Witness<C>,
        t: impl IntoTranscript,
    ) -> CryptoResult<Proof<C>> {
        use ark_std::ops::Mul;

        let mut t = t.into_transcript();
        let t = t.borrow_mut();

        let mut alphas = super::append_n_merge(t,parameters,statement)?;

        let omega: C::ScalarField = t.fork(b"rng").witness(system_rng).read_reduce();
        let a = parameters.g.mul(omega).into_affine();
        let b = if alphas.len() == 0 {
            // assert_eq!(omega, omega * )
            parameters.h[0].mul(omega)
        } else {
            for alpha in alphas.iter_mut() { *alpha *= omega; }
            <C as VariableBaseMSM>::msm(&parameters.h,&alphas).expect("already checked above")
        }.into_affine();

        t.append(&a);
        t.append(&b);

        let c: C::ScalarField = t.challenge(b"ch").read_reduce();

        let r = omega + c * *witness;

        Ok(Proof { a, b, r })
    }
}


