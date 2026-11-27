use crate::{IntoTranscript};
use super::{Parameters, Statement, Witness, proof::Proof, NAME};

use ark_ec::{CurveGroup};
use ark_std::{borrow::BorrowMut, marker::PhantomData, rand::{Rng, CryptoRng}};


pub struct Prover<C: CurveGroup> {
    phantom: PhantomData<C>,
}

impl<C: CurveGroup> Prover<C> {
    pub fn create_proof<R: Rng+CryptoRng>(
        system_rng: &mut R,
        pp: &Parameters<C>,
        statement: &Statement<C>,
        witness: &Witness<C>,
        t: impl IntoTranscript,
    ) -> Proof<C> {
        use ark_std::ops::Mul;

        let mut t = t.into_transcript();
        let t = t.borrow_mut();

        t.label(NAME);
        t.append(pp);
        t.append(statement);

        let random: C::ScalarField = t.fork(b"rng").witness(system_rng).read_reduce();
        let random_commit = pp.mul(random);

        t.append(&random_commit);

        let c: C::ScalarField = t.challenge(b"ch").read_reduce();

        let opening = random - c * witness;

        Proof { random_commit, opening, }
    }
}
