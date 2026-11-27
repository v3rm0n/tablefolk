use super::{Parameters, Statement};

use crate::{
    IntoTranscript, error::*,
    vector_commitment::HomomorphicCommitmentScheme,
    zkp::{
        arguments::{scalar_powers, zero_value_bilinear_map, zero_value_bilinear_map::YMapping},
        ArgumentOfKnowledge,
    },
};

use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::BorrowMut, vec::Vec};

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize, Debug)]
pub struct Proof<Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    // Round 1
    pub b_commits: Vec<Comm::Commitment>,

    // Round 2
    pub zero_arg_proof: zero_value_bilinear_map::proof::Proof<Scalar, Comm>,
}

impl<Scalar, Comm> Proof<Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub fn verify(
        &self,
        proof_parameters: &Parameters<Scalar, Comm>,
        statement: &Statement<Scalar, Comm>,
        t: impl IntoTranscript,
    ) -> CryptoResult<()> {
        let mut t = t.into_transcript();
        let t = t.borrow_mut();

        t.label(b"hadamard_product_argument");

        // check c_b_1 = c_a_1
        if statement.commitment_to_a[0] != self.b_commits[0] {
            return Err(CryptoError::ProofVerificationError(
                "Hadamard Product (5.1)".into()
            ));
        }

        // check c_b_m = c_b
        if statement.commitment_to_b != self.b_commits[proof_parameters.m - 1] {
            return Err(CryptoError::ProofVerificationError(
                "Hadamard Product (5.1)".into()
            ));
        }

        // Public parameters
        proof_parameters.transcript_append(t);

        // Committed values
        t.append(&self.b_commits);

        // Extract challenges
        let mut tr = t.challenge(b"xy");
        let x: Scalar = tr.read_uniform();
        let y: Scalar = tr.read_uniform();

        // Precompute all powers of the x challenge from 0 to m-1
        let x_challenge_powers = scalar_powers(x, proof_parameters.m - 1);

        // Use the second challenge to define our bilinear mapping
        let prover_mapping = YMapping::new(y, proof_parameters.n);

        let mut c_d_i = self
            .b_commits
            .iter()
            .zip(x_challenge_powers.iter().skip(1))
            .map(|(&b_i_commit, &x_power_i)| b_i_commit * x_power_i)
            .collect::<Vec<Comm::Commitment>>();

        let temp_x_c_d_shifted = self
            .b_commits
            .iter()
            .skip(1)
            .zip(x_challenge_powers.iter().skip(1))
            .map(|(&b_i_commit, &x_power_i)| b_i_commit * x_power_i)
            .collect::<Vec<Comm::Commitment>>();

        let final_cd: Comm::Commitment = temp_x_c_d_shifted
            .iter()
            .fold(Comm::Commitment::zero(), |acc, &x| acc + x);
        c_d_i.push(final_cd);

        // Engage in zero argument
        let zero_arg_parameters = zero_value_bilinear_map::Parameters::new(
            proof_parameters.m,
            proof_parameters.n,
            proof_parameters.commit_key,
        );

        let minus_one = -Scalar::one();
        let vec_minus_ones = vec![minus_one; proof_parameters.n];
        let minus_ones_commit =
            Comm::commit(proof_parameters.commit_key, &vec_minus_ones, Scalar::zero())?;
        let vec_commits_to_a: Vec<Comm::Commitment> =
            [&statement.commitment_to_a[1..], &[minus_ones_commit]]
                .concat()
                .to_vec();

        let zero_arg_statement =
            zero_value_bilinear_map::Statement::new(&vec_commits_to_a, &c_d_i, &prover_mapping);

        match zero_value_bilinear_map::ZeroValueArgument::verify(
            &zero_arg_parameters,
            &zero_arg_statement,
            &self.zero_arg_proof,
            t,
        ) {
            Ok(_) => Ok(()),
            Err(_) => Err(CryptoError::ProofVerificationError(
                "Hadamard Product (5.1)".into()
            )),
        }
    }
}
