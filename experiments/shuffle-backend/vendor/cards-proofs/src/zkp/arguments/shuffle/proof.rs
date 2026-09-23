use super::{Parameters, Statement};

use crate::{
    IntoTranscript, error::*,
    homomorphic_encryption::HomomorphicEncryptionScheme,
    utils::vector_arithmetic::dot_product,
    vector_commitment::HomomorphicCommitmentScheme,
    zkp::arguments::{scalar_powers, matrix_elements_product as product_argument, multi_exponentiation},
};

use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::BorrowMut, vec::Vec,};

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct Proof<Scalar, Enc, Comm>
where
    Scalar: Field,
    Enc: HomomorphicEncryptionScheme<Scalar>,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub a_commits: Vec<Comm::Commitment>,
    pub b_commits: Vec<Comm::Commitment>,
    pub product_argument_proof: product_argument::proof::Proof<Scalar, Comm>,
    pub multi_exp_proof: multi_exponentiation::proof::Proof<Scalar, Enc, Comm>,
}

impl<Scalar, Enc, Comm> Proof<Scalar, Enc, Comm>
where
    Scalar: Field,
    Enc: HomomorphicEncryptionScheme<Scalar>,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub fn verify(
        &self,
        proof_parameters: &Parameters<Scalar, Enc, Comm>,
        statement: &Statement<Scalar, Enc>,
        t: impl IntoTranscript,
    ) -> CryptoResult<()> {
        let mut t = t.into_transcript();
        let t = t.borrow_mut();

        statement.is_valid()?;

        t.label(b"shuffle_argument");

        // public data
        t.append(proof_parameters.public_key);
        t.append(proof_parameters.commit_key);

        // statement
        statement.transcript_append(t);

        // round 1
        t.append(&self.a_commits);
        let x: Scalar = t.challenge(b"x").read_uniform();

        let challenge_powers = scalar_powers(x, statement.m * statement.n)[1..].to_vec();

        // round 2
        t.append(&self.b_commits);
        let mut tr = t.challenge(b"yz");
        let y: Scalar = tr.read_uniform();
        let z: Scalar = tr.read_uniform();

        // PRODUCT ARGUMENT -------------------------------------------------------------
        let z_vec = vec![-z; statement.n];
        let zero = Scalar::zero();
        let single_neg_z_commit = Comm::commit(proof_parameters.commit_key, &z_vec, zero)?;
        let neg_z_commit = vec![single_neg_z_commit; statement.m];

        let c_d = self
            .a_commits
            .iter()
            .zip(self.b_commits.iter())
            .map(|(&a, &b)| a * y + b)
            .collect::<Vec<_>>();

        let verifier_side_expected_product = (1..=statement.n * statement.m)
            .zip(challenge_powers.iter())
            .map(|(i, x_pow_i)| y * Scalar::from(i as u64) + x_pow_i - z)
            .product();

        let product_argument_parameters = product_argument::Parameters::new(
            statement.m,
            statement.n,
            proof_parameters.commit_key,
        );

        let commitments_to_a = c_d
            .iter()
            .zip(neg_z_commit.iter())
            .map(|(&d_commit, &z_commit)| d_commit + z_commit)
            .collect::<Vec<_>>();
        let product_argument_statement =
            product_argument::Statement::new(&commitments_to_a, verifier_side_expected_product);

        self.product_argument_proof.verify(
            &product_argument_parameters,
            &product_argument_statement,
            &mut *t,
        )?;

        // MULTI-EXPONENTIATION ARGUMENT -------------------------------------------------------
        let multi_exp_parameters = multi_exponentiation::Parameters::new(
            proof_parameters.encrypt_parameters,
            proof_parameters.public_key,
            proof_parameters.commit_key,
            proof_parameters.generator,
        );

        let shuffled_chunks = statement
            .shuffled_ciphers
            .chunks(statement.n)
            .map(|c| c.to_vec())
            .collect::<Vec<_>>();

        let product = dot_product(&challenge_powers, statement.input_ciphers).unwrap();

        let multi_exp_statement =
            multi_exponentiation::Statement::new(&shuffled_chunks, product, &self.b_commits);

        self.multi_exp_proof
            .verify(&multi_exp_parameters, &multi_exp_statement, t)?;

        Ok(())
    }
}
