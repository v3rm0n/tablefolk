use super::{Parameters, Statement};

use crate::{
    IntoTranscript, error::*,
    homomorphic_encryption::HomomorphicEncryptionScheme,
    utils::vector_arithmetic::dot_product,
    vector_commitment::HomomorphicCommitmentScheme,
    zkp::arguments::scalar_powers,
};

use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::BorrowMut, vec::Vec};

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize, Debug)]
pub struct Proof<Scalar, Enc, Comm>
where
    Scalar: Field,
    Enc: HomomorphicEncryptionScheme<Scalar>,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    // Round 1
    pub(crate) a_0_commit: Comm::Commitment,
    pub(crate) commit_b_k: Vec<Comm::Commitment>,
    pub(crate) vector_e_k: Vec<Enc::Ciphertext>,

    // Round 2
    pub(crate) r_blinded: Scalar,
    pub(crate) b_blinded: Scalar,
    pub(crate) s_blinded: Scalar,
    pub(crate) tau_blinded: Scalar,
    pub(crate) a_blinded: Vec<Scalar>,
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
        statement: &Statement<Scalar, Enc, Comm>,
        t: impl IntoTranscript,
    ) -> CryptoResult<()> {
        let mut t = t.into_transcript();
        let t = t.borrow_mut();

        t.label(b"multi-exponentiation");

        t.append(proof_parameters.public_key);
        t.append(proof_parameters.commit_key);
        t.append(statement.commitments_to_exponents);
        t.append(&statement.product);
        t.append(statement.shuffled_ciphers);

        let m = statement.shuffled_ciphers.len();
        let n = statement.shuffled_ciphers[0].len();
        let num_of_diagonals = 2 * m - 1;

        let dim: [u32; 3] = [m as u32, n as u32, num_of_diagonals as u32];
        t.append(&dim);

        t.append(&self.a_0_commit);
        t.append(&self.commit_b_k);
        t.append(&self.vector_e_k);

        let challenge: Scalar = t.challenge(b"x_powers").read_uniform();

        // Precompute all powers of the challenge from 0 to number_of_diagonals
        let challenge_powers = scalar_powers(challenge, num_of_diagonals);

        // take vector x: x, x^2, x^3, ..., x^m
        let x_array = challenge_powers[1..m + 1].to_vec();

        let left = self.commit_b_k[m];
        let right = Comm::commit(
            proof_parameters.commit_key,
            &vec![Scalar::zero()],
            Scalar::zero(),
        )?;

        if left != right {
            return Err(CryptoError::ProofVerificationError("Multi Exponentiation".into()));
        }

        if self.vector_e_k[m] != statement.product {
            return Err(CryptoError::ProofVerificationError("Multi Exponentiation".into()));
        }

        let c_a_x = dot_product(&x_array, &statement.commitments_to_exponents)?;
        let verifier_commit_a = Comm::commit(
            &proof_parameters.commit_key,
            &self.a_blinded,
            self.r_blinded,
        )?;

        let left = c_a_x + self.a_0_commit;
        if left != verifier_commit_a {
            return Err(CryptoError::ProofVerificationError("Multi Exponentiation".into()));
        }

        let c_b_k = dot_product(&challenge_powers, &self.commit_b_k)?;
        let verif_commit_b = Comm::commit(
            proof_parameters.commit_key,
            &vec![self.b_blinded],
            self.s_blinded,
        )?;
        if c_b_k != verif_commit_b {
            return Err(CryptoError::ProofVerificationError("Multi Exponentiation".into()));
        }

        let sum_e_k = dot_product(&challenge_powers, &self.vector_e_k)?;

        let message = *proof_parameters.generator * self.b_blinded;
        let aggregate_masking_cipher = Enc::encrypt(
            &proof_parameters.encrypt_parameters,
            &proof_parameters.public_key,
            &message,
            &self.tau_blinded,
        );

        /*
            c1 * x^m-1; x[m-1]
            c2 * x^m-2; x[m-2]
            c3 * x^m-3; x[m-3]
            ...
            cm * x^m-m; x[0]
        */

        let verif_rhs: CryptoResult<Vec<Enc::Ciphertext>> = challenge_powers
            .iter()
            .take(m)
            .rev()
            .zip(statement.shuffled_ciphers.iter())
            .map(|(power_of_x, cipher_chunk)| -> CryptoResult<Enc::Ciphertext> {
                // x^m - i * a_vec
                let xm_minus_i_times_a = self
                    .a_blinded
                    .iter()
                    .map(|element_of_a| *element_of_a * *power_of_x)
                    .collect::<Vec<_>>();
                let dot_p = dot_product(&xm_minus_i_times_a, cipher_chunk)?;
                Ok(dot_p)
            })
            .collect();

        let verif_rhs = verif_rhs?.iter().fold(Enc::Ciphertext::zero(), |acc, &x| acc + x);
        if sum_e_k != aggregate_masking_cipher + verif_rhs {
            return Err(CryptoError::ProofVerificationError("Multi Exponentiation".into()));
        }

        Ok(())
    }
}
