#[cfg(test)]

mod test {
    use crate::error::*;
    use crate::utils::rand::sample_vector;
    use crate::vector_commitment::{pedersen, HomomorphicCommitmentScheme};
    use crate::zkp::{arguments::single_value_product, ArgumentOfKnowledge};

    use ark_std::{iter::Iterator, vec::Vec, rand::thread_rng, UniformRand};

    // Choose ellitptic curve setting
    type Curve = ark_secp256k1::Projective;
    type Scalar = ark_secp256k1::Fr;

    // Type aliases for concrete instances using the chosen EC.
    type Comm = pedersen::PedersenCommitment<Curve>;
    type Witness<'a> = single_value_product::Witness<'a, Scalar>;
    type Statement<'a> = single_value_product::Statement<'a, Scalar, Comm>;
    type SingleValueProd<'a> = single_value_product::SingleValueProductArgument<'a, Scalar, Comm>;
    type Parameters<'a> = single_value_product::Parameters<'a, Scalar, Comm>;

    #[test]
    fn test_single_product_argument() {
        let n = 13;
        let rng = &mut thread_rng();
        let commit_key = Comm::setup(rng, n);

        let mut a: Vec<Scalar> = sample_vector(rng, n);
        let b: Scalar = a.iter().product();

        let r = Scalar::rand(rng);
        let a_commit = Comm::commit(&commit_key, &a, r).unwrap();

        let parameters = Parameters::new(n, &commit_key);
        let witness = Witness::new(&a, &r);
        let statement = Statement::new(&a_commit, b);

        let seed = b"Initialised with some input";
        let valid_proof =
            SingleValueProd::prove(rng, &parameters, &statement, &witness, seed).unwrap();

        assert_eq!(
            Ok(()),
            valid_proof.verify(&parameters, &statement, seed)
        );

        a[0] = a[0] + a[0];
        let bad_witness = Witness::new(&a, &r);

        let invalid_proof =
            SingleValueProd::prove(rng, &parameters, &statement, &bad_witness, seed)
                .unwrap();

        assert_eq!(
            Err(CryptoError::ProofVerificationError(
                "Single Value Product Argument (5.3)".into()
            )),
            SingleValueProd::verify(&parameters, &statement, &invalid_proof, seed)
        );
    }
}
