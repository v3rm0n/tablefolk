
use crate::{
    error::*,
    zkp::{ArgumentOfKnowledge, proofs::schnorr_identification::{self as module,ERROR}}
};
use ark_ec::CurveGroup;
use ark_std::rand::thread_rng;
use ark_std::UniformRand;
use rand::{prelude::ThreadRng, Rng};

type Curve = ark_secp256k1::Projective;
type Point = ark_secp256k1::Affine;
type Scalar = ark_secp256k1::Fr;
type Schnorr<'a> = module::SchnorrIdentification<Curve>;
type Parameters = module::Parameters<Curve>;

fn setup<R: Rng>(rng: &mut R) -> CryptoResult<Parameters> {
    Ok(Curve::rand(rng).into_affine())
}

fn test_template() -> (ThreadRng, Parameters, Scalar, Point) {
    use ark_std::ops::Mul;

    let mut rng = thread_rng();

    let crs = setup(&mut rng).unwrap();

    let sk = Scalar::rand(&mut rng);
    let pk = crs.mul(sk).into_affine();

    (rng, crs, sk, pk)
}

#[test]
fn test_honest_prover() {
    let (mut rng, crs, sk, pk) = test_template();

    let seed = b"Initialised with some input";

    let proof = Schnorr::prove(&mut rng, &crs, &pk, &sk, seed).unwrap();

    assert_eq!(Schnorr::verify(&crs, &pk, &proof, seed), Ok(()));
}

#[test]
fn test_malicious_prover() {
    let (mut rng, crs, _, pk) = test_template();

    let another_scalar = Scalar::rand(&mut rng);
    let seed = b"Initialised with some input";

    let invalid_proof =
        Schnorr::prove(&mut rng, &crs, &pk, &another_scalar, seed).unwrap();

    assert_eq!(
        Schnorr::verify(&crs, &pk, &invalid_proof, seed),
        Err(CryptoError::ProofVerificationError(ERROR.into()))
    );
}

