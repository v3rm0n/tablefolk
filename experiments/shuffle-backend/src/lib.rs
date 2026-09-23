//! Evaluation of pinned proof equations with optional transcript adaptation; not production.
#[cfg(feature = "candidate-transcript")]
extern crate cards_proofs_sha512 as cards_proofs;
#[cfg(feature = "candidate-transcript")]
mod shuffle_api;
#[cfg(not(feature = "ristretto"))]
use ark_ec::AffineRepr;
use ark_ff::{UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use cards_proofs::{
    homomorphic_encryption::HomomorphicEncryptionScheme,
    utils::permutation::Permutation,
    vector_commitment::HomomorphicCommitmentScheme,
    zkp::{ArgumentOfKnowledge, arguments::shuffle},
};
use rand::{rngs::OsRng, Rng};
use serde::Serialize;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

pub const REVISION: &str = "ac4fb67b612aa89f37f6be72ea74a3c13eff66ca";
/// Structural admission only; establishes no roster or deck provenance.
#[cfg(feature = "candidate-transcript")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn validate_candidate_shuffle_statement36(statement: &[u8]) -> Result<(), String> {
    shuffle_api::validate_statement(statement)
}

#[cfg(feature = "candidate-transcript")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn verify_candidate_shuffle36(statement: &[u8], proof: &[u8]) -> Result<bool, String> {
    shuffle_api::verify(statement, proof)
}

/// Private witness arguments must never be broadcast, logged, or persisted.
#[cfg(feature = "candidate-transcript")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn prove_candidate_shuffle36(statement: &[u8], permutation: &[u8], randomizers: &[u8]) -> Result<Vec<u8>, String> {
    shuffle_api::prove(statement, permutation, randomizers)
}
#[cfg(feature = "candidate-transcript")]
pub const TRANSCRIPT_PROFILE: &str = "bg-ristretto255-36-4x9-fs-candidate-v1";
#[cfg(not(feature = "candidate-transcript"))]
pub const TRANSCRIPT_PROFILE: &str = "upstream-ark-transcript";
#[cfg(feature = "candidate-crs")]
mod crs;
#[cfg(feature = "candidate-crs")]
mod proof_codec;
#[cfg(feature = "candidate-crs")]
pub const CRS_PROFILE: &str = crs::PROFILE;
#[cfg(not(feature = "candidate-crs"))]
pub const CRS_PROFILE: &str = "random-evaluation";
#[cfg(feature = "candidate-crs")]
pub const MATRICES: &[(u32, u32)] = &[(4, 9)];
#[cfg(not(feature = "candidate-crs"))]
pub const MATRICES: &[(u32, u32)] = &[(4, 9), (6, 6)];
const CONTEXT: &[u8] = b"shuffle-evaluation/game-a/round-0/shuffle-0";
#[cfg(feature = "ristretto")]
mod ristretto;
#[cfg(feature = "ristretto")]
mod adapter_vectors;
#[cfg(feature = "ristretto")]
use ristretto::{Scalar, Enc, Comm, CURVE_NAME};
#[cfg(not(feature = "ristretto"))]
mod secp {
    pub type Scalar = ark_secp256k1::Fr;
    pub type Enc = cards_proofs::homomorphic_encryption::el_gamal::ElGamal<ark_secp256k1::Projective>;
    pub type Comm = cards_proofs::vector_commitment::pedersen::PedersenCommitment<ark_secp256k1::Projective>;
    pub const CURVE_NAME: &str = "secp256k1";
}
#[cfg(not(feature = "ristretto"))]
use secp::{Scalar, Enc, Comm, CURVE_NAME};
type Ciphertext = <Enc as HomomorphicEncryptionScheme<Scalar>>::Ciphertext;
type Plaintext = <Enc as HomomorphicEncryptionScheme<Scalar>>::Plaintext;
type Generator = <Enc as HomomorphicEncryptionScheme<Scalar>>::Generator;
type Proof = shuffle::proof::Proof<Scalar, Enc, Comm>;
type Argument<'a> = shuffle::ShuffleArgument<'a, Scalar, Enc, Comm>;

// Public statements and proof only: no key, permutation, or remasking witness.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
struct Fixture {
    rows: u32,
    cols: u32,
    encryption: <Enc as HomomorphicEncryptionScheme<Scalar>>::Parameters,
    public_key: <Enc as HomomorphicEncryptionScheme<Scalar>>::PublicKey,
    commitments: <Comm as HomomorphicCommitmentScheme<Scalar>>::CommitKey,
    generator: Generator,
    input: Vec<Ciphertext>,
    output: Vec<Ciphertext>,
    proof: Proof,
}

#[derive(Serialize)]
pub struct Check {
    pub name: String,
    pub accepted: bool,
    pub expected: bool,
}

#[derive(Serialize)]
pub struct Report {
    pub revision: &'static str,
    pub crs_profile: &'static str,
    pub transcript_profile: &'static str,
    pub challenges: Vec<ChallengeVector>,
    pub proof_codec: Option<&'static str>,
    pub curve: &'static str,
    pub rows: u32,
    pub cols: u32,
    pub initial_identity_a: bool,
    pub proof_bytes: usize,
    pub checks: Vec<Check>,
    // Arkworks is a stream decoder; callers must enforce end-of-input themselves.
    pub upstream_decoder_accepts_proof_suffix: bool,
}

#[derive(Serialize)]
pub struct ChallengeVector {
    pub input: String,
    pub digest: String,
    pub scalar: String,
}

#[cfg(feature = "candidate-transcript")]
fn new_transcript(context: &[u8], encryption: &ristretto::Parameters, generator: &ristretto::Point) -> cards_proofs::Transcript {
    use cards_proofs::transcript::{array, bytes};
    // All other public parameters and ordered decks are appended by the core.
    let root = array(&[bytes(CRS_PROFILE.as_bytes()), bytes(proof_codec::PROFILE.as_bytes()),
        bytes(context), bytes(&encryption.generator.to_bytes()), bytes(&generator.to_bytes())]);
    use sha2::{Digest, Sha256};
    let parts: Vec<_> = std::str::from_utf8(context).expect("Local evaluation context").split('/').collect();
    let game: [u8; 16] = Sha256::digest(parts[1].as_bytes())[..16].try_into().unwrap();
    let round: u64 = parts[2].strip_prefix("round-").unwrap().parse().unwrap();
    cards_proofs::Transcript::new(game, round, parts[3].as_bytes(), &root)
}

#[cfg(feature = "candidate-transcript")]
fn challenge_vectors(f: &Fixture, context: &[u8]) -> Vec<ChallengeVector> {
    let parameters = shuffle::Parameters::new(&f.encryption, &f.public_key, &f.commitments, &f.generator);
    let statement = shuffle::Statement::new(&f.input, &f.output, f.rows as usize, f.cols as usize);
    let mut transcript = new_transcript(context, &f.encryption, &f.generator);
    if Argument::verify(&parameters, &statement, &f.proof, &mut transcript).is_err() { return Vec::new(); }
    records_to_vectors(&transcript)
}

#[cfg(feature = "candidate-transcript")]
fn records_to_vectors(transcript: &cards_proofs::Transcript) -> Vec<ChallengeVector> {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    transcript.records().iter().map(|r| ChallengeVector {
        input: hex(&r.input), digest: hex(&r.digest), scalar: hex(&r.scalar),
    }).collect()
}

#[cfg(feature = "candidate-transcript")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn evaluate_transcript_vectors() -> Result<String, String> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../packages/deck/test-vectors/shuffle-transcript.json"
    )).map_err(|e| e.to_string())?;
    let hex = |s: &str| (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect::<Vec<_>>();
    let mut t = cards_proofs::Transcript::new(
        hex(fixture["context"]["gameId"].as_str().unwrap()).try_into().unwrap(),
        fixture["context"]["round"].as_u64().unwrap(),
        fixture["context"]["phase"].as_str().unwrap().as_bytes(),
        &hex(fixture["root"].as_str().unwrap()));
    for op in fixture["operations"].as_array().unwrap() {
        let bytes = hex(op["bytes"].as_str().unwrap());
        match op["kind"].as_str().unwrap() {
            "label" => t.label(&bytes),
            "append" => t.append_public_bytes(&bytes),
            "challenge" => {
                let mut reader = t.challenge(&bytes);
                for _ in 0..op["count"].as_u64().unwrap() { let _: Scalar = reader.read_uniform(); }
            }
            _ => return Err("Unknown reference operation".into()),
        }
    }
    serde_json::to_string(&records_to_vectors(&t)).map_err(|e| e.to_string())
}

impl Report {
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|check| check.accepted == check.expected)
    }
}

fn serialize<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes).unwrap();
    bytes
}

fn decode_exact<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, String> {
    let mut remaining = bytes;
    let value = T::deserialize_compressed(&mut remaining).map_err(|e| e.to_string())?;
    if !remaining.is_empty() {
        return Err("Trailing bytes".into());
    }
    Ok(value)
}

fn verify(f: &Fixture, context: &[u8]) -> bool {
    #[cfg(feature = "candidate-crs")]
    {
        let Ok((generator, key, _)) = crs::derive() else { return false; };
        if (f.rows, f.cols) != (4, 9) || f.encryption.generator != ristretto::Point::base()
            || f.generator != generator || f.commitments.h != key.h || f.commitments.g != key.g {
            return false;
        }
    }
    let parameters = shuffle::Parameters::new(
        &f.encryption, &f.public_key, &f.commitments, &f.generator,
    );
    let statement = shuffle::Statement::new(
        &f.input, &f.output, f.rows as usize, f.cols as usize,
    );
    #[cfg(feature = "candidate-transcript")]
    let context = new_transcript(context, &f.encryption, &f.generator);
    Argument::verify(&parameters, &statement, &f.proof, context).is_ok()
}

/// Local experiment inputs only; this is not an untrusted-message decoder API.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn generate_fixture(rows: u32, cols: u32, initial_identity_a: bool) -> Result<Vec<u8>, String> {
    if !MATRICES.contains(&(rows, cols)) {
        return Err("Unsupported matrix for this evaluation profile".into());
    }
    let mut rng = OsRng;
    let encryption = Enc::setup(&mut rng);
    let (public_key, secret_key) = Enc::keygen(&encryption, &mut rng);
    #[cfg(not(feature = "candidate-crs"))]
    let (generator, commitments) = (Enc::generator(&mut rng), Comm::setup(&mut rng, cols as usize));
    #[cfg(feature = "candidate-crs")]
    let (generator, commitments, _) = crs::derive()?;
    let messages: Vec<_> = (0..36).map(|_| Plaintext::rand(&mut rng)).collect();
    let input: Vec<_> = messages.iter().map(|message| {
        let randomness = if initial_identity_a { Scalar::zero() } else { nonzero_scalar(&mut rng) };
        Enc::encrypt(&encryption, &public_key, message, &randomness)
    }).collect();
    let permutation = Permutation::from_rng(&mut rng, input.len());
    let randomizers: Vec<Scalar> = (0..36).map(|_| nonzero_scalar(&mut rng)).collect();
    let output: Vec<_> = permutation.apply(&input).iter().zip(&randomizers).map(|(card, r)| {
        *card + Enc::encrypt(&encryption, &public_key, &Plaintext::zero(), r)
    }).collect();
    let expected = permutation.apply(&messages);
    for (card, message) in output.iter().zip(expected) {
        assert_eq!(Enc::decrypt(&encryption, &secret_key, card), message);
    }
    let parameters = shuffle::Parameters::new(&encryption, &public_key, &commitments, &generator);
    let statement = shuffle::Statement::new(&input, &output, rows as usize, cols as usize);
    let witness = shuffle::Witness::new(&permutation, &randomizers);
    #[cfg(feature = "candidate-transcript")]
    let mut transcript = new_transcript(CONTEXT, &encryption, &generator);
    #[cfg(feature = "candidate-transcript")]
    let context = &mut transcript;
    #[cfg(not(feature = "candidate-transcript"))]
    let context = CONTEXT;
    let proof = Argument::prove(&mut rng, &parameters, &statement, &witness, context)
        .map_err(|e| e.to_string())?;
    let fixture = Fixture { rows, cols, encryption, public_key, commitments, generator, input, output, proof };
    #[cfg(feature = "candidate-transcript")]
    {
        let verifier = challenge_vectors(&fixture, CONTEXT);
        if verifier.len() != 8 || transcript.records().len() != 8 ||
            verifier.iter().zip(transcript.records()).any(|(v, p)|
                v.input != p.input.iter().map(|x| format!("{x:02x}")).collect::<String>()) {
            return Err("Prover/verifier transcript disagreement".into());
        }
    }
    Ok(serialize(&fixture))
}

pub fn assess(bytes: &[u8]) -> Result<Report, String> {
    if bytes.len() > 64 * 1024 {
        return Err("Evaluation fixture exceeds 64 KiB".into());
    }
    let f: Fixture = decode_exact(bytes)?;
    #[cfg(feature = "candidate-crs")]
    let f = {
        let mut f = f;
        f.proof = proof_codec::decode(&proof_codec::encode(&f.proof)?)?;
        f
    };
    if !MATRICES.contains(&(f.rows, f.cols)) || f.input.len() != 36 || f.output.len() != 36 {
        return Err("Unexpected evaluation dimensions".into());
    }
    let mut checks = vec![Check { name: "valid".into(), accepted: verify(&f, CONTEXT), expected: true }];
    let mut check = |name: &str, fixture: Fixture| {
        checks.push(Check { name: name.into(), accepted: verify(&fixture, CONTEXT), expected: false });
    };
    let mut changed = f.clone();
    changed.input.swap(0, 1);
    check("input_order", changed);
    let mut changed = f.clone();
    changed.input[0].1 = -changed.input[0].1;
    check("input_card", changed);
    let mut changed = f.clone();
    changed.output.swap(0, 1);
    check("output_order", changed);
    let mut changed = f.clone();
    changed.output[0].1 = -changed.output[0].1;
    check("output_card", changed);
    let mut changed = f.clone();
    changed.public_key = -changed.public_key;
    check("aggregate_key", changed);
    let mut changed = f.clone();
    changed.encryption.generator = -changed.encryption.generator;
    check("encryption_generator", changed);
    let mut changed = f.clone();
    changed.generator.0 = -changed.generator.0;
    check("proof_generator", changed);
    let mut changed = f.clone();
    changed.commitments = Comm::setup(&mut OsRng, f.cols as usize);
    check("commitment_key", changed);
    let mut changed = f.clone();
    changed.proof.a_commits[0].0 = -changed.proof.a_commits[0].0;
    check("proof_commitment", changed);
    let mut changed = f.clone();
    changed.output.pop();
    check("statement_length", changed);
    for (name, context) in [
        ("game_context", b"shuffle-evaluation/game-b/round-0/shuffle-0".as_slice()),
        ("round_context", b"shuffle-evaluation/game-a/round-1/shuffle-0".as_slice()),
        ("seat_context", b"shuffle-evaluation/game-a/round-0/shuffle-1".as_slice()),
    ] {
        checks.push(Check { name: name.into(), accepted: verify(&f, context), expected: false });
    }
    let proof_bytes = serialize(&f.proof);
    let mut suffixed = proof_bytes.clone();
    suffixed.push(0);
    for (name, bytes) in [
        ("truncated_proof", &proof_bytes[..proof_bytes.len() - 1]),
        ("strict_proof_suffix", suffixed.as_slice()),
    ] {
        checks.push(Check { name: name.into(), accepted: decode_exact::<Proof>(bytes).is_ok(), expected: false });
    }
    let upstream_decoder_accepts_proof_suffix = Proof::deserialize_compressed(suffixed.as_slice()).is_ok();
    Ok(Report {
        revision: REVISION,
        crs_profile: CRS_PROFILE,
        transcript_profile: TRANSCRIPT_PROFILE,
        #[cfg(feature = "candidate-transcript")]
        challenges: challenge_vectors(&f, CONTEXT),
        #[cfg(not(feature = "candidate-transcript"))]
        challenges: Vec::new(),
        proof_codec: if cfg!(feature = "candidate-crs") {
            Some("bg-ristretto255-36-4x9-proof-candidate-v1")
        } else { None },
        curve: CURVE_NAME,
        rows: f.rows,
        cols: f.cols,
        initial_identity_a: f.input.iter().all(|c| c.0.is_zero()),
        proof_bytes: proof_bytes.len(),
        checks,
        upstream_decoder_accepts_proof_suffix,
    })
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn evaluate_fixture(bytes: &[u8]) -> Result<String, String> {
    serde_json::to_string(&assess(bytes)?).map_err(|e| e.to_string())
}

#[cfg(feature = "ristretto")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn evaluate_adapter_vectors(request: &str) -> Result<String, String> {
    adapter_vectors::evaluate(request)
}

#[cfg(feature = "candidate-crs")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn evaluate_crs_vectors() -> Result<String, String> {
    serde_json::to_string(&crs::derive()?.2).map_err(|e| e.to_string())
}

/// Structural codec validation only; does not verify proof equations.
#[cfg(feature = "candidate-crs")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn roundtrip_candidate_proof36(bytes: &[u8]) -> Result<Vec<u8>, String> {
    proof_codec::encode(&proof_codec::decode(bytes)?)
}

/// Local trusted fixture conversion; the outer fixture decoder is NOT hardened.
#[cfg(feature = "candidate-crs")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn candidate_proof_from_fixture(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() > 64 * 1024 { return Err("Fixture too large".into()); }
    let f: Fixture = decode_exact(bytes)?;
    if (f.rows, f.cols) != (4, 9) { return Err("Unsupported proof dimensions".into()); }
    proof_codec::encode(&f.proof)
}

fn nonzero_scalar<R: Rng>(rng: &mut R) -> Scalar {
    loop {
        let scalar = Scalar::rand(rng);
        if !scalar.is_zero() { return scalar; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "candidate-transcript")]
    #[test]
    fn independent_python_transcript_vectors_match() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../packages/deck/test-vectors/shuffle-transcript.json"
        )).unwrap();
        let actual: serde_json::Value = serde_json::from_str(&evaluate_transcript_vectors().unwrap()).unwrap();
        assert_eq!(actual, fixture["challenges"]);
    }

    #[cfg(feature = "candidate-transcript")]
    #[test]
    fn transcript_bounds_fail_before_growth() {
        use cards_proofs::Transcript;
        use std::panic::{catch_unwind, AssertUnwindSafe};
        assert!(catch_unwind(|| Transcript::new([0; 16], 0, b"test", &[])).is_err());
        assert!(catch_unwind(|| Transcript::new([0; 16], 0, b"test", &[0; 1025])).is_err());
        let mut t = Transcript::new([0; 16], 0, b"test", &[1]);
        for _ in 0..3 { t.append_public_bytes(&[0; 8192]); }
        assert!(catch_unwind(AssertUnwindSafe(|| t.append_public_bytes(&[0; 8192]))).is_err());
        let mut t = Transcript::new([0; 16], 0, b"test", &[1]);
        for _ in 0..128 { t.label(b"a"); }
        assert!(catch_unwind(AssertUnwindSafe(|| t.label(b"a"))).is_err());
        let mut t = Transcript::new([0; 16], 0, b"test", &[1]);
        let mut reader = t.challenge(b"x");
        for _ in 0..16 { let _: Scalar = reader.read_uniform(); }
        assert!(catch_unwind(AssertUnwindSafe(|| { let _: Scalar = reader.read_uniform(); })).is_err());
    }

    #[cfg(feature = "candidate-transcript")]
    #[test]
    fn context_integer_framing_matches_canonical_cbor() {
        for (round, expected) in [
            (0u64, "00"), (23, "17"), (24, "1818"), (255, "18ff"), (256, "190100"),
            (65535, "19ffff"), (65536, "1a00010000"), (4294967295, "1affffffff"),
            (4294967296, "1b0000000100000000"), (9007199254740991, "1b001fffffffffffff"),
        ] {
            let mut t = cards_proofs::Transcript::new([0; 16], round, b"shuffle-0", &[1]);
            let _: Scalar = t.challenge(b"x").read_uniform();
            let offset = b"p2pcards/v1/shuffle".len() + 16;
            let hex: String = t.records()[0].input[offset..offset + expected.len()/2]
                .iter().map(|x| format!("{x:02x}")).collect();
            assert_eq!(hex, expected);
        }
    }

    #[cfg(feature = "candidate-crs")]
    #[test]
    fn candidate_rejects_other_layouts_and_each_replaced_parameter() {
        assert!(generate_fixture(6, 6, true).is_err());
        let bytes = generate_fixture(4, 9, true).unwrap();
        let f: Fixture = decode_exact(&bytes).unwrap();
        let mut changed = f.clone();
        changed.commitments.h = -changed.commitments.h;
        assert!(!verify(&changed, CONTEXT));
        for index in 0..9 {
            let mut changed = f.clone();
            changed.commitments.g[index] = -changed.commitments.g[index];
            assert!(!verify(&changed, CONTEXT));
        }
        let mut changed = f.clone();
        changed.commitments.g.pop();
        assert!(!verify(&changed, CONTEXT));
        let mut changed = f.clone();
        changed.commitments.g.push(changed.commitments.h);
        assert!(!verify(&changed, CONTEXT));
        let mut changed = f.clone();
        changed.commitments.g.swap(0, 1);
        assert!(!verify(&changed, CONTEXT));
        let mut changed = f.clone();
        changed.rows = 6;
        changed.cols = 6;
        assert!(assess(&serialize(&changed)).is_err());
    }

    #[test]
    fn valid_and_changed_statements_for_both_matrices_and_input_forms() {
        for &(rows, cols) in MATRICES {
            for initial in [true, false] {
                let fixture = generate_fixture(rows, cols, initial).unwrap();
                let report = assess(&fixture).unwrap();
                assert!(report.passed(), "{}", serde_json::to_string_pretty(&report).unwrap());
            }
        }
    }
}
