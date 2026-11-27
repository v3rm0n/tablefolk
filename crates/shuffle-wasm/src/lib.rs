//! Bounded Bayer–Groth shuffle proving and verification over Ristretto255.
mod crs;
mod dimensions;
mod proof_codec;
mod ristretto;
mod shuffle_api;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use cards_proofs::zkp::arguments::shuffle;
use ristretto::{Comm, Enc, Scalar};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

type Proof = shuffle::proof::Proof<Scalar, Enc, Comm>;
type Argument<'a> = shuffle::ShuffleArgument<'a, Scalar, Enc, Comm>;

/// Structural admission only; establishes no roster or deck provenance.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn validate_candidate_shuffle_statement(statement: &[u8]) -> Result<(), String> {
    shuffle_api::validate_statement(statement)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn verify_candidate_shuffle(statement: &[u8], proof: &[u8]) -> Result<bool, String> {
    shuffle_api::verify(statement, proof)
}

/// Private witness arguments must never be broadcast, logged, or persisted.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn prove_candidate_shuffle(
    statement: &[u8],
    permutation: &[u8],
    randomizers: &[u8],
) -> Result<Vec<u8>, String> {
    shuffle_api::prove(statement, permutation, randomizers)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_python_transcript_vectors_match() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../packages/deck/test-vectors/shuffle-transcript.json"
        ))
        .unwrap();
        let actual: serde_json::Value =
            serde_json::from_str(&evaluate_transcript_vectors().unwrap()).unwrap();
        assert_eq!(actual, fixture["challenges"]);
    }

    #[test]
    fn transcript_bounds_fail_before_growth() {
        use cards_proofs::{Transcript, transcript::MAX_PUBLIC_BYTES};
        use std::panic::{AssertUnwindSafe, catch_unwind};
        assert!(catch_unwind(|| Transcript::new([0; 16], 0, b"test", &[])).is_err());
        assert!(catch_unwind(|| Transcript::new([0; 16], 0, b"test", &[0; 1025])).is_err());
        let mut t = Transcript::new([0; 16], 0, b"test", &[1]);
        for _ in 0..7 {
            t.append_public_bytes(&[0; MAX_PUBLIC_BYTES]);
        }
        assert!(
            catch_unwind(AssertUnwindSafe(
                || t.append_public_bytes(&[0; MAX_PUBLIC_BYTES])
            ))
            .is_err()
        );
        let mut t = Transcript::new([0; 16], 0, b"test", &[1]);
        for _ in 0..128 {
            t.label(b"a");
        }
        assert!(catch_unwind(AssertUnwindSafe(|| t.label(b"a"))).is_err());
        let mut t = Transcript::new([0; 16], 0, b"test", &[1]);
        let mut reader = t.challenge(b"x");
        for _ in 0..16 {
            let _: Scalar = reader.read_uniform();
        }
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _: Scalar = reader.read_uniform();
            }))
            .is_err()
        );
    }

    #[test]
    fn context_integer_framing_matches_canonical_cbor() {
        for (round, expected) in [
            (0u64, "00"),
            (23, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (65535, "19ffff"),
            (65536, "1a00010000"),
            (4294967295, "1affffffff"),
            (4294967296, "1b0000000100000000"),
            (9007199254740991, "1b001fffffffffffff"),
        ] {
            let mut t = cards_proofs::Transcript::new([0; 16], round, b"shuffle-0", &[1]);
            let _: Scalar = t.challenge(b"x").read_uniform();
            let offset = b"p2pcards/v1/shuffle".len() + 16;
            let hex: String = t.records()[0].input[offset..offset + expected.len() / 2]
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect();
            assert_eq!(hex, expected);
        }
    }

    #[derive(serde::Serialize)]
    struct ChallengeVector {
        input: String,
        digest: String,
        scalar: String,
    }
    fn records_to_vectors(transcript: &cards_proofs::Transcript) -> Vec<ChallengeVector> {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        transcript
            .records()
            .iter()
            .map(|r| ChallengeVector {
                input: hex(&r.input),
                digest: hex(&r.digest),
                scalar: hex(&r.scalar),
            })
            .collect()
    }

    fn evaluate_transcript_vectors() -> Result<String, String> {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../packages/deck/test-vectors/shuffle-transcript.json"
        ))
        .map_err(|e| e.to_string())?;
        let hex = |s: &str| {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>()
        };
        let mut t = cards_proofs::Transcript::new(
            hex(fixture["context"]["gameId"].as_str().unwrap())
                .try_into()
                .unwrap(),
            fixture["context"]["round"].as_u64().unwrap(),
            fixture["context"]["phase"].as_str().unwrap().as_bytes(),
            &hex(fixture["root"].as_str().unwrap()),
        );
        for op in fixture["operations"].as_array().unwrap() {
            let bytes = hex(op["bytes"].as_str().unwrap());
            match op["kind"].as_str().unwrap() {
                "label" => t.label(&bytes),
                "append" => t.append_public_bytes(&bytes),
                "challenge" => {
                    let mut reader = t.challenge(&bytes);
                    for _ in 0..op["count"].as_u64().unwrap() {
                        let _: Scalar = reader.read_uniform();
                    }
                }
                _ => return Err("Unknown reference operation".into()),
            }
        }
        serde_json::to_string(&records_to_vectors(&t)).map_err(|e| e.to_string())
    }
}
