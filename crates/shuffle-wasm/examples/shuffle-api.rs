//! Local test transport for native/WASM comparisons.
use serde_json::json;
use shuffle_wasm::{
    prove_candidate_shuffle, validate_candidate_shuffle_statement, verify_candidate_shuffle,
};
use std::io::{self, Read};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Local test transport only. Never echo private requests or witnesses.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        statement: Vec<u8>,
        proof: Option<Vec<u8>>,
        permutation: Option<Vec<u8>>,
        randomizers: Option<Vec<u8>>,
    }
    let mut input = String::new();
    io::stdin()
        .take(128 * 1024 + 1)
        .read_to_string(&mut input)?;
    if input.len() > 128 * 1024 {
        return Err("API test input too large".into());
    }
    let request: Request = serde_json::from_str(&input)?;
    let result = match (request.proof, request.permutation, request.randomizers) {
        (Some(proof), None, None) => verify_candidate_shuffle(&request.statement, &proof)
            .map(|valid| json!({ "valid": valid })),
        (None, Some(p), Some(r)) => prove_candidate_shuffle(&request.statement, &p, &r)
            .map(|proof| json!({ "proof": proof })),
        (None, None, None) => validate_candidate_shuffle_statement(&request.statement)
            .map(|_| json!({ "accepted": true })),
        _ => Err("Invalid API test operation".into()),
    };
    println!(
        "{}",
        match result {
            Ok(value) => value,
            Err(_) => json!({ "error": true }),
        }
    );
    Ok(())
}
