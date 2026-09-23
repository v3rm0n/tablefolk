use std::io::{self, Read};
use std::time::Instant;
use serde_json::json;
use shuffle_backend_evaluation::{assess, generate_fixture};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::args().nth(1).as_deref() {
        #[cfg(feature = "candidate-transcript")]
        Some("shuffle-api") => {
            // Local test transport only. Never echo private requests or witnesses.
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Request { statement: Vec<u8>, proof: Option<Vec<u8>>, permutation: Option<Vec<u8>>, randomizers: Option<Vec<u8>> }
            let mut input = String::new();
            io::stdin().take(128 * 1024 + 1).read_to_string(&mut input)?;
            if input.len() > 128 * 1024 { return Err("API test input too large".into()); }
            let request: Request = serde_json::from_str(&input)?;
            let result = match (request.proof, request.permutation, request.randomizers) {
                (Some(proof), None, None) => shuffle_backend_evaluation::verify_candidate_shuffle36(&request.statement, &proof).map(|valid| json!({ "valid": valid })),
                (None, Some(p), Some(r)) => shuffle_backend_evaluation::prove_candidate_shuffle36(&request.statement, &p, &r).map(|proof| json!({ "proof": proof })),
                (None, None, None) => shuffle_backend_evaluation::validate_candidate_shuffle_statement36(&request.statement).map(|_| json!({ "accepted": true })),
                _ => Err("Invalid API test operation".into()),
            };
            println!("{}", match result { Ok(value) => value, Err(_) => json!({ "error": true }) });
        }
        #[cfg(feature = "candidate-transcript")]
        Some("transcript") => println!("{}", shuffle_backend_evaluation::evaluate_transcript_vectors()?),
        #[cfg(feature = "candidate-crs")]
        Some("crs") => println!("{}", shuffle_backend_evaluation::evaluate_crs_vectors()?),
        #[cfg(feature = "candidate-crs")]
        Some("codec") => {
            let mut input = String::new();
            io::stdin().take(8 * 1024 * 1024 + 1).read_to_string(&mut input)?;
            if input.len() > 8 * 1024 * 1024 { return Err("Codec test input too large".into()); }
            let cases: Vec<Vec<u8>> = serde_json::from_str(&input)?;
            if cases.len() > 512 { return Err("Too many codec cases".into()); }
            let results: Vec<_> = cases.iter().map(|bytes| {
                let result = shuffle_backend_evaluation::roundtrip_candidate_proof36(bytes);
                json!({ "accepted": result.is_ok(), "bytes": result.ok() })
            }).collect();
            println!("{}", serde_json::to_string(&results)?);
        }
        #[cfg(feature = "ristretto")]
        Some("adapters") => {
            let mut input = String::new();
            io::stdin().take(1024 * 1024 + 1).read_to_string(&mut input)?;
            println!("{}", shuffle_backend_evaluation::evaluate_adapter_vectors(&input)?);
        }
        Some("generate") => {
            let mut results = Vec::new();
            for &(rows, cols) in shuffle_backend_evaluation::MATRICES {
                for initial in [true, false] {
                    let started = Instant::now();
                    let bytes = generate_fixture(rows, cols, initial)?;
                    let prove_ms = started.elapsed().as_secs_f64() * 1000.0;
                    let started = Instant::now();
                    let report = assess(&bytes)?;
                    let assess_ms = started.elapsed().as_secs_f64() * 1000.0;
                    let passed = report.passed();
                    #[cfg(feature = "candidate-crs")]
                    let proof_wire = Some(shuffle_backend_evaluation::candidate_proof_from_fixture(&bytes)?);
                    #[cfg(not(feature = "candidate-crs"))]
                    let proof_wire: Option<Vec<u8>> = None;
                    results.push(json!({ "fixture": bytes, "report": report, "passed": passed,
                        "proof_wire": proof_wire,
                        "prepare_and_prove_ms": prove_ms, "assess_ms": assess_ms }));
                }
            }
            println!("{}", serde_json::to_string(&results)?);
        }
        Some("verify") => {
            let mut input = String::new();
            io::stdin().take(1024 * 1024).read_to_string(&mut input)?;
            let fixtures: Vec<Vec<u8>> = serde_json::from_str(&input)?;
            let results: Vec<_> = fixtures.iter().map(|bytes| assess(bytes)).collect::<Result<_, _>>()?;
            println!("{}", serde_json::to_string(&results)?);
        }
        _ => return Err("Usage: shuffle-backend-evaluation generate | verify (JSON fixture arrays on stdin)".into()),
    }
    Ok(())
}
