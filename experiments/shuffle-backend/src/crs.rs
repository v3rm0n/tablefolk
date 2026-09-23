//! Independent fixed-tuple CBOR/SHA-512 implementation of the candidate CRS.
//! This does not adapt the upstream Fiat-Shamir transcript.
use sha2::{Digest, Sha512};
use ark_ff::Zero;
use serde::Serialize;
use crate::ristretto::{CommitKey, Point};

pub const PROFILE: &str = "bg-ristretto255-36-4x9-crs-candidate-v1";

#[derive(Serialize)]
pub struct Vector {
    role: &'static str,
    index: u8,
    input: String,
    digest: String,
    point: String,
}

// Only these internal ASCII constants are encoded, never arbitrary caller data.
fn text(out: &mut Vec<u8>, value: &str) {
    assert!(value.is_ascii() && value.len() < 256);
    if value.len() < 24 { out.push(0x60 + value.len() as u8); }
    else { out.extend_from_slice(&[0x78, value.len() as u8]); }
    out.extend_from_slice(value.as_bytes());
}

fn input(role: &str, index: u8) -> Vec<u8> {
    assert!(index < 24);
    let mut out = b"p2pcards/v1/shuffle".to_vec();
    out.push(0x86);
    text(&mut out, "crs");
    text(&mut out, PROFILE);
    out.extend_from_slice(&[4, 9]);
    text(&mut out, role);
    out.push(index);
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn validate(point: Point, previous: &[Point]) -> Result<(), String> {
    if point.is_zero() || previous.iter().any(|p| point == *p || point == -*p) {
        return Err("Degenerate shuffle CRS; profile revision required".into());
    }
    Ok(())
}

pub fn derive() -> Result<(Point, CommitKey, Vec<Vector>), String> {
    let mut points = vec![Point::base()];
    let mut vectors = Vec::with_capacity(11);
    for (role, count) in [("proof", 1), ("blinding", 1), ("message", 9)] {
        for index in 0..count {
            let input = input(role, index);
            let digest: [u8; 64] = Sha512::digest(&input).into();
            let point = Point::from_uniform_bytes(&digest);
            validate(point, &points)?;
            vectors.push(Vector { role, index, input: hex(&input),
                digest: hex(&digest), point: hex(&point.to_bytes()) });
            points.push(point);
        }
    }
    Ok((points[1], CommitKey { h: points[2], g: points[3..].to_vec() }, vectors))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_inputs_hashes_and_dalek_points_match_typescript_fixtures() {
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../packages/deck/test-vectors/shuffle-crs-36.json"
        )).unwrap();
        let (proof, key, vectors) = derive().unwrap();
        assert_eq!(serde_json::to_value(vectors).unwrap(), expected);
        assert_eq!(key.g.len(), 9);
        assert_ne!(proof, key.h);
    }

    #[test]
    fn identity_equal_and_negated_bases_fail_closed() {
        let (proof, _, _) = derive().unwrap();
        for point in [Point::zero(), Point::base(), -Point::base(), proof, -proof] {
            assert!(validate(point, &[Point::base(), proof]).is_err());
        }
    }
}
