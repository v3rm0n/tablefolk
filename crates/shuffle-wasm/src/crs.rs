//! Dimension-scoped CBOR/SHA-512 derivation of the candidate CRS.
use crate::dimensions::{Dimensions, cbor_head};
use crate::ristretto::{CommitKey, Point};
use ark_ff::Zero;
use sha2::{Digest, Sha512};

pub const PROFILE: &str = "bg-ristretto255-crs-candidate-v2";

#[cfg(test)]
#[derive(serde::Serialize)]
pub struct Vector {
    role: &'static str,
    index: usize,
    input: String,
    digest: String,
    point: String,
}

fn input(dimensions: Dimensions, role: &str, index: usize) -> Vec<u8> {
    let mut out = b"p2pcards/v1/shuffle".to_vec();
    out.push(0x86);
    text(&mut out, "crs");
    text(&mut out, PROFILE);
    cbor_head(&mut out, 0, dimensions.rows());
    cbor_head(&mut out, 0, dimensions.columns());
    text(&mut out, role);
    cbor_head(&mut out, 0, index);
    out
}

fn text(out: &mut Vec<u8>, value: &str) {
    cbor_head(out, 0x60, value.len());
    out.extend_from_slice(value.as_bytes());
}

fn validate(point: Point, previous: &[Point]) -> Result<(), String> {
    if point.is_zero() || previous.iter().any(|p| point == *p || point == -*p) {
        return Err("Degenerate shuffle CRS; profile revision required".into());
    }
    Ok(())
}

pub fn derive(dimensions: Dimensions) -> Result<(Point, CommitKey), String> {
    derive_with_observer(dimensions, |_, _, _, _, _| {})
}

fn derive_with_observer(
    dimensions: Dimensions,
    mut observe: impl FnMut(&'static str, usize, &[u8], &[u8; 64], Point),
) -> Result<(Point, CommitKey), String> {
    let mut points = vec![Point::base()];
    for (role, count) in [
        ("proof", 1),
        ("blinding", 1),
        ("message", dimensions.columns()),
    ] {
        for index in 0..count {
            let input = input(dimensions, role, index);
            let digest: [u8; 64] = Sha512::digest(&input).into();
            let point = Point::from_uniform_bytes(&digest);
            validate(point, &points)?;
            observe(role, index, &input, &digest, point);
            points.push(point);
        }
    }
    Ok((
        points[1],
        CommitKey {
            h: points[2],
            g: points[3..].to_vec(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_inputs_hashes_and_dalek_points_match_typescript_fixtures() {
        for (columns, fixture) in [
            (
                9,
                include_str!("../../../packages/deck/test-vectors/shuffle-crs-36.json"),
            ),
            (
                13,
                include_str!("../../../packages/deck/test-vectors/shuffle-crs-52.json"),
            ),
        ] {
            let expected: serde_json::Value = serde_json::from_str(fixture).unwrap();
            let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect();
            let mut vectors = Vec::new();
            let (proof, key) = derive_with_observer(
                Dimensions::new(4, columns).unwrap(),
                |role, index, input, digest, point| {
                    vectors.push(Vector {
                        role,
                        index,
                        input: hex(input),
                        digest: hex(digest),
                        point: hex(&point.to_bytes()),
                    });
                },
            )
            .unwrap();
            assert_eq!(serde_json::to_value(vectors).unwrap(), expected);
            assert_eq!(key.g.len(), columns);
            assert_ne!(proof, key.h);
        }
    }

    #[test]
    fn identity_equal_and_negated_bases_fail_closed() {
        let (proof, _) = derive(Dimensions::new(4, 9).unwrap()).unwrap();
        for point in [Point::zero(), Point::base(), -Point::base(), proof, -proof] {
            assert!(validate(point, &[Point::base(), proof]).is_err());
        }
    }
}
