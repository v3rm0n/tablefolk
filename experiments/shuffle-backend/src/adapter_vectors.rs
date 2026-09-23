//! Small local test oracle for comparison with the application's TypeScript primitives.
use ark_ff::{PrimeField, Zero};
use cards_proofs::{homomorphic_encryption::HomomorphicEncryptionScheme, vector_commitment::HomomorphicCommitmentScheme};
use serde::Deserialize;
use serde_json::{json, Value};
use crate::{decode_exact, ristretto::{Comm, CommitKey, Enc, Parameters, Point, Scalar, scalar_bytes}};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Vector {
    DecodePoint { bytes: String },
    DecodeScalar { bytes: String },
    Uniform { bytes: String },
    Point { left: String, right: String, scalar: String },
    Scalar { left: String, right: String, wide: String },
    Elgamal { message: String, keys: Vec<String>, mask: String, remask: String },
    Commitment { h: String, bases: Vec<String>, values: Vec<String>, blind: String },
}

pub fn evaluate(request: &str) -> Result<String, String> {
    if request.len() > 1024 * 1024 { return Err("Evaluation request too large".into()); }
    let vectors: Vec<Vector> = serde_json::from_str(request).map_err(|e| e.to_string())?;
    if vectors.len() > 512 { return Err("Too many evaluation vectors".into()); }
    let results: Vec<Value> = vectors.into_iter().map(run).collect::<Result<_, _>>()?;
    serde_json::to_string(&results).map_err(|e| e.to_string())
}

fn run(vector: Vector) -> Result<Value, String> {
    Ok(match vector {
        Vector::DecodePoint { bytes } => {
            let result = decode_exact::<Point>(&unhex(&bytes)?);
            json!({ "accepted": result.is_ok(), "bytes": result.ok().map(|p| hex(&p.to_bytes())) })
        }
        Vector::DecodeScalar { bytes } => {
            let result = decode_exact::<Scalar>(&unhex(&bytes)?);
            json!({ "accepted": result.is_ok(), "bytes": result.ok().map(|s| hex(&scalar_bytes(s))) })
        }
        Vector::Uniform { bytes } => {
            let uniform: [u8; 64] = unhex(&bytes)?.try_into().map_err(|_| "Expected 64 uniform bytes")?;
            json!(hex(&Point::from_uniform_bytes(&uniform).to_bytes()))
        }
        Vector::Point { left, right, scalar } => {
            let (a, b, s) = (point(&left)?, point(&right)?, scalar_value(&scalar)?);
            json!({ "add": hex(&(a + b).to_bytes()), "subtract": hex(&(a + -b).to_bytes()),
                "negate": hex(&(-a).to_bytes()), "multiply": hex(&(a * s).to_bytes()) })
        }
        Vector::Scalar { left, right, wide } => {
            let (a, b) = (scalar_value(&left)?, scalar_value(&right)?);
            let wide = unhex(&wide)?;
            if wide.len() != 64 { return Err("Expected 64 wide scalar bytes".into()); }
            json!({ "add": hex(&scalar_bytes(a + b)), "subtract": hex(&scalar_bytes(a - b)),
                "negate": hex(&scalar_bytes(-a)), "multiply": hex(&scalar_bytes(a * b)),
                "reduce": hex(&scalar_bytes(Scalar::from_le_bytes_mod_order(&wide))) })
        }
        Vector::Elgamal { message, keys, mask, remask } => {
            let keys = keys.iter().map(|s| scalar_value(s)).collect::<Result<Vec<_>, _>>()?;
            let key: Point = keys.iter().map(|s| Point::base() * *s).sum();
            let pp = Parameters { generator: Point::base() };
            let cipher = Enc::encrypt(&pp, &key, &point(&message)?, &scalar_value(&mask)?);
            let shuffled = cipher + Enc::encrypt(&pp, &key, &Point::zero(), &scalar_value(&remask)?);
            let shares: Vec<Point> = keys.iter().map(|s| shuffled.0 * *s).collect();
            let decrypted = shuffled.1 + -shares.iter().copied().sum::<Point>();
            json!({ "key": hex(&key.to_bytes()),
                "masked": [hex(&cipher.0.to_bytes()), hex(&cipher.1.to_bytes())],
                "remasked": [hex(&shuffled.0.to_bytes()), hex(&shuffled.1.to_bytes())],
                "shares": shares.iter().map(|p| hex(&p.to_bytes())).collect::<Vec<_>>(),
                "decrypted": hex(&decrypted.to_bytes()) })
        }
        Vector::Commitment { h, bases, values, blind } => {
            let key = CommitKey { h: point(&h)?, g: bases.iter().map(|s| point(s)).collect::<Result<_, _>>()? };
            let values = values.iter().map(|s| scalar_value(s)).collect::<Result<Vec<_>, _>>()?;
            let result = Comm::commit(&key, &values, scalar_value(&blind)?);
            json!({ "accepted": result.is_ok(), "bytes": result.ok().map(|p| hex(&p.to_bytes())) })
        }
    })
}

fn point(value: &str) -> Result<Point, String> { decode_exact(&unhex(value)?) }
fn scalar_value(value: &str) -> Result<Scalar, String> { decode_exact(&unhex(value)?) }

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn unhex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Invalid hex".into());
    }
    (0..value.len()).step_by(2).map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|e| e.to_string())).collect()
}
