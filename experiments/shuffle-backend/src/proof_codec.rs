//! Fixed candidate CBOR codec. The generic proof decoder only sees preflighted bytes.
use curve25519_dalek::scalar::Scalar;
use crate::{Proof, decode_exact, serialize, ristretto::Point};

pub const PROFILE: &str = "bg-ristretto255-36-4x9-proof-candidate-v1";
pub const ARK_BYTES: usize = 3480;
pub const ELEMENTS: usize = 106;
pub const WIRE_BYTES: usize = 1 + 2 + PROFILE.len() + 2 + ELEMENTS * 34;

// (is_point, element count, optional Arkworks vector count). Ciphertext pairs
// are interleaved A/B points, hence 16 elements but a vector count of eight.
const SECTIONS: &[(bool, usize, Option<u64>)] = &[
    (true, 4, Some(4)), (true, 4, Some(4)), (true, 1, None),
    (true, 4, Some(4)), (true, 2, None), (true, 9, Some(9)),
    (false, 9, Some(9)), (false, 9, Some(9)), (false, 3, None),
    (true, 3, None), (false, 9, Some(9)), (false, 9, Some(9)),
    (false, 2, None), (true, 1, None), (true, 8, Some(8)),
    (true, 16, Some(8)), (false, 4, None), (false, 9, Some(9)),
];

fn header() -> Vec<u8> {
    let mut bytes = vec![0x82, 0x78, PROFILE.len() as u8];
    bytes.extend_from_slice(PROFILE.as_bytes());
    bytes.extend_from_slice(&[0x98, ELEMENTS as u8]);
    bytes
}

fn validate(bytes: &[u8], point: bool) -> Result<(), String> {
    if point {
        Point::from_bytes(bytes).map_err(|e| e.to_string())?;
    } else {
        let array: [u8; 32] = bytes.try_into().map_err(|_| "Invalid scalar length")?;
        Option::<Scalar>::from(Scalar::from_canonical_bytes(array))
            .ok_or("Noncanonical scalar")?;
    }
    Ok(())
}

fn to_wire(ark: &[u8]) -> Result<Vec<u8>, String> {
    if ark.len() != ARK_BYTES { return Err("Incorrect proof byte length".into()); }
    let mut wire = header();
    wire.reserve(ELEMENTS * 34);
    let mut offset = 0;
    for &(point, count, vector) in SECTIONS {
        if let Some(length) = vector {
            if ark[offset..offset + 8] != length.to_le_bytes() {
                return Err("Incorrect proof vector length".into());
            }
            offset += 8;
        }
        for _ in 0..count {
            let element = &ark[offset..offset + 32];
            validate(element, point)?;
            wire.extend_from_slice(&[0x58, 32]);
            wire.extend_from_slice(element);
            offset += 32;
        }
    }
    debug_assert_eq!(offset, ARK_BYTES);
    debug_assert_eq!(wire.len(), WIRE_BYTES);
    Ok(wire)
}

fn to_ark(wire: &[u8]) -> Result<Vec<u8>, String> {
    // Before allocation or deserialization: exact total size and fixed grammar.
    if wire.len() != WIRE_BYTES { return Err("Incorrect candidate proof byte length".into()); }
    let prefix = header();
    if !wire.starts_with(&prefix) { return Err("Incorrect candidate proof header".into()); }
    let mut offset = prefix.len();
    let mut ark = Vec::with_capacity(ARK_BYTES);
    for &(point, count, vector) in SECTIONS {
        if let Some(length) = vector { ark.extend_from_slice(&length.to_le_bytes()); }
        for _ in 0..count {
            if wire[offset..offset + 2] != [0x58, 32] {
                return Err("Noncanonical proof element".into());
            }
            let element = &wire[offset + 2..offset + 34];
            validate(element, point)?;
            ark.extend_from_slice(element);
            offset += 34;
        }
    }
    debug_assert_eq!(offset, WIRE_BYTES);
    debug_assert_eq!(ark.len(), ARK_BYTES);
    Ok(ark)
}

pub fn encode(proof: &Proof) -> Result<Vec<u8>, String> { to_wire(&serialize(proof)) }
pub fn decode(wire: &[u8]) -> Result<Proof, String> { decode_exact(&to_ark(wire)?) }

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic() -> Vec<u8> {
        let mut ark = Vec::new();
        for &(point, count, vector) in SECTIONS {
            if let Some(length) = vector { ark.extend_from_slice(&length.to_le_bytes()); }
            for i in 0..count {
                if point { ark.extend_from_slice(&Point::base().to_bytes()); }
                else { ark.extend_from_slice(&Scalar::from(i as u64).to_bytes()); }
            }
        }
        ark
    }

    #[test]
    fn exact_roundtrip_with_canonical_points_and_scalars() {
        let ark = synthetic();
        let wire = to_wire(&ark).unwrap();
        assert_eq!(to_ark(&wire).unwrap(), ark);
        assert_eq!(encode(&decode(&wire).unwrap()).unwrap(), wire);
    }

    #[test]
    fn rejects_every_truncation_and_trailing_bytes() {
        let mut wire = to_wire(&synthetic()).unwrap();
        for length in 0..wire.len() { assert!(decode(&wire[..length]).is_err()); }
        wire.push(0);
        assert!(decode(&wire).is_err());
    }

    #[test]
    fn rejects_all_vector_lengths_before_generic_deserialization() {
        let ark = synthetic();
        let mut offset = 0;
        for &(_, count, vector) in SECTIONS {
            if vector.is_some() {
                for bad in [0u64, 1, u64::MAX] {
                    let mut changed = ark.clone();
                    changed[offset..offset + 8].copy_from_slice(&bad.to_le_bytes());
                    assert!(to_wire(&changed).is_err());
                }
                offset += 8;
            }
            offset += count * 32;
        }
    }

    #[test]
    fn rejects_each_bad_header_and_each_invalid_field() {
        let wire = to_wire(&synthetic()).unwrap();
        for i in 0..header().len() {
            let mut changed = wire.clone(); changed[i] ^= 1;
            assert!(decode(&changed).is_err());
        }
        for i in 0..ELEMENTS {
            let offset = header().len() + i * 34;
            let mut changed = wire.clone(); changed[offset] = 0x98;
            assert!(decode(&changed).is_err());
            let mut changed = wire.clone(); changed[offset + 1] = 31;
            assert!(decode(&changed).is_err());
            let mut changed = wire.clone(); changed[offset + 2..offset + 34].fill(0xff);
            assert!(decode(&changed).is_err());
        }
    }
}
