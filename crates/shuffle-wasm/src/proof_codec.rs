//! Fixed candidate CBOR codec. The generic proof decoder only sees preflighted bytes.
use crate::{
    Proof, decode_exact,
    dimensions::{Dimensions, cbor_head},
    ristretto::Point,
    serialize,
};
use curve25519_dalek::scalar::Scalar;

pub const PROFILE: &str = "bg-ristretto255-proof-candidate-v2";
// (is_point, element count, optional Arkworks vector count). Ciphertext pairs
// are interleaved A/B points, hence twice as many elements as vector entries.
fn sections(dimensions: Dimensions) -> [(bool, usize, Option<usize>); 18] {
    let (m, n) = (dimensions.rows(), dimensions.columns());
    [
        (true, m, Some(m)),
        (true, m, Some(m)),
        (true, 1, None),
        (true, m, Some(m)),
        (true, 2, None),
        (true, 2 * m + 1, Some(2 * m + 1)),
        (false, n, Some(n)),
        (false, n, Some(n)),
        (false, 3, None),
        (true, 3, None),
        (false, n, Some(n)),
        (false, n, Some(n)),
        (false, 2, None),
        (true, 1, None),
        (true, 2 * m, Some(2 * m)),
        (true, 4 * m, Some(2 * m)),
        (false, 4, None),
        (false, n, Some(n)),
    ]
}

fn header(dimensions: Dimensions, count: usize) -> Vec<u8> {
    let mut bytes = vec![0x84, 0x78, PROFILE.len() as u8];
    bytes.extend_from_slice(PROFILE.as_bytes());
    cbor_head(&mut bytes, 0, dimensions.rows());
    cbor_head(&mut bytes, 0, dimensions.columns());
    cbor_head(&mut bytes, 0x80, count);
    bytes
}

fn validate(bytes: &[u8], point: bool) -> Result<(), String> {
    if point {
        Point::from_bytes(bytes).map_err(|e| e.to_string())?;
    } else {
        let array: [u8; 32] = bytes.try_into().map_err(|_| "Invalid scalar length")?;
        Option::<Scalar>::from(Scalar::from_canonical_bytes(array)).ok_or("Noncanonical scalar")?;
    }
    Ok(())
}

fn to_wire(ark: &[u8], dimensions: Dimensions) -> Result<Vec<u8>, String> {
    let sections = sections(dimensions);
    let elements = sections.iter().map(|section| section.1).sum::<usize>();
    let ark_bytes = elements * 32
        + sections
            .iter()
            .filter(|section| section.2.is_some())
            .count()
            * 8;
    if ark.len() != ark_bytes {
        return Err("Incorrect proof byte length".into());
    }
    let mut wire = header(dimensions, elements);
    wire.reserve(elements * 34);
    let mut offset = 0;
    for (point, count, vector) in sections {
        if let Some(length) = vector {
            if ark[offset..offset + 8] != (length as u64).to_le_bytes() {
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
    debug_assert_eq!(offset, ark_bytes);
    Ok(wire)
}

fn to_ark(wire: &[u8], dimensions: Dimensions) -> Result<Vec<u8>, String> {
    let sections = sections(dimensions);
    let elements = sections.iter().map(|section| section.1).sum::<usize>();
    let prefix = header(dimensions, elements);
    let wire_bytes = prefix.len() + elements * 34;
    // Before allocation or deserialization: exact total size and fixed grammar.
    if wire.len() != wire_bytes {
        return Err("Incorrect candidate proof byte length".into());
    }
    if !wire.starts_with(&prefix) {
        return Err("Incorrect candidate proof header".into());
    }
    let mut offset = prefix.len();
    let mut ark = Vec::with_capacity(elements * 32 + sections.len() * 8);
    for (point, count, vector) in sections {
        if let Some(length) = vector {
            ark.extend_from_slice(&(length as u64).to_le_bytes());
        }
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
    debug_assert_eq!(offset, wire_bytes);
    Ok(ark)
}

pub fn encode(proof: &Proof, dimensions: Dimensions) -> Result<Vec<u8>, String> {
    to_wire(&serialize(proof), dimensions)
}

pub fn decode(wire: &[u8], dimensions: Dimensions) -> Result<Proof, String> {
    decode_exact(&to_ark(wire, dimensions)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dimensions() -> Dimensions {
        Dimensions::new(4, 9).unwrap()
    }

    fn synthetic(dimensions: Dimensions) -> Vec<u8> {
        let mut ark = Vec::new();
        for (point, count, vector) in sections(dimensions) {
            if let Some(length) = vector {
                ark.extend_from_slice(&(length as u64).to_le_bytes());
            }
            for i in 0..count {
                if point {
                    ark.extend_from_slice(&Point::base().to_bytes());
                } else {
                    ark.extend_from_slice(&Scalar::from(i as u64).to_bytes());
                }
            }
        }
        ark
    }

    #[test]
    fn exact_roundtrip_with_canonical_points_and_scalars() {
        let ark = synthetic(dimensions());
        let wire = to_wire(&ark, dimensions()).unwrap();
        assert_eq!(to_ark(&wire, dimensions()).unwrap(), ark);
        assert_eq!(
            encode(&decode(&wire, dimensions()).unwrap(), dimensions()).unwrap(),
            wire
        );
    }

    #[test]
    fn rejects_every_truncation_and_trailing_bytes() {
        let mut wire = to_wire(&synthetic(dimensions()), dimensions()).unwrap();
        for length in 0..wire.len() {
            assert!(decode(&wire[..length], dimensions()).is_err());
        }
        wire.push(0);
        assert!(decode(&wire, dimensions()).is_err());
    }

    #[test]
    fn rejects_all_vector_lengths_before_generic_deserialization() {
        let ark = synthetic(dimensions());
        let mut offset = 0;
        for (_, count, vector) in sections(dimensions()) {
            if vector.is_some() {
                for bad in [0u64, 1, u64::MAX] {
                    let mut changed = ark.clone();
                    changed[offset..offset + 8].copy_from_slice(&bad.to_le_bytes());
                    assert!(to_wire(&changed, dimensions()).is_err());
                }
                offset += 8;
            }
            offset += count * 32;
        }
    }

    #[test]
    fn rejects_each_bad_header_and_each_invalid_field() {
        let wire = to_wire(&synthetic(dimensions()), dimensions()).unwrap();
        for i in 0..header(dimensions(), 106).len() {
            let mut changed = wire.clone();
            changed[i] ^= 1;
            assert!(decode(&changed, dimensions()).is_err());
        }
        for i in 0..106 {
            let offset = header(dimensions(), 106).len() + i * 34;
            let mut changed = wire.clone();
            changed[offset] = 0x98;
            assert!(decode(&changed, dimensions()).is_err());
            let mut changed = wire.clone();
            changed[offset + 1] = 31;
            assert!(decode(&changed, dimensions()).is_err());
            let mut changed = wire.clone();
            changed[offset + 2..offset + 34].fill(0xff);
            assert!(decode(&changed, dimensions()).is_err());
        }
    }
}
