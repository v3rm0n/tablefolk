use super::*;
use ark_ff::{BigInteger, Field, PrimeField};
use crate::{adapter_vectors::{hex, unhex}, decode_exact, serialize};
use rand::rngs::OsRng;

#[test]
fn rfc9496_group_interface_vectors() {
    let rfc: serde_json::Value = serde_json::from_str(include_str!("../rfc9496.json")).unwrap();
    let multiples = rfc["multiples"].as_array().unwrap();
    let invalid = rfc["invalid"].as_array().unwrap();
    let uniform = rfc["uniform"].as_array().unwrap();
    assert_eq!((multiples.len(), invalid.len(), uniform.len()), (16, 29, 11));
    let mut sum = Point::zero();
    for (index, encoded) in multiples.iter().enumerate() {
        let expected = encoded.as_str().unwrap();
        assert_eq!(hex(&sum.to_bytes()), expected);
        assert_eq!(Point::base() * Scalar::from(index as u64), sum);
        assert_eq!(decode_exact::<Point>(&unhex(expected).unwrap()).unwrap(), sum);
        for mode in [Compress::Yes, Compress::No] {
            let mut bytes = Vec::new();
            sum.serialize_with_mode(&mut bytes, mode).unwrap();
            assert_eq!(hex(&bytes), expected);
        }
        sum = sum + Point::base();
    }
    for encoded in invalid {
        let bytes = unhex(encoded.as_str().unwrap()).unwrap();
        assert!(Point::from_bytes(&bytes).is_err());
        for mode in [Compress::Yes, Compress::No] {
            for validation in [Validate::Yes, Validate::No] {
                assert!(Point::deserialize_with_mode(bytes.as_slice(), mode, validation).is_err());
            }
        }
    }
    for vector in uniform {
        let input: [u8; 64] = unhex(vector["input"].as_str().unwrap()).unwrap().try_into().unwrap();
        assert_eq!(hex(&Point::from_uniform_bytes(&input).to_bytes()), vector["output"].as_str().unwrap());
    }
}

#[test]
fn scalar_bridge_is_canonical_and_uses_the_ristretto_order() {
    let order = unhex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010").unwrap();
    assert_eq!(Scalar::MODULUS.to_bytes_le(), order);
    assert!(decode_exact::<Scalar>(&order).is_err());
    assert!(decode_exact::<Scalar>(&[0xff; 32]).is_err());
    let mut forbidden_flag = [0; 32];
    forbidden_flag[31] = 0x80;
    assert!(decode_exact::<Scalar>(&forbidden_flag).is_err());
    for value in [Scalar::zero(), Scalar::from(1), Scalar::from(7), -Scalar::from(1)] {
        let bytes = scalar_bytes(value);
        assert_eq!(decode_exact::<Scalar>(&bytes).unwrap(), value);
        assert_eq!(dalek_scalar(value).to_bytes(), bytes);
        assert_eq!(bytes.to_vec(), serialize(&value));
        if !value.is_zero() { assert_eq!(value * value.inverse().unwrap(), Scalar::from(1)); }
    }
    assert_eq!(Point::base() * -Scalar::from(1), -Point::base());
    assert_eq!(Point::base() * Scalar::zero(), Point::zero());
    let mut wide = [0; 64];
    wide[..32].copy_from_slice(&order);
    wide[0] += 5;
    assert_eq!(Scalar::from_le_bytes_mod_order(&wide), Scalar::from(5));
    for size in [0, 31, 33] {
        assert!(decode_exact::<Scalar>(&vec![0; size]).is_err());
        assert!(decode_exact::<Point>(&vec![0; size]).is_err());
    }
}

#[test]
fn elgamal_algebra_including_zero_terms_and_wrapping_randomness() {
    let pp = Enc::setup(&mut OsRng);
    assert_eq!(pp.generator, Point::base());
    let sk = Scalar::from(17);
    let pk = Point::base() * sk;
    let message = Point::from_uniform_bytes(&[42; 64]);
    let initial = Enc::encrypt(&pp, &pk, &message, &Scalar::zero());
    assert_eq!(initial, Ciphertext(Point::zero(), message));
    let masked = Enc::encrypt(&pp, &pk, &message, &-Scalar::from(1));
    let remasked = masked + Enc::encrypt(&pp, &pk, &Point::zero(), &Scalar::from(1));
    assert_eq!(remasked, initial);
    assert_eq!(Enc::decrypt(&pp, &sk, &(masked * Scalar::from(3))), message * Scalar::from(3));
    assert_eq!(serialize(&initial).len(), 64);
    assert_eq!(decode_exact::<Ciphertext>(&serialize(&masked)).unwrap(), masked);
}

#[test]
fn pedersen_uses_independent_nonidentity_bases_and_preserves_linearity() {
    let key = Comm::setup(&mut OsRng, 9);
    assert!(!key.h.is_zero());
    for (i, g) in key.g.iter().enumerate() {
        assert!(!g.is_zero());
        assert_ne!(*g, key.h);
        assert!(!key.g[..i].contains(g));
    }
    let a = [Scalar::from(2), Scalar::from(3)];
    let b = [Scalar::from(5), -Scalar::from(1)];
    let left = Comm::commit(&key, &a, Scalar::from(7)).unwrap();
    let right = Comm::commit(&key, &b, Scalar::from(11)).unwrap();
    assert_eq!(left + right, Comm::commit(&key, &[a[0] + b[0], a[1] + b[1]], Scalar::from(18)).unwrap());
    assert_eq!(Comm::commit(&key, &[], Scalar::from(7)).unwrap(), key.h * Scalar::from(7));
    assert_eq!(Comm::commit(&key, &[], Scalar::zero()).unwrap(), Point::zero());
    assert!(Comm::commit(&key, &[Scalar::zero(); 10], Scalar::zero()).is_err());
}
