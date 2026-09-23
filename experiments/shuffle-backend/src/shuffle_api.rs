//! Bounded public statement and private witness admission. Never uses Fixture.
use ark_ff::Zero;
use ark_serialize::CanonicalDeserialize;
use cards_proofs::{homomorphic_encryption::HomomorphicEncryptionScheme,
    utils::permutation::Permutation, zkp::{ArgumentOfKnowledge, arguments::shuffle}};
use rand::{CryptoRng, Rng, rngs::OsRng};
use crate::{Argument, Enc, Scalar, crs, proof_codec, TRANSCRIPT_PROFILE,
    ristretto::{Ciphertext, Parameters, Point}};

pub const PROFILE: &str = "bg-ristretto255-36-4x9-statement-candidate-v1";
pub const MIN_BYTES: usize = 3 + PROFILE.len() + 17 + 1 + 1 + 34 + 34 + 2 * 2307;
pub const MAX_BYTES: usize = MIN_BYTES + 8;

struct Statement {
    game: [u8; 16], round: u64, seat: u8, roster: [u8; 32], key: Point,
    input: [Ciphertext; 36], output: [Ciphertext; 36],
}
struct Reader<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let end = self.offset.checked_add(count).ok_or("Statement length overflow")?;
        let result = self.bytes.get(self.offset..end).ok_or("Truncated statement")?;
        self.offset = end; Ok(result)
    }
    fn exact(&mut self, expected: &[u8]) -> Result<(), String> {
        if self.take(expected.len())? != expected { return Err("Invalid statement header".into()); }
        Ok(())
    }
    fn fixed(&mut self, count: usize) -> Result<&'a [u8], String> {
        match count {
            16 => self.exact(&[0x50])?,
            32 => self.exact(&[0x58, 32])?,
            2304 => self.exact(&[0x59, 9, 0])?,
            _ => return Err("Unsupported fixed field".into()),
        }
        self.take(count)
    }
    fn round(&mut self) -> Result<u64, String> {
        let tag = self.take(1)?[0];
        if tag < 24 { return Ok(tag as u64); }
        let (count, min) = match tag { 24 => (1, 24), 25 => (2, 256),
            26 => (4, 65536), 27 => (8, 4294967296), _ => return Err("Invalid round encoding".into()) };
        let mut value = 0u64;
        for byte in self.take(count)? { value = (value << 8) | *byte as u64; }
        if value < min || value > 9007199254740991 { return Err("Noncanonical or unsafe round".into()); }
        Ok(value)
    }
    fn deck(&mut self) -> Result<[Ciphertext; 36], String> {
        let bytes = self.fixed(2304)?;
        let mut deck = [Ciphertext::zero(); 36];
        for (card, chunk) in deck.iter_mut().zip(bytes.chunks_exact(64)) {
            *card = Ciphertext(Point::from_bytes(&chunk[..32]).map_err(|e| e.to_string())?,
                Point::from_bytes(&chunk[32..]).map_err(|e| e.to_string())?);
        }
        Ok(deck)
    }
}
impl Statement {
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if !(MIN_BYTES..=MAX_BYTES).contains(&bytes.len()) { return Err("Invalid statement byte length".into()); }
        let mut r = Reader { bytes, offset: 0 };
        r.exact(&[0x88, 0x78, PROFILE.len() as u8])?; r.exact(PROFILE.as_bytes())?;
        let game = r.fixed(16)?.try_into().unwrap();
        let round = r.round()?;
        let seat = r.take(1)?[0];
        if seat > 3 { return Err("Invalid shuffle seat".into()); }
        let roster = r.fixed(32)?.try_into().unwrap();
        let key = Point::from_bytes(r.fixed(32)?).map_err(|e| e.to_string())?;
        if key.is_zero() { return Err("Identity shuffle key".into()); }
        let input = r.deck()?;
        let output = r.deck()?;
        if r.offset != bytes.len() { return Err("Trailing statement bytes".into()); }
        Ok(Self { game, round, seat, roster, key, input, output })
    }
    fn transcript(&self, generator: Point) -> cards_proofs::Transcript {
        use cards_proofs::transcript::{array, bytes};
        let root = array(&[bytes(PROFILE.as_bytes()), bytes(crs::PROFILE.as_bytes()),
            bytes(proof_codec::PROFILE.as_bytes()), bytes(TRANSCRIPT_PROFILE.as_bytes()),
            bytes(&self.roster), vec![self.seat], bytes(&Point::base().to_bytes()), bytes(&generator.to_bytes())]);
        let phase = format!("round.{}.shuffle.{}", self.round, self.seat);
        cards_proofs::Transcript::new(self.game, self.round, phase.as_bytes(), &root)
    }
}

pub fn validate_statement(bytes: &[u8]) -> Result<(), String> { Statement::decode(bytes).map(|_| ()) }

pub fn verify(statement: &[u8], proof: &[u8]) -> Result<bool, String> {
    let statement = Statement::decode(statement)?;
    let proof = proof_codec::decode(proof)?;
    let (generator, commitments, _) = crs::derive()?;
    let encryption = Parameters { generator: Point::base() };
    let parameters = shuffle::Parameters::new(&encryption, &statement.key, &commitments, &generator);
    let public = shuffle::Statement::new(&statement.input, &statement.output, 4, 9);
    Ok(Argument::verify(&parameters, &public, &proof, statement.transcript(generator)).is_ok())
}

pub fn prove(statement: &[u8], permutation: &[u8], randomizers: &[u8]) -> Result<Vec<u8>, String> {
    prove_with_rng(statement, permutation, randomizers, &mut OsRng)
}

fn prove_with_rng<R: Rng + CryptoRng>(encoded: &[u8], permutation: &[u8], randomizers: &[u8], rng: &mut R) -> Result<Vec<u8>, String> {
    let statement = Statement::decode(encoded)?;
    if permutation.len() != 36 || randomizers.len() != 36 * 32 { return Err("Invalid private witness length".into()); }
    let mut seen = [false; 36];
    let mut masks = Vec::with_capacity(36);
    let encryption = Parameters { generator: Point::base() };
    for (j, (&position, bytes)) in permutation.iter().zip(randomizers.chunks_exact(32)).enumerate() {
        if position >= 36 || seen[position as usize] { return Err("Invalid private permutation".into()); }
        seen[position as usize] = true;
        let mask = Scalar::deserialize_compressed(bytes).map_err(|_| "Noncanonical private randomizer")?;
        if mask.is_zero() { return Err("Zero private randomizer".into()); }
        let expected = statement.input[position as usize] + Enc::encrypt(&encryption, &statement.key, &Point::zero(), &mask);
        if expected != statement.output[j] { return Err("Private witness does not match statement".into()); }
        masks.push(mask);
    }
    // All public/private admission and relation checks precede proof RNG use.
    let permutation = Permutation::from(permutation.iter().map(|p| *p as usize).collect::<Vec<_>>());
    let (generator, commitments, _) = crs::derive()?;
    let parameters = shuffle::Parameters::new(&encryption, &statement.key, &commitments, &generator);
    let public = shuffle::Statement::new(&statement.input, &statement.output, 4, 9);
    let witness = shuffle::Witness::new(&permutation, &masks);
    let proof = Argument::prove(rng, &parameters, &public, &witness, statement.transcript(generator)).map_err(|e| e.to_string())?;
    if Argument::verify(&parameters, &public, &proof, statement.transcript(generator)).is_err() {
        return Err("Generated proof failed self-verification".into());
    }
    proof_codec::encode(&proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_serialize::CanonicalSerialize;
    use rand::RngCore;
    use cards_proofs::transcript::{array, bytes};

    fn fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let encryption = Parameters { generator: Point::base() };
        let key = Point::base() * Scalar::from(7u64);
        let input: Vec<_> = (0..36).map(|i| Ciphertext(Point::zero(), Point::base() * Scalar::from(i + 1))).collect();
        let permutation: Vec<u8> = (0..36).map(|i| (i + 1) % 36).collect();
        let masks: Vec<_> = (0..36).map(|i| Scalar::from(i + 11)).collect();
        let output: Vec<_> = permutation.iter().enumerate().map(|(j, &p)| input[p as usize] + Enc::encrypt(&encryption, &key, &Point::zero(), &masks[j])).collect();
        let pack = |deck: &[Ciphertext]| deck.iter().flat_map(|c| [c.0.to_bytes(), c.1.to_bytes()].concat()).collect::<Vec<_>>();
        let mut profile = vec![0x78, PROFILE.len() as u8]; profile.extend(PROFILE.as_bytes());
        let statement = array(&[profile, bytes(&[0; 16]), vec![0], vec![0], bytes(&[0; 32]), bytes(&key.to_bytes()), bytes(&pack(&input)), bytes(&pack(&output))]);
        let mut randomizers = Vec::new();
        for scalar in masks { scalar.serialize_compressed(&mut randomizers).unwrap(); }
        (statement, permutation, randomizers)
    }
    struct NoRng;
    impl RngCore for NoRng {
        fn next_u32(&mut self) -> u32 { panic!("RNG before admission") }
        fn next_u64(&mut self) -> u64 { panic!("RNG before admission") }
        fn fill_bytes(&mut self, _: &mut [u8]) { panic!("RNG before admission") }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> { panic!("RNG before admission") }
    }
    impl CryptoRng for NoRng {}
    #[test]
    fn rejects_before_randomness() {
        let (s, p, r) = fixture();
        for n in 0..s.len() { assert!(validate_statement(&s[..n]).is_err()); }
        assert_eq!(s.len(), MIN_BYTES);
        assert!(prove_with_rng(&s, &p[..35], &r, &mut NoRng).is_err());
        for value in [0, 36, 255] { let mut bad = p.clone(); bad[0] = value; assert!(prove_with_rng(&s, &bad, &r, &mut NoRng).is_err()); }
        for value in [0, 255] { let mut bad = r.clone(); bad[..32].fill(value); assert!(prove_with_rng(&s, &p, &bad, &mut NoRng).is_err()); }
        let mut wrong = r.clone(); wrong[0] += 1;
        assert!(prove_with_rng(&s, &p, &wrong, &mut NoRng).is_err());
    }
    #[test]
    fn proof_binds_all_public_fields() {
        let (s, p, r) = fixture();
        let proof = prove(&s, &p, &r).unwrap();
        assert_eq!(proof.len(), 3650); assert!(verify(&s, &proof).unwrap());
        let round = 3 + PROFILE.len() + 17;
        for offset in [3 + PROFILE.len() + 1, round, round + 1, round + 4] {
            let mut changed = s.clone(); changed[offset] ^= 1;
            assert!(!verify(&changed, &proof).unwrap());
        }
        for offset in [round + 38, round + 73, round + 73 + 2307] {
            let mut changed = s.clone(); changed[offset..offset + 32].copy_from_slice(&Point::base().to_bytes());
            assert!(!verify(&changed, &proof).unwrap());
        }
        assert!(verify(&s, &proof[..proof.len() - 1]).is_err());
    }
}
