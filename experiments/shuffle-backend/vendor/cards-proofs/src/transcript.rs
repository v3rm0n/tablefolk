//! Local candidate SHA-512/CBOR transcript. See docs/shuffle-transcript.md at the repository root.
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ark_std::{borrow::BorrowMut, vec::Vec};
use sha2::{Digest, Sha512};

pub const PROFILE: &[u8] = b"bg-ristretto255-36-4x9-fs-candidate-v1";
const DOMAIN: &[u8] = b"p2pcards/v1/shuffle";

pub fn bytes(value: &[u8]) -> Vec<u8> {
    let mut out = length(2, value.len()); out.extend_from_slice(value); out
}
pub fn array(values: &[Vec<u8>]) -> Vec<u8> {
    let mut out = length(4, values.len());
    for value in values { out.extend_from_slice(value); }
    out
}
fn length(major: u8, size: usize) -> Vec<u8> {
    assert!(size <= 65535, "Candidate transcript field bound");
    if size < 24 { vec![(major << 5) | size as u8] }
    else if size < 256 { vec![(major << 5) | 24, size as u8] }
    else { vec![(major << 5) | 25, (size >> 8) as u8, size as u8] }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeRecord {
    pub input: Vec<u8>,
    pub digest: [u8; 64],
    pub scalar: Vec<u8>,
}

pub struct Transcript {
    context: Vec<u8>,
    root: Vec<u8>,
    events: Vec<Vec<u8>>,
    event_bytes: usize,
    records: Vec<ChallengeRecord>,
}

impl Transcript {
    pub fn new(game: [u8; 16], round: u64, phase: &[u8], root: &[u8]) -> Self {
        assert!(!root.is_empty() && root.len() <= 1024, "Candidate transcript root bound");
        assert!(round <= 9007199254740991 && !phase.is_empty() && phase.len() <= 64 && phase.is_ascii(), "Candidate context bound");
        let mut context = game.to_vec();
        if round < 24 { context.push(round as u8); }
        else if round <= 255 { context.extend_from_slice(&[0x18, round as u8]); }
        else if round <= 65535 { context.push(0x19); context.extend_from_slice(&(round as u16).to_be_bytes()); }
        else if round <= u32::MAX as u64 { context.push(0x1a); context.extend_from_slice(&(round as u32).to_be_bytes()); }
        else { context.push(0x1b); context.extend_from_slice(&round.to_be_bytes()); }
        context.extend_from_slice(&length(3, phase.len())); context.extend_from_slice(phase);
        Self { context, root: root.to_vec(), events: Vec::new(), event_bytes: 0, records: Vec::new() }
    }
    fn push(&mut self, event: Vec<u8>) {
        assert!(self.events.len() < 128 && self.event_bytes + event.len() <= 32768,
            "Candidate transcript event bound");
        self.event_bytes += event.len(); self.events.push(event);
    }
    pub fn label(&mut self, label: &[u8]) {
        assert!(!label.is_empty() && label.len() <= 64, "Candidate label bound");
        self.push(array(&[vec![0], bytes(label)]));
    }
    pub fn append<T: CanonicalSerialize + ?Sized>(&mut self, value: &T) {
        assert!(value.compressed_size() <= 8192, "Candidate append bound");
        let mut encoded = Vec::new();
        value.serialize_compressed(&mut encoded).expect("Serialize public transcript value");
        self.append_public_bytes(&encoded);
    }
    pub fn append_public_bytes(&mut self, encoded: &[u8]) {
        assert!(encoded.len() <= 8192, "Candidate append bound");
        self.push(array(&[vec![1], bytes(encoded)]));
    }
    pub fn challenge<'a>(&'a mut self, label: &[u8]) -> Challenge<'a> {
        assert!(!label.is_empty() && label.len() <= 64, "Candidate challenge label bound");
        Challenge { transcript: self, label: label.to_vec(), index: 0 }
    }
    pub fn records(&self) -> &[ChallengeRecord] { &self.records }
}

pub struct Challenge<'a> { transcript: &'a mut Transcript, label: Vec<u8>, index: u8 }
impl Challenge<'_> {
    pub fn read_uniform<F: Field>(&mut self) -> F {
        assert!(self.index < 16, "Candidate challenge count bound");
        let request = array(&[vec![2], bytes(&self.label), vec![self.index]]);
        let body = array(&[bytes(PROFILE), bytes(&self.transcript.root),
            array(&self.transcript.events), request]);
        let mut input = DOMAIN.to_vec(); input.extend_from_slice(&self.transcript.context); input.extend_from_slice(&body);
        let digest: [u8; 64] = Sha512::digest(&input).into();
        // LE 512-bit integer reduced in the field; unlike upstream read_uniform,
        // this has the same result as the application's wide scalar reduction.
        let scalar = digest.iter().rev().fold(F::ZERO, |acc, b| acc * F::from(256u64) + F::from(*b as u64));
        let mut encoded = Vec::new(); scalar.serialize_compressed(&mut encoded).unwrap();
        self.transcript.push(array(&[vec![2], bytes(&self.label), vec![self.index], bytes(&encoded)]));
        self.transcript.records.push(ChallengeRecord { input, digest, scalar: encoded });
        self.index += 1;
        scalar
    }
}

pub trait IntoTranscript {
    type Target: BorrowMut<Transcript>;
    fn into_transcript(self) -> Self::Target;
}
impl<'a> IntoTranscript for &'a mut Transcript {
    type Target = &'a mut Transcript;
    fn into_transcript(self) -> Self::Target { self }
}
impl IntoTranscript for Transcript {
    type Target = Self;
    fn into_transcript(self) -> Self { self }
}
