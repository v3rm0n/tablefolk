pub use ark_std::{borrow::Cow};
use thiserror::Error;

pub type CryptoResult<T> = ark_std::result::Result<T,CryptoError>;

pub type CowStr = Cow<'static,str>;

/// This is an error that could occur when running a cryptographic primitive
// We label the origin cases manually because Rust has no notions like
// enum multiple inheritance, cross type variant allocators, or similar. 
#[derive(Error, Debug, PartialEq)]
pub enum CryptoError {
    #[error("Failed to verify {0} proof")]
    ProofVerificationError(CowStr),
    // verifier only

    #[error("Failed to output a {0} commitment: values {1} > bases {2}")]
    CommitmentLengthError(&'static str, usize, usize),
    // common, PedersenComm::PedersenCommitment

    #[error("Dot Product error: left = {0} - right = {1}")]
    DotProductLengthError(usize, usize),
    // common, vector_arithmetic.rs

    #[error("Bilinear Map error: left = {0} - right = {1}")]
    BilinearMapLengthError(usize, usize),
    // common (both), zkp::arguments::zero_value_bilinear_map::YMapping

    #[error("Hadamard Product error: left = {0} - right = {1}")]
    HadamardProductLengthError(usize, usize),
    // prover only, vector_arithmetic.rs, matrix_elements_product

    #[error("Cannot cast vector of size {0} to matrix of {1} by {2}")]
    VectorCastingError(usize, usize, usize),
    // porver only, shuffle only, vector_arithmetic.rs

    #[error("Diagonals Error: left = {0} - right = {1}")]
    DiagonalLengthError(usize, usize),
    // prover only

    #[error("InvalidProductArgumentStatement")]
    InvalidProductArgumentStatement,
    // common

    #[error("InvalidShuffleStatement")]
    InvalidShuffleStatement,
    // common, shuffle only

    // ark_std::io::Error is more efficent and infomrative than String, but lacks PartialEq
    // #[error("IoError in cards-proofs: {0}")]
    // IoError(ark_std::string::String),
    #[error("IoError in cards-proofs: {0:?}")]
    IoError(AlwayUnequal<ark_std::io::Error>),
    // common
}

#[derive(Error, Debug)]
pub struct AlwayUnequal<T: ?Sized>(pub T);

impl<T: ?Sized> ark_std::cmp::PartialEq for AlwayUnequal<T> {
    fn eq(&self, _other: &Self) -> bool { false }
}

impl From<ark_std::io::Error> for CryptoError {
    fn from(err: ark_std::io::Error) -> Self {
        // Self::IoError(err.to_string())
        Self::IoError(AlwayUnequal(err))
    }
}
