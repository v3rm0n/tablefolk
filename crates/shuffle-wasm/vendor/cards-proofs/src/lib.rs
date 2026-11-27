#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

pub mod error;
pub mod homomorphic_encryption;
pub mod utils;
pub mod vector_commitment;
pub mod zkp;

pub mod transcript;
pub use transcript::{Transcript, IntoTranscript};
