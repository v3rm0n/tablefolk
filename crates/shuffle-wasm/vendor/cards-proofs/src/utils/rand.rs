use ark_std::{vec::Vec, rand::Rng, UniformRand};

/// Sample a vector of random elements of type T
pub fn sample_vector<T: UniformRand, R: Rng>(seed: &mut R, length: usize) -> Vec<T> {
    (0..length)
        .map(|_| T::rand(seed))
        .collect::<Vec<_>>()
}
