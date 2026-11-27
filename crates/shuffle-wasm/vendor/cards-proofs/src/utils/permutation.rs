use ark_std::{borrow::ToOwned, boxed::Box, vec::Vec, rand::{Rng, distributions::uniform::SampleRange}}; // seq::SliceRandom

/// Represent a permutation pi as slice such that for all indices i, self.0[i] = pi(i)
#[derive(Clone,PartialEq,Eq,Debug)]
pub struct Permutation(Box<[usize]>);

impl core::ops::Deref for Permutation {
    type Target = [usize];
    fn deref(&self) -> &[usize] { &self.0 }
}
/*
impl core::ops::DerefMut for Permutation {
    fn deref_mut(&mut self) -> &mut [usize] { &mut self.0 }
}
*/

impl From<Vec<usize>> for Permutation {
    fn from(permutation: Vec<usize>) -> Permutation {
        Permutation(permutation.into_boxed_slice())
    }
}

impl From<&[usize]> for Permutation {
    fn from(permutation: &[usize]) -> Permutation {
        Permutation(permutation.to_owned().into_boxed_slice())
    }
}

impl Permutation {
    pub fn identity(size: usize) -> Self {
        Permutation((0..size).collect())
    }

    /// Shuffle the permutation from some point onwards
    ///
    /// We use Durstenfeld's algorithm for the [Fisher–Yates shuffle](https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#The_modern_algorithm)
    /// for an unbiased permutation, similar to `rand::seq::SliceRandom`.
    /// We choose a slightly less optimized sampling procedure, but look
    /// slightly easier to explain.
    fn shuffle_tail<R: Rng>(&mut self, rng: &mut R, m: usize) {
        let size = self.len();
        for i in m..size {
            let j = (i..size).sample_single(rng);
            self.0.swap(i, j);
        }
    }

    pub fn from_rng<R: Rng>(rng: &mut R, size: usize) -> Self {
        let mut mapping = Permutation::identity(size);
        mapping.shuffle_tail(rng, 0);
        mapping
    }

    /*
    /// Create a random Permutation with a fixed initial prefix.
    ///
    /// You must inverse this if you want the initial prefix to describe
    /// from where the permutation takes elements.
    pub fn prefixed<R: Rng>(rng: &mut R, prefix: &[usize], size: usize) -> Self {
        assert!(size < (u32::MAX as usize), "Cannot suffle more than 2^32 elements!");
        let mut mapping = Permutation::identity(size);
        let m = prefix.len();
        assert!(m <= size, "The prefix is longer than the permutation!");
        for (i,j) in prefix.iter().enumerate() {
            assert!(*j < size, "The prefix goes outside the bounds of the permutation!");
            if *j > i {
                mapping.0.swap(i, *j);
            } else if *j < i {
                // assert_eq!(mapping.0[*j],i);  // NOPE STUPID !!
            }
        }
        mapping.shuffle_tail(rng,m);
        mapping
    }
    */

    pub fn inverse(&self) -> Self {
        let mut inv = vec![0; self.len()].into_boxed_slice();
        for (i,j) in self.0.iter().copied().enumerate() {
            inv[j] = i;
        }
        Permutation(inv)
    }

    /// Permute an array by applying the shuffle
    pub fn apply<T: Copy>(&self, input_vector: &[T]) -> Vec<T> {
        assert_eq!(input_vector.len(), self.len());
        self.0.iter()
            .map(|&pi_i| input_vector[pi_i])
            .collect::<Vec<T>>()
    }

    /// Fix an initial prefix into a Permutation, usually a random one.
    ///
    /// Assumes the provided prefix is a valid fragment of a permutation.
    /// You must inverse this if you want the initial prefix to describe
    /// from where the permutation takes elements.
    pub fn prefixed_squish(mut self, prefix: &[usize]) -> Permutation {
        let inv = self.inverse();
        // Mark & erase every destination used by the prefix
        for p in prefix {
            self.0[inv.0[*p]] = usize::MAX;
        }
        let erased = self.0.iter().filter(|p| **p != usize::MAX);
        let v: Vec<usize> = prefix.iter().chain(erased).cloned().collect();
        Permutation(v.into_boxed_slice())
    }

    pub fn random_prefixed<R: Rng>(rng: &mut R, prefix: &[usize], size: usize) -> Permutation {
        let p = Permutation::from_rng(rng, size);
        p.prefixed_squish(prefix)
    }

    pub fn random_prefixed_checked<R: Rng>(rng: &mut R, prefix: &[usize], size: usize) -> Option<Permutation> {
        if prefix.len() > size { return None; }
        for p in prefix {
            if *p > size { return None; }
        }
        let mut mapping_test = prefix.to_owned();
        mapping_test.sort();
        for w in mapping_test.windows(2) {
            if w[0] == w[1] { return None; }
        }
        Some(Permutation::random_prefixed(rng, prefix, size))
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;
    use crate::utils::permutation::Permutation;

    #[test]
    fn operations() {
        let rng = &mut rand::thread_rng();
        let a = Permutation::from_rng(rng, 52);
        let a_inv = a.inverse();

        let id = Permutation::identity(52);
        let s = a.apply(a_inv.deref());
        let s: Permutation = s.as_slice().into();
        assert!(s == id);

        let b = Permutation::from_rng(rng, 52);
        let b_inv = b.inverse();

        let c = a.apply(b.deref());
        let c: Permutation = c.as_slice().into();
        let d = b_inv.apply(a_inv.deref());
        let d: Permutation = d.as_slice().into();
        assert!(c.inverse() == d);

        let p = Permutation::random_prefixed(rng, &a.0, 52);
        assert!(p == a);
    }
}
