
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Valid, Validate, SerializationError};

use ark_std::{borrow::{Borrow,Cow,ToOwned}, convert::AsRef, io::{Read,Write}, ops::{Deref}, vec::Vec};

#[derive(Clone,Debug,Default,PartialEq,Eq,PartialOrd,Ord)]
pub struct CowVec<T: 'static+Clone>(pub Cow<'static,[T]>);

impl<T: 'static+Clone> CowVec<T> {
    pub fn owned(moo: Vec<T>) -> CowVec<T> {
        CowVec(Cow::Owned(moo))
    }
    pub const fn borrowed(moo: &'static [T]) -> CowVec<T> {
        CowVec(Cow::Borrowed(moo))
    }
}

impl<T: 'static+Clone> Deref for CowVec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        self.0.deref()
    }
}

impl<T: 'static+Clone> Borrow<[T]> for CowVec<T> {
    fn borrow(&self) -> &[T] {
        self.0.borrow()
    }
}

impl<T: 'static+Clone> AsRef<[T]> for CowVec<T> {
    fn as_ref(&self) -> &[T] {
        self.0.as_ref()
    }
}

impl<'a, T: 'static+Clone> IntoIterator for &'a CowVec<T> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T: 'static+Clone+CanonicalSerialize> CanonicalSerialize for CowVec<T> {
    #[inline]
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.as_ref().serialize_with_mode(&mut writer, compress)
    }

    #[inline]
    fn serialized_size(&self, compress: Compress) -> usize {
        self.as_ref().serialized_size(compress)
    }
}

impl<T: 'static+Clone+Valid> Valid for CowVec<T> {
    #[inline]
    fn check(&self) -> Result<(), SerializationError> {
        <Vec<T>>::check(&self.as_ref().to_owned())
    }

    #[inline]
    fn batch_check<'a>(
        batch: impl Iterator<Item = &'a Self> + Send,
    ) -> Result<(), SerializationError>
    where
        Self: 'a,
    {
        let t: Vec<_> = batch.map(|v| v.as_ref().to_owned()).collect();
        <Vec<T>>::batch_check(t.iter())
    }
}

impl<T: 'static+Clone+CanonicalDeserialize> CanonicalDeserialize for CowVec<T> {
    #[inline]
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        Ok(CowVec::owned(Vec::deserialize_with_mode(
            reader, compress, validate,
        )?))
    }
}
