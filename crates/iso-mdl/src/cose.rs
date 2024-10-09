mod cose_key;

// use std::borrow::{Borrow, BorrowMut};
// use std::ops::{Deref, DerefMut};

// use coset::{iana,
use coset::{AsCborValue, TaggedCborSerializable};
use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};

#[allow(clippy::module_name_repetitions)]
pub use self::cose_key::{OKPCurve,CoseKey};

#[derive(Debug, Clone)]
pub struct Tagged<T>
where
    T: AsCborValue + TaggedCborSerializable,
{
    pub tagged: bool,
    pub inner: T,
}

impl<T> Tagged<T>
where
    T: AsCborValue + TaggedCborSerializable,
{
    pub const fn new(tagged: bool, inner: T) -> Self {
        Self { tagged, inner }
    }

    // /// If we are serialized as tagged.
    // pub fn is_tagged(&self) -> bool {
    //     self.tagged
    // }

    // /// Set serialization to tagged.
    // pub fn set_tagged(&mut self) {
    //     self.tagged = true;
    // }
}

// impl<T> Deref for Tagged<T>
// where
//     T: AsCborValue + TaggedCborSerializable,
// {
//     type Target = T;

//     fn deref(&self) -> &Self::Target {
//         &self.inner
//     }
// }

// impl<T> DerefMut for Tagged<T>
// where
//     T: AsCborValue + TaggedCborSerializable,
// {
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         &mut self.inner
//     }
// }

// impl<T> Borrow<T> for Tagged<T>
// where
//     T: AsCborValue + TaggedCborSerializable,
// {
//     fn borrow(&self) -> &T {
//         &self.inner
//     }
// }

// impl<T> BorrowMut<T> for Tagged<T>
// where
//     T: AsCborValue + TaggedCborSerializable,
// {
//     fn borrow_mut(&mut self) -> &mut T {
//         &mut self.inner
//     }
// }

// impl<T> AsRef<T> for Tagged<T>
// where
//     T: AsCborValue + TaggedCborSerializable,
// {
//     fn as_ref(&self) -> &T {
//         &self.inner
//     }
// }

/// Serialize manually using `ciborium::tag::Captured`, putting the tag if
/// necessary.
impl<T> serde::Serialize for Tagged<T>
where
    T: AsCborValue + TaggedCborSerializable + Clone,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let tag = if self.tagged { Some(T::TAG) } else { None };

        ciborium::tag::Captured(tag, CborValue(&self.inner)).serialize(serializer)
    }
}

/// Deserialize manually using `ciborium::tag::Captured`, checking the tag.
impl<'de, T> serde::Deserialize<'de> for Tagged<T>
where
    T: AsCborValue + TaggedCborSerializable,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let ciborium::tag::Captured(tag, CborValue(inner)) =
            ciborium::tag::Captured::deserialize(deserializer)?;
        let tagged = match tag {
            Some(tag) if tag == T::TAG => true,
            Some(_) => return Err(serde::de::Error::custom("unexpected tag")),
            None => false,
        };

        Ok(Self { tagged, inner })
    }
}

/// This is a small helper wrapper to deal with `coset` types that don't
/// implement `Serialize`/`Deserialize` but only `AsCborValue`.
pub struct CborValue<T>(pub T);

impl<T: Clone + AsCborValue> Serialize for CborValue<&T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.clone().to_cbor_value().map_err(ser::Error::custom)?.serialize(serializer)
    }
}

impl<'de, T: AsCborValue> Deserialize<'de> for CborValue<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::from_cbor_value(ciborium::Value::deserialize(deserializer)?)
            .map_err(de::Error::custom)
            .map(Self)
    }
}
