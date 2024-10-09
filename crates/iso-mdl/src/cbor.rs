use std::io::Cursor;

use anyhow::anyhow;
use ciborium::Value;
use coset::CoseError;
use serde::de::{self, DeserializeOwned};
use serde::{ser, Deserialize, Serialize};

pub fn to_vec<T>(value: &T) -> anyhow::Result<Vec<u8>>
where
    T: serde::Serialize,
{
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)?;
    Ok(buf)
}

pub fn from_slice<T>(slice: &[u8]) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    ciborium::from_reader(Cursor::new(&slice)).map_err(|e| {
        anyhow!(CoseError::DecodeFailed(ciborium::de::Error::Semantic(None, e.to_string())))
    })
}

/// Wrap types that require tagging with tag 24.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag24<T> {
    pub inner: T,
}

impl<T: Serialize> Tag24<T> {
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }

    pub fn to_vec(&self) -> anyhow::Result<Vec<u8>> {
        to_vec(&self.inner)
    }
}

impl<T: DeserializeOwned> TryFrom<Value> for Tag24<T> {
    type Error = anyhow::Error;

    fn try_from(v: Value) -> anyhow::Result<Self> {
        match v.clone() {
            Value::Tag(24, inner_value) => match inner_value.as_ref() {
                Value::Bytes(inner_bytes) => {
                    let inner: T = from_slice(inner_bytes)?;
                    Ok(Self { inner })
                }
                _ => Err(anyhow!("invalid tag: {inner_value:?}")),
            },
            _ => Err(anyhow!("not a tag24: {v:?}")),
        }
    }
}

impl<T: Serialize> Serialize for Tag24<T> {
    fn serialize<S: ser::Serializer>(&self, s: S) -> anyhow::Result<S::Ok, S::Error> {
        Value::Tag(24, Box::new(Value::Bytes(to_vec(&self.inner).unwrap()))).serialize(s)
    }
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for Tag24<T> {
    fn deserialize<D>(deserializer: D) -> anyhow::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        value.try_into().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod test {
    use super::Tag24;

    #[test]
    #[should_panic]
    // A Tag24 cannot be serialized directly into a non-cbor format as it will lose the tag.
    fn non_cbor_roundtrip() {
        let original = Tag24::new(String::from("some data"));
        let json = serde_json::to_vec(&original).unwrap();
        let roundtripped = serde_json::from_slice(&json).unwrap();
        assert_eq!(original, roundtripped)
    }
}
