//! # Stringify
//!
//! This module provides a serde serializer and deserializer for 'stringifying'
//! types to simplify serializing/deserializing complex types for compliance
//! with `OpenID` issuance and presentation specifications.

use std::fmt;
use std::marker::PhantomData;

use serde::de::{self, Deserialize, DeserializeOwned, Deserializer, MapAccess, Visitor};
use serde::ser::{self, Serialize, Serializer};

/// Serialize a type to a string.
///
/// # Errors
///
/// This function will return an `Err::ServerError` error if the string cannot
/// be serialized into the target type.
pub fn serialize<T, S>(value: &Option<T>, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    // T: Serialize + ToString,
    T: Serialize,
    S: Serializer,
{
    if let Some(val) = value {
        let string = serde_json::to_string(val)
            .map_err(|e| ser::Error::custom(format!("issue 'stringifying': {e}")))?;
        serializer.serialize_str(&string)
    } else {
        serializer.serialize_none()
    }
}

/// Deserialize a type from a string or struct.
///
/// # Errors
///
/// This function will return an `Err::ServerError` error if the string cannot
/// be deserialized into the target type.
pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: DeserializeOwned,
    D: Deserializer<'de>,
{
    struct VisitorImpl<T>(PhantomData<fn() -> Option<T>>);

    impl<'de, T> Visitor<'de> for VisitorImpl<Option<T>>
    where
        T: DeserializeOwned,
    {
        type Value = Option<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("deserialized string")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let val = serde_json::from_str::<T>(value)
                .map_err(|e| de::Error::custom(format!("issue 'de-stringifying': {e}")))?;
            Ok(Some(val))
        }

        // just in case we get an un-stringified json object...
        fn visit_map<M>(self, map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let res: T = Deserialize::deserialize(de::value::MapAccessDeserializer::new(map))?;
            Ok(Some(res))
        }
    }

    deserializer.deserialize_any(VisitorImpl(PhantomData))
}
