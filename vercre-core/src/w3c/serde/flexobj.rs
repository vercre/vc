use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use serde::de;
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde::ser::{Serialize, Serializer};

pub(in crate::w3c) fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    value.serialize(serializer)
}

pub(in crate::w3c) fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: Deserialize<'de> + FromStr,
    D: Deserializer<'de>,
{
    struct FlexObj<T>(PhantomData<fn() -> T>);

    impl<'de, T> Visitor<'de> for FlexObj<T>
    where
        T: Deserialize<'de> + FromStr,
    {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or map")
        }

        // deserialize string to T using T's FromStr implementation
        fn visit_str<E>(self, value: &str) -> Result<T, E>
        where
            E: de::Error,
        {
            T::from_str(value).map_or_else(
                |_| Err(de::Error::invalid_value(de::Unexpected::Str(value), &self)),
                |res| Ok(res),
            )
        }

        // deserialize object to T
        fn visit_map<M>(self, map: M) -> Result<T, M::Error>
        where
            M: MapAccess<'de>,
        {
            Deserialize::deserialize(de::value::MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_any(FlexObj(PhantomData))
}
