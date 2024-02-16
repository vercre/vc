use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use serde::de;
use serde::de::value::MapAccessDeserializer;
use serde::de::{Deserialize, DeserializeOwned, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeSeq, Serializer};

pub(in crate::w3c) fn serialize<T, S>(value: &[T], serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    // serialize single entry to object, otherwise as array
    if value.len() == 1 {
        serializer.serialize_some(&value[0])
    } else {
        let mut seq = serializer.serialize_seq(Some(value.len()))?;
        for e in value {
            seq.serialize_element(e)?;
        }
        seq.end()
    }
}

pub(in crate::w3c) fn deserialize<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    T: DeserializeOwned + FromStr,
    D: Deserializer<'de>,
{
    struct FlexSet<T>(PhantomData<fn() -> Vec<T>>);

    impl<'de, T> Visitor<'de> for FlexSet<T>
    where
        T: DeserializeOwned + FromStr,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("Option<Vec<<T>>")
        }

        // deserialize object to single Vec<T> entry
        fn visit_map<A>(self, access: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let res: T = Deserialize::deserialize(MapAccessDeserializer::new(access))?;
            Ok(vec![res])
        }

        // deserialize array to Vec<T>
        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            // could be mixed array of strings and objects
            let mut deser: Vec<T> = Vec::new();
            while let Some(curr) = seq.next_element::<serde_json::Value>()? {
                match curr {
                    serde_json::Value::String(s) => {
                        let Ok(res) = T::from_str(&s) else {
                            return Err(de::Error::invalid_type(de::Unexpected::Str(&s), &self));
                        };
                        deser.push(res);
                    }
                    serde_json::Value::Object(o) => {
                        let Ok(res) = serde_json::from_value::<T>(serde_json::Value::Object(o))
                        else {
                            return Err(de::Error::invalid_type(de::Unexpected::Map, &self));
                        };
                        deser.push(res);
                    }
                    _ => {
                        return Err(de::Error::custom(
                            "invalid type: cannot deserialize array element",
                        ));
                    }
                }
            }
            Ok(deser)
        }

        // deserialize string to single Vec<T> entry
        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            // check for serialized array
            if value.starts_with('[') {
                // return Ok(serde_json::from_str::<Vec<T>>(value).map_err(|e| {
                //     de::Error::custom(format!("issue deserializing array: {}", e))
                // })?);

                match serde_json::from_str::<Vec<T>>(value) {
                    Ok(res) => {
                        if res.len() == 1 {
                            return Err(de::Error::custom(
                                "a single-element array should be serialized as the element itself",
                            ));
                        }
                        return Ok(res);
                    }
                    Err(e) => {
                        return Err(de::Error::custom(format!("issue deserializing array: {e}")));
                    }
                }
            }

            let Ok(res) = T::from_str(value) else {
                return Err(de::Error::invalid_type(de::Unexpected::Str(value), &self));
            };
            Ok(vec![res])
        }
    }

    deserializer.deserialize_any(FlexSet(PhantomData))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use anyhow::anyhow;
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    use crate::w3c::serde::flexvec;

    #[derive(Clone, Debug, Default, Deserialize, Serialize)]
    #[serde(default)]
    struct TestData {
        string: String,

        #[serde(with = "flexvec")]
        object: Vec<Nested>,

        #[serde(with = "flexvec")]
        object_array: Vec<Nested>,

        #[serde(with = "flexvec")]
        array: Vec<String>,

        #[serde(with = "flexvec")]
        none: Vec<String>,
    }

    #[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
    struct Nested {
        n: String,
    }

    impl FromStr for Nested {
        type Err = anyhow::Error;

        fn from_str(_: &str) -> Result<Self, Self::Err> {
            Err(anyhow!("unimplemented"))
        }
    }

    #[test]
    fn test_flex() {
        let test_data = TestData {
            string: "string".to_string(),
            object: vec![Nested {
                n: "object".to_string(),
            }],
            object_array: vec![
                Nested {
                    n: "object1".to_string(),
                },
                Nested {
                    n: "object2".to_string(),
                },
            ],
            array: vec!["item1".to_string(), "item2".to_string()],
            none: Default::default(),
        };

        // serialize
        let test_json = serde_json::to_value(&test_data).expect("should serialize");
        assert_eq!(*test_json.get("string").expect("string should be set"), json!("string"));
        assert_eq!(*test_json.get("object").expect("object should be set"), json!({"n": "object"}));
        assert_eq!(
            *test_json.get("object_array").expect("object_array should be set"),
            json!([{"n": "object1"}, {"n": "object2"}])
        );
        assert_eq!(
            *test_json.get("array").expect("array should be set"),
            json!(["item1", "item2"]),
        );
        assert_eq!(*test_json.get("none").expect("none should be set"), json!([]));

        // deserialize
        let test_de: TestData = serde_json::from_value(test_json).expect("should deserialize");
        assert_eq!(test_de.string, test_data.string);
        assert_eq!(test_de.object, test_data.object);
        assert_eq!(test_de.object_array, test_data.object_array);
        assert_eq!(test_de.array, test_data.array);
        assert_eq!(test_de.none, test_data.none);
    }
}
