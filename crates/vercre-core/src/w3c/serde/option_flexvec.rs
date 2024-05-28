use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use serde::de;
use serde::de::value::MapAccessDeserializer;
use serde::de::{Deserialize, DeserializeOwned, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeSeq, Serializer};

pub(in crate::w3c) fn serialize<T, S>(
    value: &Option<Vec<T>>, serializer: S,
) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    // serialize None as empty array
    if value.is_none() {
        return serializer.serialize_none();
    }

    let Some(some_val) = value.as_ref() else {
        return serializer.serialize_none();
    };

    // serialize single entry to object, otherwise as array
    if some_val.len() == 1 {
        serializer.serialize_some(&some_val[0])
    } else {
        let mut seq = serializer.serialize_seq(Some(some_val.len()))?;
        for e in some_val {
            seq.serialize_element(e)?;
        }
        seq.end()
    }
}

pub(in crate::w3c) fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<Vec<T>>, D::Error>
where
    T: DeserializeOwned + FromStr,
    D: Deserializer<'de>,
{
    struct VisitorImpl<T>(PhantomData<fn() -> Vec<T>>);

    impl<'de, T> Visitor<'de> for VisitorImpl<T>
    where
        T: DeserializeOwned + FromStr,
    {
        type Value = Option<Vec<T>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("Option<Vec<<T>>")
        }

        // deserialize object to single Vec<T> entry
        fn visit_map<A>(self, access: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let res: T = Deserialize::deserialize(MapAccessDeserializer::new(access))?;
            Ok(Some(vec![res]))
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
            Ok(Some(deser))
        }

        // deserialize string to single Vec<T> entry
        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.starts_with('[') {
                // return Ok(Some(serde_json::from_str::<Vec<T>>(value).map_err(|e| {
                //     de::Error::custom(format!("issue deserializing array: {}", e))
                // })?));

                match serde_json::from_str::<Vec<T>>(value) {
                    Ok(res) => {
                        if res.len() == 1 {
                            return Err(de::Error::custom(
                                "a single-element array should be serialized as the element itself",
                            ));
                        }
                        return Ok(Some(res));
                    }
                    Err(e) => {
                        return Err(de::Error::custom(format!("issue deserializing array: {e}")));
                    }
                }
            }

            let Ok(res) = T::from_str(value) else {
                return Err(de::Error::invalid_type(de::Unexpected::Str(value), &self));
            };
            Ok(Some(vec![res]))
        }
    }

    deserializer.deserialize_any(VisitorImpl(PhantomData))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use anyhow::anyhow;
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    use crate::w3c::serde::{flexvec, option_flexvec};

    #[derive(Clone, Debug, Default, Deserialize, Serialize)]
    #[serde(default)]
    struct TestData {
        string: String,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(with = "option_flexvec")]
        object: Option<Vec<Nested>>,

        #[serde(with = "flexvec")]
        object_array: Vec<Nested>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(with = "option_flexvec")]
        array: Option<Vec<String>>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(with = "option_flexvec")]
        none: Option<Vec<String>>,
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
            string: String::from("string"),
            object: Some(vec![Nested {
                n: String::from("object"),
            }]),
            object_array: vec![
                Nested {
                    n: String::from("object1"),
                },
                Nested {
                    n: String::from("object2"),
                },
            ],
            array: Some(vec![String::from("item1"), String::from("item2")]),
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
        assert_eq!(test_json.get("none"), None);

        // deserialize
        let test_de: TestData = serde_json::from_value(test_json).expect("should deserialize");
        assert_eq!(test_de.string, test_data.string);
        assert_eq!(test_de.object, test_data.object);
        assert_eq!(test_de.object_array, test_data.object_array);
        assert_eq!(test_de.array, test_data.array);
        assert_eq!(test_de.none, test_data.none);
    }
}
