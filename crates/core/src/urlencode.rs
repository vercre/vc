//! # Url Encoder/Decoder

mod de;
mod error;
mod ser;

pub use de::{from_str, Deserializer};
pub use ser::{to_string, Serializer};

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::ser;

    #[derive(Debug, Serialize, Deserialize)]
    struct TopLevel {
        field_1: String,
        field_2: String,
        nested: Nested,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Nested {
        field_3: String,
        field_4: String,
    }

    #[test]
    fn encode_struct() {
        let data = TopLevel {
            field_1: "value1".to_owned(),
            field_2: "value2".to_owned(),
            nested: Nested {
                field_3: "field3".to_owned(),
                field_4: "field4".to_owned(),
            },
        };

        let serialized = super::to_string(&data).expect("should serialize");
        println!("{serialized}");

        let expected = r#"field_1=value1&field_2=value2&nested=%7B%22field_3%22%3A%22field3%22%2C%22field_4%22%3A%22field4%22%7D"#;
        assert_eq!(serialized, expected);
    }

    #[test]
    fn encode_enum() {
        #[derive(Serialize)]
        enum E {
            Unit,
            Newtype(u32),
            Tuple(u32, u32),
            Struct { a: u32 },
        }

        let u = E::Unit;
        let expected = r#"Unit"#;
        assert_eq!(ser::to_string(&u).unwrap(), expected);

        let n = E::Newtype(1);
        let expected = r#"Newtype=1"#;
        assert_eq!(ser::to_string(&n).unwrap(), expected);

        let t = E::Tuple(1, 2);
        let expected = r#"Tuple=%5B1%2C2%5D"#;
        assert_eq!(ser::to_string(&t).unwrap(), expected);

        let s = E::Struct { a: 1 };
        let expected = r#"Struct=%7Ba%3A1%7D"#;
        assert_eq!(ser::to_string(&s).unwrap(), expected);
    }

    #[test]
    fn decode_struct() {
        let encoded = r#"field_1=value1&field_2=value2&nested=%7B%22field_3%22%3A%22field3%22%2C%22field_4%22%3A%22field4%22%7D"#;

        let deserialized: TopLevel = super::from_str(encoded).expect("should serialize");
        println!("{deserialized:?}");

        // let expected = r#"field_1=field1&field_2=field2&nested=%7B%22field_3%22%3A%22field3%22%2C%22field_4%22%3A%22field4%22%7D"#;
        // assert_eq!(serialized, expected);
    }
}
