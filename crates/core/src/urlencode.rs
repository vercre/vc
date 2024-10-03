mod de;
mod error;
mod ser;

pub use ser::to_string;

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::ser;

    #[derive(Serialize, Deserialize)]
    struct TopLevel {
        field_1: String,
        field_2: String,
        nested: Nested,
    }

    #[derive(Serialize, Deserialize)]
    struct Nested {
        field_3: String,
        field_4: String,
    }

    #[test]
    fn encode() {
        let data = TopLevel {
            field_1: "field1".to_owned(),
            field_2: "field2".to_owned(),
            nested: Nested {
                field_3: "field3".to_owned(),
                field_4: "field4".to_owned(),
            },
        };

        let serialized = ser::to_string(&data).expect("should serialize");
        println!("{serialized}");
    }
}
