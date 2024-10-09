//! # Shared Types
//!
//! This module contains lower-level types that are shared across the data
//! models for Verifiable Credentials (`vc`) and Verifiable Presentations
//! (`vp`).

use serde::{Deserialize, Serialize};
use vercre_core::{Kind, Quota};

/// `LangString` is a string that has one or more language representations.
///
/// https://www.w3.org/TR/vc-data-model-2.0/#language-and-base-direction
pub type LangString = Kind<Quota<LangValue>>;

/// `LangValue` is a description of a string in a specific language.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct LangValue {
    /// Value of the string
    #[serde(rename = "@value")]
    pub value: String,

    /// Language-tag as defined in [rfc5646](https://www.rfc-editor.org/rfc/rfc5646)
    #[serde(rename = "@language")]
    pub language: String,

    /// Base direction of the text when bidirectional text is displayed.
    #[serde(rename = "@direction")]
    pub direction: Option<Direction>,
}

/// Base direction of the text when bidirectional text is displayed.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Direction {
    /// Left-to-right
    #[serde(rename = "ltr")]
    Ltr,

    /// Right-to-left
    #[serde(rename = "rtl")]
    Rtl,
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;

    use super::*;

    #[derive(Deserialize, Serialize)]
    struct Info {
        name: LangString,
        description: LangString,
        other: Option<LangString>,
    }

    #[test]
    fn language_string_serialization() {
        let info = json!(
            {
                "name": {
                    "@value": "Alice",
                    "@language": "en",
                },
                "description": [
                    {
                        "@value": "HTML and CSS: Designing and Creating Websites",
                        "@language": "en"
                    },
                    {
                        "@value": "HTML و CSS: تصميم و إنشاء مواقع الويب",
                        "@language": "ar",
                        "@direction": "rtl"
                    }
                ],
                "other": "Just a string"
            }
        );
        let hydrated: Info = serde_json::from_value(info).unwrap();
        assert_snapshot!("language_string_serialization", hydrated, {
            ".description" => insta::sorted_redaction(),
        });
        let serialized = serde_json::to_value(&hydrated).unwrap();
        assert_snapshot!("language_string_serialization_json", serialized);
    }
}
