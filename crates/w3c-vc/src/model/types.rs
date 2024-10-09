//! # Shared Types
//!
//! This module contains lower-level types that are shared across the data
//! models for Verifiable Credentials (`vc`) and Verifiable Presentations
//! (`vp`).

use std::ops::Deref;

use serde::{Deserialize, Serialize};
use vercre_core::{Kind, Quota};

/// `LangString` is a string that has one or more language representations.
///
/// <https://www.w3.org/TR/vc-data-model-2.0/#language-and-base-direction>
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct LangString(Kind<Quota<LangValue>>);

impl LangString {
    /// Extract a value for the provided language tag.
    ///
    /// If the language string is a simple string, the value is returned as is.
    /// If the language string is an object, the value for the provided language
    /// tag is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if the language tag is not found.
    pub fn value(&self, language: &str) -> anyhow::Result<String> {
        match &self.0 {
            Kind::String(s) => Ok(s.to_string()),
            Kind::Object(lang_values) => match lang_values {
                Quota::One(lang_value) => {
                    if lang_value.language == language {
                        Ok(lang_value.value.clone())
                    } else {
                        Err(anyhow::anyhow!("Language tag not found"))
                    }
                }
                Quota::Many(lang_values) => {
                    for lang_value in lang_values {
                        if lang_value.language == language {
                            return Ok(lang_value.value.clone());
                        }
                    }
                    Err(anyhow::anyhow!("Language tag not found"))
                }
            },
        }
    }
}

impl Deref for LangString {
    type Target = Kind<Quota<LangValue>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

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

    fn info_sample() -> serde_json::Value {
        json!(
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
        )
    }

    #[test]
    fn language_string_serialization() {
        let info = info_sample();
        let hydrated: Info = serde_json::from_value(info).unwrap();
        assert_snapshot!("language_string_serialization", hydrated, {
            ".description" => insta::sorted_redaction(),
        });
        let serialized = serde_json::to_value(&hydrated).unwrap();
        assert_snapshot!("language_string_serialization_json", serialized);
    }

    #[test]
    fn language_string_value() {
        let json = info_sample();
        let info: Info = serde_json::from_value(json).unwrap();
        assert_eq!(info.name.value("en").unwrap(), "Alice");
        assert_eq!(
            info.other.expect("option should be some").value("en").unwrap(),
            "Just a string"
        );
        info.description.value("es").expect_err("Spanish language tag should not be found");
    }
}
