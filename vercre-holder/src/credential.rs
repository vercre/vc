//! # Holder Agent (Wallet)
//!
//! This module defines types and traits to enable wallets or other holder
//! agents to interact with the `vercre-holder` endpoints.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use vercre_core::strings::title_case;
use vercre_dif_exch::Claims;
use vercre_issuer::Claim;
use vercre_openid::issuer::CredentialDisplay;
use vercre_w3c_vc::model::CredentialSubject;

/// A set of claims for a subject (holder).
///
/// (Some credentials can be issued to multiple subjects).
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubjectClaims {
    /// An identifier of the subject (holder) of the claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// The claims for the subject as a map of JSON objects.
    pub claims: Map<String, Value>,
}

impl From<CredentialSubject> for SubjectClaims {
    fn from(subject: CredentialSubject) -> Self {
        Self {
            id: subject.id,
            claims: subject.claims,
        }
    }
}

/// The Credential model contains information about a credential owned by the
/// Wallet.
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credential {
    /// Credential `id` is the credential's unique identifier
    /// (from Verifiable Credential `id` or generated if credential has no
    /// `id`).
    pub id: String,

    /// The credential issuer ID.
    pub issuer: String,

    /// The credential issuer's name. (from the issuer's metadata).
    pub issuer_name: String,

    /// The Verifiable Credential as issued, for use in Presentation
    /// Submissions. This could be a base64-encoded JWT or 'stringified'
    /// JSON.
    pub issued: String,

    /// The credential type. Used to determine whether a credential matches a
    /// presentation request.
    #[serde(rename = "type")]
    pub type_: Vec<String>,

    /// Credential format. Information on how the encoded credential is
    /// formatted.
    pub format: String,

    /// Claim definitions that can be used for displaying the credential.
    pub claim_definitions: Option<HashMap<String, Claim>>,

    /// Claims for one or more subjects (holders).
    pub subject_claims: Vec<SubjectClaims>,

    /// The date the credential was issued.
    pub issuance_date: DateTime<Utc>,

    /// The date the credential is valid from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,

    /// The date the credential is valid until (expiry).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,

    /// Display information from the issuer's metadata for this credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<CredentialDisplay>>,

    /// A base64-encoded logo image for the credential ingested from the logo
    /// url in the display section of the metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<ImageData>,

    /// A base64-encoded background image for the credential ingested from the
    /// url in the display section of the metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background: Option<ImageData>,
}

/// Get the claims on the VC as a JSON object.
impl Claims for Credential {
    /// Serialize Claims as a JSON object.
    ///
    /// # Errors
    ///
    /// The implementation should return an error if the Claims cannot be
    /// serialized to JSON.
    fn to_json(&self) -> anyhow::Result<serde_json::Value> {
        serde_json::to_value(self).map_err(Into::into)
    }
}

impl Credential {
    /// Convenience method to display the claims and their values as a vector
    /// of labels and values, where the labels honour locale display
    /// configuration.
    ///
    /// Nested claims are flattened using dot notation in the
    /// label.
    #[must_use]
    pub fn claims_display(
        &self, subject_id: Option<&str>, locale: Option<&str>,
    ) -> Vec<(String, String)> {
        // Get the claim set for the subject
        let subject_claims =
            match self.subject_claims.iter().find(|sc| sc.id.as_deref() == subject_id) {
                Some(sc) => &sc.claims,
                None => {
                    return Vec::new();
                }
            };

        let mut claim_set = Vec::new();
        for (name, claim) in subject_claims {
            let prefix = "";
            self.claim_label_and_value(&mut claim_set, prefix, name, claim, locale);
        }
        claim_set
    }

    /// Recursively build the claim label and value pairs using credential
    /// definition information.
    fn claim_label_and_value(
        &self, claim_set: &mut Vec<(String, String)>, prefix: &str, name: &str, claim: &Value,
        locale: Option<&str>,
    ) {
        match claim {
            Value::Object(map) => {
                let mut pre = prefix.to_string();
                pre.push_str(&title_case(name));
                pre.push('.');
                for (name, claim) in map {
                    self.claim_label_and_value(claim_set, &pre, name, claim, locale);
                }
            }
            _ => {
                // Try to get the claim definition and locale display name. Otherwise just use the
                // claim name.
                if let Some(claim_def) = self.claim_definitions.as_ref().and_then(|cd| cd.get(name))
                {
                    if let Claim::Entry(def) = claim_def {
                        let locale_display = def.display.as_ref().and_then(|display| {
                            locale.as_ref().map_or_else(
                                || {
                                    Some(
                                        display
                                            .iter()
                                            .find(|d| d.locale.is_none())
                                            .unwrap_or_else(|| &display[0]),
                                    )
                                },
                                |loc| display.iter().find(|d| d.locale.as_deref() == Some(loc)),
                            )
                        });
                        match locale_display {
                            Some(display) => claim_set
                                .push((prefix.to_owned() + &display.name, claim.to_string().replace('"', ""))),
                            None => claim_set
                                .push((prefix.to_owned() + &title_case(name), claim.to_string().replace('"', ""))),
                        }
                    } else {
                        // This shouldn't happen: if the claim definition is a Set (nested claim),
                        // then the claim should be an object. To be safe, we just use the claim
                        // name.
                        claim_set.push((prefix.to_owned() + &title_case(name), claim.to_string().replace('"', "")));
                    }
                } else {
                    claim_set.push((prefix.to_owned() + &title_case(name), claim.to_string().replace('"', "")));
                }
            }
        }
    }
}


/// Image information for a credential.
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImageData {
    /// The logo image as a base64-encoded string.
    pub data: String,

    /// Content type. e.g. "image/png"
    #[serde(rename = "mediaType")]
    pub media_type: String,
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot;

    use super::*;

    #[test]
    fn test_claims_display() {
        let json = serde_json::json!({
            "id": "http://vercre.io/credentials/EmployeeIDCredential",
            "issuer": "http://vercre.io",
            "issuer_name": "Vercre",
            "issued": "2024-11-21T22:35:18Z",
            "type": [
              "EmployeeIDCredential",
              "VerifiableCredential"
            ],
            "format": "jwt_vc_json",
            "claim_definitions": {
                "address": {
                    "country": {
                        "value_type": "string",
                        "display": [
                            {
                                "name": "Country",
                                "locale": "en-NZ"
                            }
                        ]
                    },
                    "locality": {
                        "value_type": "string",
                        "display": [
                            {
                                "name": "Locality",
                                "locale": "en-NZ"
                            }
                        ]
                    },
                    "region": {
                        "value_type": "string",
                        "display": [
                            {
                                "name": "Region",
                                "locale": "en-NZ"
                            }
                        ]
                    },
                    "street_address": {
                        "value_type": "string",
                        "display": [
                            {
                                "name": "Street Address",
                                "locale": "en-NZ"
                            }
                        ]
                    }
                },
                "email": {
                    "mandatory": true,
                    "value_type": "string",
                    "display": [
                        {
                            "name": "Email",
                            "locale": "en-NZ"
                        }
                    ]
                },
                "family_name": {
                    "mandatory": true,
                    "value_type": "string",
                    "display": [
                        {
                            "name": "Family name",
                            "locale": "en-NZ"
                        }
                    ]
                },
                "given_name": {
                    "mandatory": true,
                    "value_type": "string",
                    "display": [
                        {
                            "name": "Given name",
                            "locale": "en-NZ"
                        }
                    ]
                }
            },
            "subject_claims": [
                {
                    "claims": {
                        "address": {
                            "locality": "Wellington",
                            "street_address": "123 Fake St"
                        },
                        "email": "normal.user@example.com",
                        "family_name": "Person",
                        "given_name": "Normal"
                    },
                    "id": "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX"
                }
            ],
            "issuance_date": "2024-11-22T01:10:00Z",
            "display": [
                {
                    "name": "Employee ID",
                    "locale": "en-NZ",
                    "logo": {
                        "uri": "https://vercre.github.io/assets/employee.png",
                        "alt_text": "Vercre Logo"
                    },
                    "description": "Vercre employee ID credential",
                    "background_color": "#323ed2",
                    "background_image": {
                        "uri": "https://vercre.github.io/assets/employee-background.png",
                        "alt_text": "Vercre Background"
                    },
                    "text_color": "#ffffff",
                }
            ],
            "logo": {
                "data": "",
                "mediaType": ""
            },
            "background": {
                "data": "",
                "mediaType": ""
            }
        });
        let credential = serde_json::from_value::<Credential>(json).unwrap();
        let claims =
            credential.claims_display(credential.subject_claims[0].id.as_deref(), Some("en-NZ"));
        assert_yaml_snapshot!("claims_display_en-NZ", &claims, {
            "." => insta::sorted_redaction(),
        });
        let default = credential.claims_display(credential.subject_claims[0].id.as_deref(), None);
        assert_yaml_snapshot!("claims_display_default", &default, {
            "." => insta::sorted_redaction(),
        });
    }
}
