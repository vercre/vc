use std::fmt::Debug;

use credibil_infosec::jose::jwk::PublicKeyJwk;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::core::Kind;
use crate::w3c_vc::model::VerifiableCredential;

/// The user information returned by the Subject trait.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Dataset {
    /// The credential subject populated for the user.
    pub claims: Map<String, Value>,

    /// Specifies whether user information required for the credential subject
    /// is pending.
    pub pending: bool,
}

/// `CredentialRequest` is used by the Client to make a Credential Request to
/// the Credential Endpoint.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct CredentialRequest {
    /// The URL of the Credential Issuer the Wallet can use obtain offered
    /// Credentials.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub credential_issuer: String,

    /// A previously issued Access Token, as extracted from the Authorization
    /// header of the Credential Request.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub access_token: String,

    /// Identifies the credential requested for issuance using either a
    /// `credential_identifier` or a supported format.
    ///
    /// If `credential_identifiers` were returned in the Token
    /// Response, they MUST be used here. Otherwise, they MUST NOT be used.
    #[serde(flatten)]
    pub credential: RequestBy,

    /// Wallet's proof of possession of cryptographic key material the issued
    /// Credential will be bound to.
    /// REQUIRED if the `proof_types_supported` parameter is non-empty and
    /// present in the `credential_configurations_supported` parameter of
    /// the Issuer metadata for the requested Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub proof: Option<Proof>,

    /// If present, specifies how the Credential Response should be encrypted.
    /// If not present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
}

/// Means used to identifiy Credential type and format when requesting a
/// Credential.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum RequestBy {
    /// Credential is requested by `credential_identifier`.
    /// REQUIRED when an Authorization Details of type `openid_credential` was
    /// returned from the Token Response.
    #[serde(rename = "credential_identifier")]
    Identifier(String),

    /// Credential is requested by `credential_configuration_id`. This
    /// identifies the entry in the `credential_configurations_supported`
    /// Issuer metadata.
    #[serde(rename = "credential_configuration_id")]
    ConfigurationId(String),
}

impl Default for RequestBy {
    fn default() -> Self {
        Self::Identifier(String::new())
    }
}

/// Wallet's proof of possession of the key material the issued Credential is to
/// be bound to.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum Proof {
    /// A single proof of possession of the cryptographic key material to which
    /// the issued Credential instance will be bound to.
    #[serde(rename = "proof")]
    Single {
        /// The proof type used by the wallet
        #[serde(flatten)]
        proof_type: SingleProof,
    },

    /// One or more proof of possessions of the cryptographic key material to
    /// which the issued Credential instances will be bound to.
    #[serde(rename = "proofs")]
    Multiple(MultipleProofs),
}

impl Default for Proof {
    fn default() -> Self {
        Self::Single {
            proof_type: SingleProof::default(),
        }
    }
}

/// A single proof of possession of the cryptographic key material provided by
/// the Wallet to which the issued Credential instance will be bound.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(tag = "proof_type")]
pub enum SingleProof {
    /// The JWT containing the Wallet's proof of possession of key material.
    #[serde(rename = "jwt")]
    Jwt {
        /// The JWT containing the Wallet's proof of possession of key material.
        jwt: String,
    },
}

impl Default for SingleProof {
    fn default() -> Self {
        Self::Jwt { jwt: String::new() }
    }
}

/// A a single proof of possession of the cryptographic key material provided by
/// the Wallet to which the issued Credential instance will be bound.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum MultipleProofs {
    /// The JWT containing the Wallet's proof of possession of key material.
    #[serde(rename = "jwt")]
    Jwt(Vec<String>),
}

impl Default for MultipleProofs {
    fn default() -> Self {
        Self::Jwt(vec![String::new()])
    }
}

/// Claims containing a Wallet's proof of possession of key material that can be
/// used for binding an issued Credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProofClaims {
    /// The `client_id` of the Client making the Credential request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// The Credential Issuer Identifier.
    pub aud: String,

    /// The time at which the proof was issued, as
    /// [RFC7519](https://www.rfc-editor.org/rfc/rfc7519) `NumericDate`.
    ///
    /// For example, "1541493724".
    pub iat: i64,

    /// A server-provided `c_nonce`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// Contains information about whether the Credential Issuer supports encryption
/// of the Credential Response on top of TLS.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialResponseEncryption {
    /// The public key used for encrypting the Credential Response.
    pub jwk: PublicKeyJwk,

    /// JWE [RFC7516] alg algorithm [RFC7518] for encrypting Credential
    /// Response.
    ///
    /// [RFC7516]: (https://www.rfc-editor.org/rfc/rfc7516)
    /// [RFC7518]: (https://www.rfc-editor.org/rfc/rfc7518)
    pub alg: String,

    /// JWE [RFC7516] enc algorithm [RFC7518] for encoding Credential Response.
    ///
    /// [RFC7516]: (https://www.rfc-editor.org/rfc/rfc7516)
    /// [RFC7518]: (https://www.rfc-editor.org/rfc/rfc7518)
    pub enc: String,
}

/// The Credential Response can be Synchronous or Deferred.
///
/// The Credential Issuer MAY be able to immediately issue a requested
/// Credential. In other cases, the Credential Issuer MAY NOT be able to
/// immediately issue a requested Credential and will instead return a
/// `transaction_id` to be used later to retrieve a Credential when it is ready.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialResponse {
    /// The Credential Response can be Synchronous or Deferred.
    #[serde(flatten)]
    pub response: CredentialResponseType,

    /// A nonce to be used to create a proof of possession of key material when
    /// requesting a Credential. When received, the Wallet MUST use this
    /// value for its subsequent credential requests until the Credential
    /// Issuer provides a fresh nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce: Option<String>,

    /// The lifetime in seconds of the `c_nonce` parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce_expires_in: Option<i64>,

    /// Identifies an issued Credential when the Wallet calls the Issuer's
    /// Notification endpoint. The `notification_id` is included in the
    /// Notification Request.
    ///
    /// Will only be set if credential parameter is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_id: Option<String>,
}

/// The Credential Response can be Synchronous or Deferred.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialResponseType {
    /// Contains issued Credential.It MAY be a string or an object, depending
    /// on the Credential Format.
    Credential(Kind<VerifiableCredential>),

    /// Contains an array of issued Credentials. The values in the array MAY be
    /// a string or an object, depending on the Credential Format.
    Credentials(Vec<Kind<VerifiableCredential>>),

    /// String identifying a Deferred Issuance transaction. This claim is
    /// contained in the response if the Credential Issuer cannot
    /// immediately issue the Credential. The value is subsequently used to
    /// obtain the respective Credential with the Deferred Credential
    /// Endpoint.
    TransactionId(String),
}

impl Default for CredentialResponseType {
    fn default() -> Self {
        Self::Credential(Kind::default())
    }
}

/// An HTTP POST request, which accepts an `acceptance_token` as the only
/// parameter. The `acceptance_token` parameter MUST be sent as Access Token in
/// the HTTP header.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DeferredCredentialRequest {
    /// The URL of the Credential Issuer the Wallet can use obtain offered
    /// Credentials.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub credential_issuer: String,

    /// A previously issued Access Token, as extracted from the Authorization
    /// header of the Batch Credential Request.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub access_token: String,

    /// Identifies a Deferred Issuance transaction from an earlier Credential
    /// Request.
    pub transaction_id: String,
}

/// The Deferred Credential Response uses the same format and credential
/// parameters defined for a Credential Response.
#[derive(Debug, Deserialize, Serialize)]
pub struct DeferredCredentialResponse {
    /// The Credential Response object.
    #[serde(flatten)]
    pub credential_response: CredentialResponse,
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;

    use super::*;
    use crate::oid4vci::types::CredentialConfiguration;

    #[test]
    fn credential_identifier() {
        let json = serde_json::json!({
            "credential_issuer": "https://example.com",
            "access_token": "1234",
            "credential_identifier": "EngineeringDegree2023",
            "proof": {
                "proof_type": "jwt",
                "jwt": "SomeJWT"
            }
        });

        let deserialized: CredentialRequest =
            serde_json::from_value(json.clone()).expect("should deserialize from json");
        assert_snapshot!("credential_identifier", &deserialized);

        let request = CredentialRequest {
            credential_issuer: "https://example.com".into(),
            access_token: "1234".into(),
            credential: RequestBy::Identifier("EngineeringDegree2023".to_string()),
            proof: Some(Proof::Single {
                proof_type: SingleProof::Jwt {
                    jwt: "SomeJWT".into(),
                },
            }),
            ..CredentialRequest::default()
        };

        let serialized = serde_json::to_value(&request).expect("should serialize to string");
        assert_eq!(json, serialized);
    }

    #[test]
    fn credential_format() {
        let json = serde_json::json!({
          "credential_issuer": "https://example.com",
          "access_token": "1234",
          "format": "jwt_vc_json",
          "credential_definition": {
            "type": [
              "VerifiableCredential",
              "EmployeeIDCredential"
            ],
          },
          "proof": {
            "proof_type": "jwt",
            "jwt": "SomeJWT"
          }
        });

        let deserialized: CredentialRequest =
            serde_json::from_value(json.clone()).expect("should deserialize from json");
        assert_snapshot!("credential_format", &deserialized);

        let request = CredentialRequest {
            credential_issuer: "https://example.com".into(),
            access_token: "1234".into(),
            credential: RequestBy::ConfigurationId("EmployeeID_JWT".to_string()),
            proof: Some(Proof::Single {
                proof_type: SingleProof::Jwt {
                    jwt: "SomeJWT".into(),
                },
            }),
            ..CredentialRequest::default()
        };

        let serialized = serde_json::to_value(&request).expect("should serialize to string");
        assert_eq!(json, serialized);
    }

    #[test]
    fn multiple_proofs() {
        let json = serde_json::json!({
            "credential_issuer": "https://example.com",
            "access_token": "1234",
            "credential_identifier": "EngineeringDegree2023",
            "proofs": {
                "jwt": [
                    "SomeJWT1",
                    "SomeJWT2"
                ]
            }
        });

        let deserialized: CredentialRequest =
            serde_json::from_value(json.clone()).expect("should deserialize from json");
        assert_snapshot!("multiple_proofs", &deserialized);

        let request = CredentialRequest {
            credential_issuer: "https://example.com".into(),
            access_token: "1234".into(),
            credential: RequestBy::Identifier("EngineeringDegree2023".to_string()),
            proof: Some(Proof::Multiple(MultipleProofs::Jwt(vec![
                "SomeJWT1".into(),
                "SomeJWT2".into(),
            ]))),
            ..CredentialRequest::default()
        };

        let serialized = serde_json::to_value(&request).expect("should serialize to string");
        assert_eq!(json, serialized);
    }

    #[test]
    fn claim_label_display() {
        let json = serde_json::json!({
            "format": "jwt_vc_json",
            "scope": "EmployeeIDCredential",
            "cryptographic_binding_methods_supported": [
                "did:key",
                "did:web"
            ],
            "credential_signing_alg_values_supported": [
                "ES256K",
                "EdDSA"
            ],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": [
                        "ES256K",
                        "EdDSA"
                    ]
                }
            },
            "display": [
                {
                    "name": "Employee ID",
                    "description": "Credibil employee ID credential",
                    "locale": "en-NZ",
                    "logo": {
                        "uri": "https://credibil.io/assets/employee.png",
                        "alt_text": "Employee ID Logo"
                    },
                    "text_color": "#ffffff",
                    "background_color": "#323ed2",
                    "background_image": {
                        "uri": "https://credibil.io/assets/employee-background.png",
                        "alt_text": "Employee ID Background"
                    }
                }
            ],
            "credential_definition": {
                "type": [
                    "VerifiableCredential",
                    "EmployeeIDCredential"
                ],
                "credentialSubject": {
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
                    },
                    "address": {
                        "street_address": {
                            "value_type": "string",
                            "display": [
                                {
                                    "name": "Street Address",
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
                        "country": {
                            "value_type": "string",
                            "display": [
                                {
                                    "name": "Country",
                                    "locale": "en-NZ"
                                }
                            ]
                        }
                    }
                }
            }
        });

        let config: CredentialConfiguration =
            serde_json::from_value(json.clone()).expect("should deserialize from json");
        let claims = config.claims_display(Some("en-NZ"));
        assert_snapshot!("claim_label_display_en-NZ", &claims, {
            "." => insta::sorted_redaction(),
        });
        let default = config.claims_display(None);
        assert_snapshot!("claim_label_display_default", &default, {
            "." => insta::sorted_redaction(),
        });
    }
}
