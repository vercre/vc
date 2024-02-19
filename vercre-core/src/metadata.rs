//! # Metadata
//!
//! Types and traits for working with `OpenID` Connect client and server metadata.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::Err;
use crate::{err, error, Result};

/// OAuth 2.0 Authorization Code grant type.
pub const AUTH_CODE_GRANT_TYPE: &str = "authorization_code";

/// `OpenID4VCI` Pre-Authorized Code grant type.
pub const PRE_AUTH_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

/// OAuth 2 client metadata used for registering clients of the issuance and
/// vercre-wallet authorization servers.
///
/// In the case of Credential Issuance, the Wallet is the Client and the Issuer
/// is the Authorization Server.
///
/// In the case of Wallet Authorization, the Wallet is the Authorization Server
/// and the Verifier is the Client.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Client {
    /// ID of the registered client.
    pub client_id: String,

    /// Time at which the client identifier was issued, as Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_issued_at: Option<i64>,

    /// OAuth 2.0 client secret string. If issued, this MUST be unique for each
    /// 'client_id' and SHOULD be unique for multiple instances of a client
    /// using the same 'client_id'.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,

    /// Required if 'client_secret' is issued. Time at which the client secret
    /// will expire (Unix time) or 0 if it will not expire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,

    /// Redirection URIs for use in authorization code redirect-based flows.
    /// As required by RFC6749, clients using flows with redirection MUST
    /// register their redirection URI values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,

    /// Authentication method for the token endpoint.
    /// Values are:
    /// - "none": The client is public and does not have a secret
    /// - ~~"client_secret_post": The client uses RFC6749 HTTP POST
    ///   parameters.~~
    /// - ~~"client_secret_basic": The client uses HTTP Basic.~~
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,

    /// OAuth 2.0 grant types the client can use at the token endpoint.
    /// Supported grant types are:
    /// - "authorization_code": RFC6749 Authorization Code Grant
    /// - "urn:ietf:params:oauth:grant-type:pre-authorized_code": OpenID4VCI
    ///   Pre-Authorized Code Grant
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<String>>,

    /// OAuth 2.0 response types the client can use at the authorization
    /// endpoint. MUST be "code".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types: Option<Vec<String>>,

    /// Human-readable name of the client shown to the end-user during
    /// authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,

    /// URL of a web page providing information about the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,

    /// URL string that references a logo for the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,

    /// A space-separated list of scope values the client can use when
    /// requesting access tokens. Semantics of scope values are service
    /// specific.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Ways to contact people responsible for the client, typically email
    /// addresses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<String>,

    /// URL pointing to a human-readable terms of service document for the
    /// client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,

    /// URL pointing to a human-readable privacy policy for the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,

    /// URL referencing the client's JSON Web Key (JWK) Set [RFC7517](https://www.rfc-editor.org/rfc/rfc7517) document,
    /// containing the client's public keys. MUST NOT both be set if the`jwks`
    /// parameter is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// Client's JSON Web Key Set [RFC7517](https://www.rfc-editor.org/rfc/rfc7517), containing the client's public
    /// keys. MUST be a JSON object containing a valid JWK Set. MUST NOT be
    /// set if the `jwks_uri` parameter is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,

    /// A unique identifier string (e.g., a Universally Unique Identifier
    /// (UUID)) assigned by the client developer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_id: Option<String>,

    /// A version identifier string for the client software identified by
    /// "software_id"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,

    /// OpenID4VCI
    /// Used by the Wallet to publish its Credential Offer Handler. The
    /// Credential Issuer should use `openid-credential-offer://` if unable
    /// to perform discovery of the endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_offer_endpoint: Option<String>,

    /// REQUIRED for OpenID4VP
    /// An object defining the formats and proof types of Verifiable Presentations
    /// and Verifiable Credentials that a Verifier supports. For specific values that
    /// can be used.
    ///
    /// # Example
    ///
    /// ```json
    /// "jwt_vc_json": {
    ///     "proof_type": [
    ///         "JsonWebSignature2020"
    ///     ]
    /// }
    /// ```
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_formats: Option<HashMap<String, VpFormat>>,
}

/// Used to define the format and proof types of Verifiable Presentations and
/// Verifiable Credentials that a Verifier supports.
/// Deployments can extend the formats supported, provided Issuers, Holders and
/// Verifiers all understand the new format.
/// See <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#alternative_credential_formats>
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct VpFormat {
    /// Algorithms supported by the format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<Vec<String>>,

    /// Proof types supported by the format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_type: Option<Vec<String>>,
}

impl Client {
    /// Create a new Client with the specified client ID.
    #[must_use]
    pub fn new(client_id: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            ..Default::default()
        }
    }
}

impl fmt::Display for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        let Ok(s) = serde_json::to_string(self) else {
            return Err(fmt::Error);
        };
        write!(f, "{s}")
    }
}

impl FromStr for Client {
    type Err = error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Ok(res) = serde_json::from_str(s) else {
            err!(Err::InvalidRequest, "Failed to parse Verifier");
        };
        Ok(res)
    }
}

/// The Credential Issuer's configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Issuer {
    /// The Credential Issuer's identifier.
    pub credential_issuer: String,

    /// Authorization Server's identifier (metadata `issuer` parameter). If
    /// omitted, the Credential Issuer is acting as the AS. That is, the
    /// `credential_issuer` value is also used as the Authorization Server
    /// `issuer` value in metadata requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_servers: Option<Vec<String>>,

    /// URL of the Credential Issuer's Credential Endpoint. MAY contain port,
    /// path and query parameter components.
    pub credential_endpoint: String,

    /// URL of the Credential Issuer's Batch Credential Endpoint. MAY contain
    /// port, path and query parameter components. When omitted, the
    /// Credential Issuer does not support the Batch Credential Handler.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_credential_endpoint: Option<String>,

    /// URL of the Credential Issuer's Deferred Credential Endpoint. This URL
    /// MUST use the https scheme and MAY contain port, path, and query parameter
    /// components. If omitted, the Credential Issuer does not support the
    /// Deferred Credential Endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred_credential_endpoint: Option<String>,

    /// A list of the JWE encryption algorithms (alg values)
    /// [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#section-4.1) supported by the
    /// Credential and Batch Credential Endpoint to encode the Response in a JWT
    /// [RFC7519](https://www.rfc-editor.org/rfc/rfc7519).
    ///
    /// For example, "ECDH-ES"
    pub credential_response_encryption_alg_values_supported: Option<Vec<String>>,

    /// A list of the JWE encryption algorithms (enc values)
    /// [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#section-5) supported by the
    /// Credential and Batch Credential Endpoints to encode the Response in a JWT
    /// [RFC7519](https://www.rfc-editor.org/rfc/rfc7519).
    ///
    /// For example, "A256GCM"
    pub credential_response_encryption_enc_values_supported: Option<Vec<String>>,

    /// Specifies whether the Credential Issuer requires additional encryption on
    /// top of TLS for the Credential Response and expects encryption parameters
    /// to be present in the Credential Request and/or Batch Credential Request,
    /// with true indicating support.
    ///
    /// When true, 'credential_response_encryption_alg_values_supported parameter'
    /// MUST also be provided. The default value is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_credential_response_encryption: Option<bool>,

    /// Specifies whether the Credential Issuer supports returning 'credential_identifiers'
    /// parameter in the authorization_details Token Response parameter, with true
    /// indicating support. The default value is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_identifiers_supported: Option<bool>,

    /// Credential Issuer display properties for supported languages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Display>,

    /// A list of name/value pairs of credentials supported by the Credential Issuer.
    /// Each name is a unique identifier for the supported credential described. The
    /// identifier is used in the Credential Offer to communicate to the Wallet which
    /// Credential is being offered. The value is a Credential object containing
    /// metadata about specific credential.
    pub credentials_supported: HashMap<String, SupportedCredential>,
}

impl Issuer {
    /// Create a new `Issuer` with the specified `credential_issuer` and
    /// `credential_endpoint`.
    #[must_use]
    pub fn sample() -> Self {
        const ISSUER_URI: &str = "http://credibil.io";

        Self {
            credential_issuer: ISSUER_URI.to_string(),
            authorization_servers: None,
            credential_endpoint: format!("{ISSUER_URI}/credential"),
            batch_credential_endpoint: Some(format!("{ISSUER_URI}/batch_credential")),
            deferred_credential_endpoint: Some(format!("{ISSUER_URI}/deferred_credential")),
            credential_response_encryption_alg_values_supported: Some(vec!["ECDH-ES".to_string()]),
            credential_response_encryption_enc_values_supported: Some(vec!["A256GCM".to_string()]),
            require_credential_response_encryption: Some(false),
            credential_identifiers_supported: Some(true),
            display: Some(Display {
                name: "Credibil".to_string(),
                locale: Some("en-NZ".to_string()),
            }),
            credentials_supported: HashMap::from([
                ("EmployeeID_JWT".to_string(), SupportedCredential::sample()),
                ("Developer_JWT".to_string(), SupportedCredential::sample2()),
            ]),
        }
    }
}

/// Language-based display properties for Issuer or Claim.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Display {
    /// The name to use when displaying the name of the `Issuer` or `Claim` for the
    /// specified locale. If no locale is set, then this value is the default value.
    pub name: String,

    /// A BCP47 [RFC5646](https://www.rfc-editor.org/rfc/rfc5646) language tag identifying the display language.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
}

/// Supported credential metadata.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct SupportedCredential {
    /// Identifies the format of the credential, e.g. jwt_vc_json or ldp_vc.
    /// Each object will contain further elements defining the type and
    /// claims the credential MAY contain, as well as information on how to
    /// display the credential.
    ///
    /// See Appendix E of the OpenID4VCI specification for Credential Format
    /// Profiles.
    pub format: String,

    /// Identifies the scope value that this Credential Issuer supports for this
    /// particular credential. The value can be the same accross multiple
    /// 'credentials_supported' objects. The Authorization Server MUST be able to
    /// uniquely identify the Credential Issuer based on the scope value. The Wallet
    /// can use this value in the Authorization Request Scope values in this
    /// Credential Issuer metadata MAY duplicate those in the scopes_supported
    /// parameter of the Authorization Server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    // /// Identifies this SupportedCredential object. MUST be unique across all
    // /// `credentials_supported` entries in the Credential Issuer's Metadata.
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub id: Option<String>,
    /// Identifies how the Credential should be bound to the identifier of the
    /// End-User who possesses the Credential. Is case sensitive.
    ///
    /// Support for keys in JWK format [RFC7517](https://www.rfc-editor.org/rfc/rfc7517) is indicated by the value jwk.
    /// Support for keys expressed as a COSE Key object [RFC8152](https://www.rfc-editor.org/rfc/rfc8152) (for example, used
    /// in [ISO.18013-5]) is indicated by the value 'cose_key'.
    ///
    /// When Cryptographic Binding Method is a DID, valid values MUST be a did: prefix
    /// followed by a method-name using a syntax as defined in Section 3.1 of [DID-Core],
    /// but without a :and method-specific-id. For example, support for the DID method
    /// with a method-name "example" would be represented by did:example. Support for
    /// all DID methods listed in Section 13 of [DID Specification Registries](https://www.w3.org/TR/did-spec-registries/)
    /// is indicated by sending a DID without any method-name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,

    /// Case sensitive strings that identify the cryptographic suites supported for
    /// the 'cryptographic_binding_methods_supported'. Cryptographic algorithms for
    /// Credentials in jwt_vc format should use algorithm names defined in IANA JOSE
    /// Algorithms Registry. Cryptographic algorithms for Credentials in ldp_vc format
    /// should use signature suites names defined in Linked Data Cryptographic Suite
    /// Registry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_suites_supported: Option<Vec<String>>,

    /// Case sensitive strings, representing proof_type that the Credential Issuer
    /// supports. Supported values include those defined in Credential Requests
    /// (jwt, cwt) or other values defined in a profile of the specification.
    /// The 'proof_type'mclaim is defined in the Credential Request specification.
    ///
    /// If omitted, the default value is jwt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_types_supported: Option<Vec<String>>,

    /// Language-based display properties of the supported credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<CredentialDisplay>>,

    /// Language-based display properties for the associated Credential Definition.
    pub credential_definition: CredentialDefinition,
}

impl SupportedCredential {
    /// Create a new `SupportedCredential` with the specified format.
    // #[cfg(feature = "typegen")]
    #[must_use]
    pub fn sample() -> Self {
        Self {
            format: "jwt_vc_json".to_string(),
            scope: Some("EmployeeIDCredential".to_string()),
            cryptographic_binding_methods_supported: Some(vec![
                "did:jwk".to_string(),
                "did:ion".to_string(),
            ]),
            cryptographic_suites_supported: Some(vec!["ES256K".to_string(), "EdDSA".to_string()]),
            proof_types_supported: Some(vec!["jwt".to_string()]),
            display: Some(vec![CredentialDisplay {
                name: "Employee ID".to_string(),
                description: Some("Credibil employee ID credential".to_string()),
                locale: Some("en-NZ".to_string()),
                logo: Some(Logo {
                    url: Some(
                        "https://credibil.github.io/assets/credibil-logo-reversed.png".to_string(),
                    ),
                    alt_text: Some("Credibil Logo".to_string()),
                }),
                text_color: Some("#ffffff".to_string()),
                background_color: Some("#323ed2".to_string()),
            }]),
            credential_definition: CredentialDefinition {
                context: Some(vec![
                    "https://www.w3.org/2018/credentials/v1".to_string(),
                    "https://www.w3.org/2018/credentials/examples/v1".to_string(),
                ]),
                type_: vec!["VerifiableCredential".to_string(), "EmployeeIDCredential".to_string()],
                credential_subject: Some(HashMap::from([
                    (
                        "email".to_string(),
                        Claim {
                            mandatory: Some(true),
                            value_type: Some("string".to_string()),
                            display: Some(vec![Display {
                                name: "Email".to_string(),
                                locale: Some("en-NZ".to_string()),
                            }]),
                            claim_nested: None,
                        },
                    ),
                    (
                        "familyName".to_string(),
                        Claim {
                            mandatory: Some(true),
                            value_type: Some("string".to_string()),
                            display: Some(vec![Display {
                                name: "Family name".to_string(),
                                locale: Some("en-NZ".to_string()),
                            }]),
                            claim_nested: None,
                        },
                    ),
                    (
                        "givenName".to_string(),
                        Claim {
                            mandatory: Some(true),
                            value_type: Some("string".to_string()),
                            display: Some(vec![Display {
                                name: "Given name".to_string(),
                                locale: Some("en-NZ".to_string()),
                            }]),
                            claim_nested: None,
                        },
                    ),
                ])),
            },
        }
    }

    /// Create a new `SupportedCredential` with the specified format.
    // TODO: Better demonstrate standards variation from that supplied by sample().
    #[must_use]
    pub fn sample2() -> Self {
        Self {
            format: "jwt_vc_json".to_string(),
            scope: Some("DeveloperCredential".to_string()),
            cryptographic_binding_methods_supported: Some(vec![
                "did:jwk".to_string(),
                "did:ion".to_string(),
            ]),
            cryptographic_suites_supported: Some(vec!["ES256K".to_string(), "EdDSA".to_string()]),
            proof_types_supported: Some(vec!["jwt".to_string()]),
            display: Some(vec![CredentialDisplay {
                name: "Developer".to_string(),
                description: Some("Propellerhead certified developer credential".to_string()),
                locale: Some("en-NZ".to_string()),
                logo: Some(Logo {
                    url: Some(
                        "https://credibil.github.io/assets/propellerhead-logo-reversed.png"
                            .to_string(),
                    ),
                    alt_text: Some("Propellerhead Logo".to_string()),
                }),
                text_color: Some("#ffffff".to_string()),
                background_color: Some("#010100".to_string()),
            }]),
            credential_definition: CredentialDefinition {
                context: Some(vec![
                    "https://www.w3.org/2018/credentials/v1".to_string(),
                    "https://www.w3.org/2018/credentials/examples/v1".to_string(),
                ]),
                type_: vec!["VerifiableCredential".to_string(), "DeveloperCredential".to_string()],
                credential_subject: Some(HashMap::from([
                    (
                        "proficiency".to_string(),
                        Claim {
                            mandatory: Some(true),
                            value_type: Some("number".to_string()),
                            display: Some(vec![Display {
                                name: "Proficiency".to_string(),
                                locale: Some("en-NZ".to_string()),
                            }]),
                            claim_nested: None,
                        },
                    ),
                    (
                        "familyName".to_string(),
                        Claim {
                            mandatory: Some(true),
                            value_type: Some("string".to_string()),
                            display: Some(vec![Display {
                                name: "Family name".to_string(),
                                locale: Some("en-NZ".to_string()),
                            }]),
                            claim_nested: None,
                        },
                    ),
                    (
                        "givenName".to_string(),
                        Claim {
                            mandatory: Some(true),
                            value_type: Some("string".to_string()),
                            display: Some(vec![Display {
                                name: "Given name".to_string(),
                                locale: Some("en-NZ".to_string()),
                            }]),
                            claim_nested: None,
                        },
                    ),
                ])),
            },
        }
    }
}

/// `CredentialDisplay` holds language-based display properties of the supported
/// credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialDisplay {
    /// The value to use when displaying the name of the `Credential` for the
    /// specified locale. If no locale is set, then this is the default value.
    pub name: String,

    /// A BCP47 [RFC5646](https://www.rfc-editor.org/rfc/rfc5646) language tag identifying the display language.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    /// Information about the logo of the Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<Logo>,

    /// Description of the Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Background color of the Credential using CSS Color Module Level 37
    /// values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,

    /// Text color color of the Credential using CSS Color Module Level 37
    /// values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
}

/// Logo contains information about the logo of the Credential.
/// N.B. The list is non-exhaustive and may be extended in the future.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Logo {
    /// URL where the Wallet can obtain a logo of the Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Alternative text of a logo image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
}

/// `CredentialDefinition` defines a Supported Credential that may requested by
/// Wallets.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialDefinition {
    /// The @context property is used to map property URIs into short-form aliases,
    /// in accordance with the W3C Verifiable Credentials Data Model.
    ///
    /// REQUIRED when 'format' is "jwt_vc_json-ld" or "ldp_vc".
    #[cfg_attr(not(feature = "typegen"), serde(rename = "@context"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<String>>,

    /// Uniquely identifies the credential type the Credential Definition display
    /// properties are for, in accordance with the W3C Verifiable Credentials Data
    /// Model.
    #[serde(rename = "type")]
    pub type_: Vec<String>,

    /// A list of name/value pairs identifying claims offered in the Credential.
    /// A value can be another such object (nested data structures), or an array of
    /// objects.
    /// Each claim defines language-based display properties for credentialSubject
    /// fields.
    #[serde(rename = "credentialSubject")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_subject: Option<HashMap<String, Claim>>,
}

/// Claim is used to hold language-based display properties for a
/// credentialSubject field.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Claim {
    /// When set to true indicates the claim MUST be present in the issued
    /// Credential. Defaults to false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandatory: Option<bool>,

    /// The type of value of the claim. Defaults to string.
    /// Supported values include `string`, `number`, and `image` media types
    /// such as image/jpeg. See IANA media type registry for a complete
    /// list. (<https://www.iana.org/assignments/media-types/media-types.xhtml#image>).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,

    /// Language-based display properties of the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<Display>>,

    /// A list nested claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_nested: Option<HashMap<String, Box<Claim>>>,
}

/// OAuth 2.0 Authorization Server metadata.
/// See RFC 8414 - Authorization Server Metadata
#[derive(Default, Debug, Clone, Deserialize, Serialize)]
pub struct Server {
    /// The authorization server's issuer identifier (URL). MUST be identical to
    /// the issuer identifier value in the well-known URI:
    /// `{issuer}/.well-known/oauth-authorization-server``.
    pub issuer: String,

    /// URL of the authorization server's authorization endpoint.
    pub authorization_endpoint: String,

    /// URL of the authorization server's token endpoint.
    pub token_endpoint: String,

    /// URL of the authorization server's JWK Set document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// URL of the authorization server's Dynamic Client Registration endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,

    /// List of scope values the authorization server supports. RECOMMENDED.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,

    /// List of `response_type` values the authorization server supports.
    pub response_types_supported: Vec<String>,

    /// A list of `response_mode` values the authorization server supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_modes_supported: Option<Vec<String>>,

    /// A list of grant types supported. Values are the same as the Dynamic
    /// Client Registration "grant_types"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,

    /// A list of client authentication methods supported by the token endpoint.
    /// The same as those used with the "grant_types" parameter defined by the
    /// OAuth 2.0 Dynamic Client Registration Protocol specification.
    /// Values can be one of: "none", "client_secret_post",
    /// "client_secret_basic"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// A list of the JWS algorithms supported by the token endpoint for the
    /// signature on the JWT used to authenticate the client at the endpoint
    /// for the "private_key_jwt" and "client_secret_jwt" authentication
    /// methods.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// URL to information developers might need when using the authorization
    /// server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<String>,

    /// Languages supported for the user interface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_locales_supported: Option<Vec<String>>,

    /// URL provided to the person registering a client regarding how the
    /// authorization server's data may be used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_policy_uri: Option<String>,

    /// URL provided to the person registering the client to read about the
    /// authorization server's terms of service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_tos_uri: Option<String>,

    /// URL of the authorization server's revocation endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,

    /// A list of client authentication methods supported by this revocation
    /// endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// A list of the JWS algorithms supported by the revocation endpoint for
    /// the signature on the JWT used to authenticate the client at the
    /// endpoint for the "private_key_jwt" and "client_secret_jwt"
    /// authentication methods.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// URL of the authorization server's introspection endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,

    /// A list of client authentication methods supported by this introspection
    /// endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// A list of the JWS algorithms supported by the introspection endpoint for
    /// the signature on the JWT used to authenticate the client at the
    /// endpoint for the "private_key_jwt" and "client_secret_jwt"
    /// authentication methods.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// Proof Key for Code Exchange (PKCE) code challenge methods supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,

    /// Metadata values MAY also be provided as a "signed_metadata" value, which
    /// is a JSON Web Token (JWT) that asserts metadata values about the
    /// authorization server as a bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_metadata: Option<String>,

    /// OpenID4VCI
    /// Indicates whether the issuer accepts a Token Request with a
    /// Pre-Authorized Code but without a client id. Defaults to false.
    #[serde(rename = "pre-authorized_grant_anonymous_access_supported")]
    pub pre_authorized_grant_anonymous_access_supported: bool,

    /// OpenID.Wallet
    /// Specifies whether the Wallet supports the transfer of
    /// presentation_definition by reference, with true indicating support.
    /// If omitted, the default value is true.
    pub presentation_definition_uri_supported: bool,

    /// OpenID.Wallet
    /// A list of key value pairs, where the key identifies a Credential format
    /// supported by the Wallet.
    pub vp_formats_supported: Option<HashMap<String, SupportedVpFormat>>,
}

impl Server {
    /// Create a new `Issuer` with the specified `credential_issuer` and
    /// `credential_endpoint`.
    #[must_use]
    pub fn sample() -> Self {
        Self {
            issuer: "http://credibil.io".to_string(),
            authorization_endpoint: "/auth".to_string(),
            token_endpoint: "/token".to_string(),
            scopes_supported: Some(vec!["openid".to_string()]),
            response_types_supported: vec!["code".to_string()],
            response_modes_supported: Some(vec!["query".to_string()]),
            grant_types_supported: Some(vec![
                AUTH_CODE_GRANT_TYPE.to_string(),
                PRE_AUTH_GRANT_TYPE.to_string(),
            ]),
            code_challenge_methods_supported: Some(vec!["S256".to_string()]),
            pre_authorized_grant_anonymous_access_supported: true,
            presentation_definition_uri_supported: false,
            jwks_uri: None,
            registration_endpoint: None,
            token_endpoint_auth_methods_supported: None,
            token_endpoint_auth_signing_alg_values_supported: None,
            service_documentation: None,
            ui_locales_supported: None,
            op_policy_uri: None,
            op_tos_uri: None,
            revocation_endpoint: None,
            revocation_endpoint_auth_methods_supported: None,
            revocation_endpoint_auth_signing_alg_values_supported: None,
            introspection_endpoint: None,
            introspection_endpoint_auth_methods_supported: None,
            introspection_endpoint_auth_signing_alg_values_supported: None,
            signed_metadata: None,
            vp_formats_supported: None,
            // vp_formats_supported: Some(HashMap::from([
            //     (
            //         "jwt_vc_json".to_string(),
            //         SupportedVpFormat {
            //             alg_values_supported: Some(vec!["ES256K".to_string(), "EdDSA".to_string()]),
            //         },
            //     ),
            //     (
            //         "jwt_vp_json".to_string(),
            //         SupportedVpFormat {
            //             alg_values_supported: Some(vec!["ES256K".to_string(), "EdDSA".to_string()]),
            //         },
            //     ),
            // ])),
        }
    }
}

/// Credential format supported by the Wallet.
/// Valid Credential format identifier values are defined in Annex E of
/// [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SupportedVpFormat {
    /// An object where the value is an array of case sensitive strings that
    /// identify the cryptographic suites that are supported. Parties will
    /// need to agree upon the meanings of the values used, which may be
    /// context-specific.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg_values_supported: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "typegen")]
    use super::SupportedCredential;

    #[cfg(feature = "typegen")]
    #[test]
    fn generate() {
        let mut gen = crux_core::typegen::TypeGen::new();
        gen.register_samples::<SupportedCredential>(vec![SupportedCredential::sample()])
            .expect("should register type");
        // gen.swift("SharedTypes", "swift").expect("should generate swift types");
    }
}
