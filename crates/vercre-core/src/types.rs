//! # `OpenID4VC` Types
//!
//! Types used in the `OpenID4VC` specifications.

pub mod issuance;
pub mod presentation;

use std::collections::HashMap;
use std::fmt::{self, Display};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use self::issuance::{Format, GrantType};
use self::presentation::VpFormat;
use crate::{err, error};

/// OAuth 2 client metadata used for registering clients of the issuance and
/// vercre-wallet authorization servers.
///
/// In the case of Issuance, the Wallet is the Client and the Issuer is the
/// Authorization Server.
///
/// In the case of Presentation, the Wallet is the Authorization Server and the
/// Verifier is the Client.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Client {
    /// ID of the registered client.
    pub client_id: String,

    /// Time at which the client identifier was issued, as Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_issued_at: Option<i64>,

    /// OAuth 2.0 client secret string. If issued, this MUST be unique for each
    /// `client_id` and SHOULD be unique for multiple instances of a client
    /// using the same `client_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,

    /// Required if `client_secret` is issued. Time at which the client secret
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
    /// - "`none`": The client is public and does not have a secret
    /// - ~~"`client_secret_post`": The client uses RFC6749 HTTP POST parameters.~~
    /// - ~~"`client_secret_basic`": The client uses HTTP Basic.~~
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,

    /// OAuth 2.0 grant types the client can use at the token endpoint.
    /// Supported grant types are:
    /// - "`authorization_code`" = RFC6749 Authorization Code Grant
    /// - "`urn:ietf:params:oauth:grant-type:pre-authorized_code`" =
    ///   Pre-Authorized Code Grant
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<GrantType>>,

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

    /// URL referencing the client's JSON Web Key (JWK) Set [RFC7517] document,
    /// containing the client's public keys. MUST NOT both be set if the`jwks`
    /// parameter is set.
    ///
    /// [RFC7517]: (https://www.rfc-editor.org/rfc/rfc7517)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// Client's JSON Web Key Set [RFC7517], containing the client's public keys.
    /// MUST be a JSON object containing a valid JWK Set. MUST NOT be set if the
    /// `jwks_uri` parameter is set.
    ///
    /// [RFC7517]: (https://www.rfc-editor.org/rfc/rfc7517)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,

    /// A unique identifier string (e.g., a Universally Unique Identifier
    /// (UUID)) assigned by the client developer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_id: Option<String>,

    /// A version identifier string for the client software identified by `software_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,

    /// **`OpenID4VCI`**
    /// Used by the Wallet to publish its Credential Offer endpoint. The Credential
    /// Issuer should use "`openid-credential-offer://`" if unable to perform discovery
    /// of the endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_offer_endpoint: Option<String>,

    /// **`OpenID4VP`**
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
    pub vp_formats: Option<HashMap<Format, VpFormat>>,
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

impl Display for Client {
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
            err!(error::Err::InvalidRequest, "failed to parse Verifier");
        };
        Ok(res)
    }
}

/// OAuth 2.0 Authorization Server metadata.
/// See RFC 8414 - Authorization Server Metadata
#[derive(Default, Debug, Clone, Deserialize, Serialize)]
pub struct Server {
    /// The authorization server's issuer identifier (URL). MUST be identical to
    /// the issuer identifier value in the well-known URI:
    /// `{issuer}/.well-known/oauth-authorization-server`.
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
    /// Client Registration `grant_types`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<GrantType>>,

    /// A list of client authentication methods supported by the token endpoint.
    /// The same as those used with the `grant_types` parameter defined by the
    /// OAuth 2.0 Dynamic Client Registration Protocol specification.
    /// Values can be one of: "`none`", "`client_secret_post`",
    /// "`client_secret_basic`".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// A list of the JWS algorithms supported by the token endpoint for the
    /// signature on the JWT used to authenticate the client at the endpoint
    /// for the `private_key_jwt` and `client_secret_jwt` authentication
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
    /// endpoint for the `private_key_jwt` and `client_secret_jwt`
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
    /// endpoint for the `private_key_jwt` and `client_secret_jwt`
    /// authentication methods.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// Proof Key for Code Exchange (PKCE) code challenge methods supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,

    /// Metadata values MAY also be provided as a `signed_metadata` value, which
    /// is a JSON Web Token (JWT) that asserts metadata values about the
    /// authorization server as a bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_metadata: Option<String>,

    /// **`OpenID4VCI`**
    /// Indicates whether the issuer accepts a Token Request with a
    /// Pre-Authorized Code but without a client id. Defaults to false.
    #[serde(rename = "pre-authorized_grant_anonymous_access_supported")]
    pub pre_authorized_grant_anonymous_access_supported: bool,

    /// **`OpenID4VP`**
    /// Specifies whether the Wallet supports the transfer of
    /// `presentation_definition` by reference, with true indicating support.
    /// If omitted, the default value is true.
    pub presentation_definition_uri_supported: bool,

    /// **`OpenID4VP`**
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
            issuer: "http://vercre.io".into(),
            authorization_endpoint: "/auth".into(),
            token_endpoint: "/token".into(),
            scopes_supported: Some(vec!["openid".into()]),
            response_types_supported: vec!["code".into()],
            response_modes_supported: Some(vec!["query".into()]),
            grant_types_supported: Some(vec![
                GrantType::AuthorizationCode,
                GrantType::PreAuthorizedCode,
            ]),
            code_challenge_methods_supported: Some(vec!["S256".into()]),
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
            //         "jwt_vc_json".into(),
            //         SupportedVpFormat {
            //             alg_values_supported: Some(vec!["ES256K".into(), "EdDSA".into()]),
            //         },
            //     ),
            //     (
            //         "jwt_vp_json".into(),
            //         SupportedVpFormat {
            //             alg_values_supported: Some(vec!["ES256K"into(), "EdDSA".into()]),
            //         },
            //     ),
            // ])),
        }
    }
}

/// Credential format supported by the Wallet.
/// Valid Credential format identifier values are defined in Annex E of [OpenID4VCI].
///
/// [OpenID4VCI]: (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SupportedVpFormat {
    /// An object where the value is an array of case sensitive strings that
    /// identify the cryptographic suites that are supported. Parties will
    /// need to agree upon the meanings of the values used, which may be
    /// context-specific.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg_values_supported: Option<Vec<String>>,
}
