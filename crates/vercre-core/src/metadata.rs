//! # Metadata
//!
//! Types and traits for working with `OpenID` Connect client and server metadata.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::Err;
use crate::vci::{Format, GrantType};
use crate::{err, error, Result};
use crate::provider;

/// The `ClientMetadata` trait is used by implementers to provide `Client` metadata to the
/// library.
pub trait ClientMetadata: Send + Sync {
    /// Returns client metadata for the specified client.
    fn metadata(&self, client_id: &str) -> impl Future<Output = provider::Result<Client>> + Send;

    /// Used by OAuth 2.0 clients to dynamically register with the authorization
    /// server.
    fn register(&self, client_meta: &Client) -> impl Future<Output = provider::Result<Client>> + Send;
}

/// The `IssuerMetadata` trait is used by implementers to provide Credential Issuer metadata.
pub trait IssuerMetadata: Send + Sync {
    /// Returns the Credential Issuer's metadata.
    fn metadata(&self, issuer_id: &str) -> impl Future<Output = provider::Result<Issuer>> + Send;
}

/// The `ServerMetadata` trait is used by implementers to provide Authorization Server metadata.
pub trait ServerMetadata: Send + Sync {
    /// Returns the Authorization Server's metadata.
    fn metadata(&self, server_id: &str) -> impl Future<Output = provider::Result<Server>> + Send;
}

// /// OAuth 2.0 Authorization Code grant type.
// pub const AUTH_CODE_GRANT_TYPE: &str = "authorization_code";

// /// `OpenID4VCI` Pre-Authorized Code grant type.
// pub const PRE_AUTH_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

/// OAuth 2 client metadata used for registering clients of the issuance and
/// vercre-wallet authorization servers.
///
/// In the case of Credential issuance, the Wallet is the Client and the Issuer
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
            err!(Err::InvalidRequest, "failed to parse Verifier");
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

    /// Specifies whether (and how)the Credential Issuer supports encryption of the
    /// Credential and Batch Credential Response on top of TLS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialResponseEncryption>,

    /// Specifies whether the Credential Issuer supports returning `credential_identifiers`
    /// parameter in the `authorization_details` Token Response parameter, with true
    /// indicating support. The default value is "false".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_identifiers_supported: Option<bool>,

    /// A signed JWT containing Credential Issuer metadata parameters as claims. The
    /// signed metadata MUST be secured using JSON Web Signature (JWS) [RFC7515] and
    /// MUST contain an iat (Issued At) claim, an iss (Issuer) claim denoting the party
    /// attesting to the claims in the signed metadata, and sub (Subject) claim matching
    /// the Credential Issuer identifier. If the Wallet supports signed metadata,
    /// metadata values conveyed in the signed JWT MUST take precedence over the
    /// corresponding values conveyed using plain JSON elements. If the Credential Issuer
    /// wants to enforce use of signed metadata, it omits the respective metadata
    /// parameters from the unsigned part of the Credential Issuer metadata. A signed_
    /// metadata metadata value MUST NOT appear as a claim in the JWT. The Wallet MUST
    /// establish trust in the signer of the metadata, and obtain the keys to validate
    /// the signature before processing the metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_metadata: Option<String>,

    /// Credential Issuer display properties for supported languages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Display>,

    /// A list of name/value pairs of credentials supported by the Credential Issuer.
    /// Each name is a unique identifier for the supported credential described. The
    /// identifier is used in the Credential Offer to communicate to the Wallet which
    /// Credential is being offered. The value is a Credential object containing
    /// metadata about specific credential.
    pub credential_configurations_supported: HashMap<String, CredentialConfiguration>,
}

/// `CredentialResponseEncryption` contains information about whether the Credential
/// Issuer supports encryption of the Credential and Batch Credential Response on
/// top of TLS.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialResponseEncryption {
    /// JWE [RFC7516] alg algorithm [RFC7518] REQUIRED for encrypting Credential
    /// Responses.
    ///
    /// [RFC7516]: (https://www.rfc-editor.org/rfc/rfc7516)
    /// [RFC7518]: (https://www.rfc-editor.org/rfc/rfc7518)
    pub alg_values_supported: Vec<String>,

    /// JWE [RFC7516] enc algorithm [RFC7518] REQUIRED for encrypting Credential
    /// Responses. If `credential_response_encryption_alg` is specified, the default
    /// for this value is "`A256GCM`".
    ///
    /// [RFC7516]: (https://www.rfc-editor.org/rfc/rfc7516)
    /// [RFC7518]: (https://www.rfc-editor.org/rfc/rfc7518)
    pub enc_values_supported: Vec<String>,

    /// Specifies whether the Credential Issuer requires the additional encryption
    /// on top of TLS for the Credential Response. If the value is true, the Credential
    /// Issuer requires encryption for every Credential Response and therefore the
    /// Wallet MUST provide encryption keys in the Credential Request. If the value is
    /// false, the Wallet MAY chose whether it provides encryption keys or not.
    pub encryption_required: bool,
}

/// Language-based display properties for Issuer or Claim.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Display {
    /// The name to use when displaying the name of the `Issuer` or `Claim` for the
    /// specified locale. If no locale is set, then this value is the default value.
    pub name: String,

    /// A BCP47 [RFC5646] language tag identifying the display language.
    ///
    /// [RFC5646]: (https://www.rfc-editor.org/rfc/rfc5646)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
}

/// Credential configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct CredentialConfiguration {
    /// Identifies the format of the credential, e.g. "`jwt_vc_json`" or "`ldp_vc`".
    /// Each object will contain further elements defining the type and
    /// claims the credential MAY contain, as well as information on how to
    /// display the credential.
    ///
    /// See [Credential Format Profiles] in the `OpenID4VCI` specification.
    ///
    /// [Appendix A]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-format-profiles
    pub format: Format,

    /// Identifies the scope value that this Credential Issuer supports for this
    /// particular credential. The value can be the same accross multiple
    /// `credential_configurations_supported` objects. The Authorization Server MUST be able to
    /// uniquely identify the Credential Issuer based on the scope value. The Wallet
    /// can use this value in the Authorization Request Scope values in this
    /// Credential Issuer metadata MAY duplicate those in the `scopes_supported`
    /// parameter of the Authorization Server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    // /// Identifies this CredentialConfiguration object. MUST be unique across all
    // /// `credential_configurations_supported` entries in the Credential Issuer's Metadata.
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub id: Option<String>,
    /// Identifies how the Credential should be bound to the identifier of the
    /// End-User who possesses the Credential. Is case sensitive.
    ///
    /// Support for keys in JWK format [RFC7517] is indicated by the value "`jwk`".
    /// Support for keys expressed as a COSE Key object [RFC8152] (for example, used in
    /// [ISO.18013-5]) is indicated by the value "`cose_key`".
    ///
    /// When Cryptographic Binding Method is a DID, valid values MUST be a "did:" prefix
    /// followed by a method-name using a syntax as defined in Section 3.1 of
    /// [DID-Core], but without a ":" and method-specific-id. For example, support for
    /// the DID method with a method-name "example" would be represented by
    /// "did:example". Support for all DID methods listed in Section 13 of
    /// [DID Specification Registries] is indicated by sending a DID without any
    /// method-name.
    ///
    /// [RFC7517]: (https://www.rfc-editor.org/rfc/rfc7517)
    /// [RFC8152]: (https://www.rfc-editor.org/rfc/rfc8152)
    /// [ISO.18013-5]: (https://www.iso.org/standard/69084.html)
    /// [DID-Core]: (https://www.w3.org/TR/did-core/)
    /// [DID Specification Registries]: (https://www.w3.org/TR/did-spec-registries/)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,

    /// Case sensitive strings that identify the cryptographic suites supported for
    /// the `cryptographic_binding_methods_supported`. Cryptographic algorithms for
    /// Credentials in `jwt_vc` format should use algorithm names defined in IANA JOSE
    /// Algorithms Registry. Cryptographic algorithms for Credentials in `ldp_vc` format
    /// should use signature suites names defined in Linked Data Cryptographic Suite
    /// Registry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_signing_alg_values_supported: Option<Vec<String>>,

    /// The key proof(s) that the Credential Issuer supports. This object contains
    /// a list of name/value pairs, where each name is a unique identifier of the
    /// supported proof type(s). Valid values are defined in Section 7.2.1,
    /// other values MAY be used. This identifier is also used by the Wallet in the
    /// Credential Request as defined in Section 7.2. The value in the name/value
    /// pair is an object that contains metadata about the key proof and contains
    /// the following parameters defined by this specification:
    ///
    ///  - `jwt`: A JWT [RFC7519] is used as proof of possession. A proof object MUST
    ///    include a jwt claim containing a JWT defined in Section 7.2.1.1.
    ///
    ///  - `cwt`: A CWT [RFC8392] is used as proof of possession. A proof object MUST
    ///    include a cwt claim containing a CWT defined in Section 7.2.1.3.
    ///
    ///  - `ldp_vp`: A W3C Verifiable Presentation object signed using the Data Integrity
    ///    Proof as defined in [VC_DATA_2.0] or [VC_DATA], and where the proof of
    ///    possession MUST be done in accordance with [VC_Data_Integrity]. When
    ///    `proof_type` is set to `ldp_vp`, the proof object MUST include a `ldp_vp`
    ///    claim containing a W3C Verifiable Presentation defined in Section 7.2.1.2.
    ///
    /// # Example
    ///
    /// ```json
    /// "proof_types_supported": {
    ///     "jwt": {
    ///         "proof_signing_alg_values_supported": [
    ///             "ES256"
    ///         ]
    ///     }
    /// }
    /// ```
    ///
    /// [RFC7519]: (https://www.rfc-editor.org/rfc/rfc7519)
    /// [RFC8392]: (https://www.rfc-editor.org/rfc/rfc8392)
    /// [VC_DATA]: (https://www.w3.org/TR/vc-data-model/)
    /// [VC_DATA_2.0]: (https://www.w3.org/TR/vc-data-model-2.0/)
    /// [VC_Data_Integrity]: (https://www.w3.org/TR/vc-data-integrity/)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_types_supported: Option<HashMap<String, ProofTypesSupported>>,

    /// Language-based display properties of the supported credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<CredentialDisplay>>,

    /// Language-based display properties for the associated Credential Definition.
    pub credential_definition: CredentialDefinition,
}

/// `ProofTypesSupported` describes specifics of the key proof(s) that the Credential
/// Issuer supports. This object contains a list of name/value pairs, where each name
/// is a unique identifier of the supported proof type(s). Valid values are defined in
/// Section 7.2.1, other values MAY be used. This identifier is also used by the Wallet
/// in the Credential Request as defined in Section 7.2. The value in the name/value
/// pair is an object that contains metadata about the key proof.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProofTypesSupported {
    /// One or more case sensitive strings that identify the algorithms that the Issuer
    /// supports for this proof type. The Wallet uses one of them to sign the proof.
    /// Algorithm names used are determined by the key proof type.
    ///
    /// For example, for JWT, the algorithm names are defined in IANA JOSE Algorithms
    /// Registry.
    ///
    /// # Example
    ///
    /// ```json
    /// "proof_signing_alg_values_supported": ["ES256K", "EdDSA"]
    /// ```
    pub proof_signing_alg_values_supported: Vec<String>,
}

/// `CredentialDisplay` holds language-based display properties of the supported
/// credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialDisplay {
    /// The value to use when displaying the name of the `Credential` for the
    /// specified locale. If no locale is set, then this is the default value.
    pub name: String,

    /// A BCP47 [RFC5646] language tag identifying the display language.
    ///
    /// [RFC5646]: (https://www.rfc-editor.org/rfc/rfc5646)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    /// Information about the logo of the Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<Image>,

    /// Description of the Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Background color of the Credential using CSS Color Module Level 37
    /// values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,

    /// Information about the background image of the Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_image: Option<Image>,

    /// Text color color of the Credential using CSS Color Module Level 37
    /// values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
}

/// Image contains information about the logo of the Credential.
/// N.B. The list is non-exhaustive and may be extended in the future.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Image {
    /// URL where the Wallet can obtain a logo of the Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,

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
    /// REQUIRED when `format` is "`jwt_vc_json-ld`" or "`ldp_vc`".
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<String>>,

    /// Uniquely identifies the credential type the Credential Definition display
    /// properties are for, in accordance with the W3C Verifiable Credentials Data
    /// Model.
    /// Contains the type values the Wallet requests authorization for at the
    /// Credential Issuer. It MUST be present if the claim format is present in the
    /// root of the authorization details object. It MUST not be present otherwise.
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<Vec<String>>,

    /// A list of name/value pairs identifying claims offered in the Credential.
    /// A value can be another such object (nested data structures), or an array of
    /// objects. Each claim defines language-based display properties for
    /// `credentialSubject` fields.
    ///
    /// N.B. This property is used by the Wallet to specify which claims it is
    /// requesting to be issued out of all the claims the Credential Issuer is capable
    /// of issuing for this particular Credential (data minimization).
    #[serde(rename = "credentialSubject")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_subject: Option<HashMap<String, Claim>>,
}

/// Claim is used to hold language-based display properties for a
/// credentialSubject field.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Claim {
    /// When true, indicates that the Credential Issuer will always include this claim
    /// in the issued Credential. When false, the claim is not included in the issued
    /// Credential if the wallet did not request the inclusion of the claim, and/or if
    /// the Credential Issuer chose to not include the claim. If the mandatory parameter
    /// is omitted, the default value is false. Defaults to false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandatory: Option<bool>,

    /// The type of value of the claim. Defaults to string. Supported values include
    /// `string`, `number`, and `image` media types such as image/jpeg. See
    /// [IANA media type registry] for a complete list of media types.
    ///
    /// [IANA media type registry]: (https://www.iana.org/assignments/media-types/media-types.xhtml#image)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_type: Option<ValueType>,

    /// Language-based display properties of the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<Display>>,

    /// A list nested claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_nested: Option<HashMap<String, Box<Claim>>>,
}

/// `ValueType` is used to define a claim's value type.
#[derive(Default, Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    /// Value of type String. The default.
    #[default]
    String,

    /// Value of type Number.
    Number,

    /// Image media types such as `image/jpeg`. See [IANA media type registry]
    /// for a complete list of media types.
    ///
    ///[IANA media type registry]: (https://www.iana.org/assignments/media-types/media-types.xhtml#image)
    Image,
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

    /// **`OpenID.Wallet`**
    /// Specifies whether the Wallet supports the transfer of
    /// `presentation_definition` by reference, with true indicating support.
    /// If omitted, the default value is true.
    pub presentation_definition_uri_supported: bool,

    /// **`OpenID.Wallet`**
    /// A list of key value pairs, where the key identifies a Credential format
    /// supported by the Wallet.
    pub vp_formats_supported: Option<HashMap<String, SupportedVpFormat>>,
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

impl Issuer {
    /// Create a new `Issuer` with the specified `credential_issuer` and
    /// `credential_endpoint`.
    ///
    /// # Panics
    ///
    /// Panics if the JSON does not serialize to an `Issuer` object
    #[must_use]
    pub fn sample() -> Self {
        const ISSUER_URI: &str = "http://vercre.io";

        let issuer = serde_json::json!({
            "credential_issuer": ISSUER_URI,
            "credential_endpoint": format!("{ISSUER_URI}/credential"),
            "batch_credential_endpoint": format!("{ISSUER_URI}/batch"),
            "deferred_credential_endpoint": format!("{ISSUER_URI}/deferred"),
            "display": {
                "name": "Vercre",
                "locale": "en-NZ"
            },
            "credential_configurations_supported": {
                "EmployeeID_JWT": CredentialConfiguration::sample(),
                "Developer_JWT": CredentialConfiguration::sample2(),
            },
        });

        serde_json::from_value(issuer).expect("should serialize to Issuer")
    }
}

impl CredentialConfiguration {
    /// Create a new `CredentialConfiguration` with the specified format.
    ///
    /// # Panics
    ///
    /// Panics if the JSON does not serialize to an `CredentialConfiguration` object
    #[must_use]
    pub fn sample() -> Self {
        Self {
            format: Format::JwtVcJson,
            scope: Some("EmployeeIDCredential".into()),
            cryptographic_binding_methods_supported: Some(vec!["did:jwk".into(), "did:ion".into()]),
            credential_signing_alg_values_supported: Some(vec!["ES256K".into(), "EdDSA".into()]),
            proof_types_supported: Some(HashMap::from([(
                "jwt".into(),
                ProofTypesSupported {
                    proof_signing_alg_values_supported: vec!["ES256K".into(), "EdDSA".into()],
                },
            )])),
            display: Some(vec![CredentialDisplay {
                name: "Employee ID".into(),
                description: Some("Vercre employee ID credential".into()),
                locale: Some("en-NZ".into()),
                logo: Some(Image {
                    uri: Some("https://vercre.github.io/assets/employee.png".into()),
                    alt_text: Some("Vercre Logo".into()),
                }),
                text_color: Some("#ffffff".into()),
                background_color: Some("#323ed2".into()),
                background_image: Some(Image {
                    uri: Some("https://vercre.github.io/assets/vercre-background.png".into()),
                    alt_text: Some("Vercre Background".into()),
                }),
            }]),
            credential_definition: CredentialDefinition {
                context: Some(vec![
                    "https://www.w3.org/2018/credentials/v1".into(),
                    "https://www.w3.org/2018/credentials/examples/v1".into(),
                ]),
                type_: Some(vec!["VerifiableCredential".into(), "EmployeeIDCredential".into()]),
                credential_subject: Some(HashMap::from([
                    (
                        "email".into(),
                        Claim {
                            mandatory: Some(true),
                            value_type: Some(ValueType::String),
                            display: Some(vec![Display {
                                name: "Email".into(),
                                locale: Some("en-NZ".into()),
                            }]),
                            claim_nested: None,
                        },
                    ),
                    (
                        "familyName".into(),
                        Claim {
                            mandatory: Some(true),
                            value_type: Some(ValueType::String),
                            display: Some(vec![Display {
                                name: "Family name".into(),
                                locale: Some("en-NZ".into()),
                            }]),
                            claim_nested: None,
                        },
                    ),
                    (
                        "givenName".into(),
                        Claim {
                            mandatory: Some(true),
                            value_type: Some(ValueType::String),
                            display: Some(vec![Display {
                                name: "Given name".into(),
                                locale: Some("en-NZ".into()),
                            }]),
                            claim_nested: None,
                        },
                    ),
                ])),
            },
        }
    }

    // TODO: Better demonstrate standards variation from that supplied by sample().

    /// Create a new `CredentialConfiguration` with the specified format.
    ///
    /// # Panics
    ///
    /// Panics if the JSON does not serialize to an `CredentialConfiguration` object.
    #[must_use]
    pub fn sample2() -> Self {
        Self {
            format: Format::JwtVcJson,
            scope: Some("DeveloperCredential".into()),
            cryptographic_binding_methods_supported: Some(vec!["did:jwk".into(), "did:ion".into()]),
            credential_signing_alg_values_supported: Some(vec!["ES256K".into(), "EdDSA".into()]),
            proof_types_supported: Some(HashMap::from([(
                "jwt".into(),
                ProofTypesSupported {
                    proof_signing_alg_values_supported: vec!["ES256K".into(), "EdDSA".into()],
                },
            )])),
            display: Some(vec![CredentialDisplay {
                name: "Developer".into(),
                description: Some("Vercre certified developer credential".into()),
                locale: Some("en-NZ".into()),
                logo: Some(Image {
                    uri: Some("https://vercre.github.io/assets/developer.png".into()),
                    alt_text: Some("Vercre Logo".into()),
                }),
                text_color: Some("#ffffff".into()),
                background_color: Some("#010100".into()),
                background_image: Some(Image {
                    uri: Some("https://vercre.github.io/assets/vercre-background.png".into()),
                    alt_text: Some("Vercre Background".into()),
                }),
            }]),
            credential_definition: CredentialDefinition {
                context: Some(vec![
                    "https://www.w3.org/2018/credentials/v1".into(),
                    "https://www.w3.org/2018/credentials/examples/v1".into(),
                ]),
                type_: Some(vec!["VerifiableCredential".into(), "DeveloperCredential".into()]),
                credential_subject: Some(HashMap::from([
                    (
                        "proficiency".into(),
                        Claim {
                            mandatory: Some(true),
                            value_type: Some(ValueType::Number),
                            display: Some(vec![Display {
                                name: "Proficiency".into(),
                                locale: Some("en-NZ".into()),
                            }]),
                            claim_nested: None,
                        },
                    ),
                    (
                        "familyName".into(),
                        Claim {
                            mandatory: Some(true),
                            value_type: Some(ValueType::String),
                            display: Some(vec![Display {
                                name: "Family name".into(),
                                locale: Some("en-NZ".into()),
                            }]),
                            claim_nested: None,
                        },
                    ),
                    (
                        "givenName".into(),
                        Claim {
                            mandatory: Some(true),
                            value_type: Some(ValueType::String),
                            display: Some(vec![Display {
                                name: "Given name".into(),
                                locale: Some("en-NZ".into()),
                            }]),
                            claim_nested: None,
                        },
                    ),
                ])),
            },
        }
    }
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
