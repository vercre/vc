//! # `OpenID` for Verifiable Credential Issuance

use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::future::Future;
use std::io::Cursor;
use std::str::FromStr;

use anyhow::anyhow;
use base64ct::{Base64, Encoding};
use qrcode::QrCode;
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use vercre_core::{urlencode, Kind};
use vercre_datasec::jose::jwk::PublicKeyJwk;
use vercre_datasec::SecOps;
use vercre_did::DidResolver;
use vercre_status::issuer::Status;
use vercre_w3c_vc::model::VerifiableCredential;

use crate::oauth;
pub use crate::oauth::{
    CodeChallengeMethod, GrantType, OAuthClient, OAuthServer, ResponseMode, ResponseType,
    TokenEndpointAuth, TokenEndpointAuthSigningAlg,
};
pub use crate::provider::{self, Result, StateStore};

// TODO: find a home for shared types

/// Issuer Provider trait.
pub trait Provider:
    Metadata + Subject + StateStore + SecOps + DidResolver + Status + Clone
{
}

/// The `Metadata` trait is used by implementers to provide `Client`, `Issuer`,
/// and `Server` metadata to the library.
pub trait Metadata: Send + Sync {
    /// Client (wallet) metadata for the specified issuance client.
    fn client(&self, client_id: &str) -> impl Future<Output = provider::Result<Client>> + Send;

    /// Credential Issuer metadata for the specified issuer.
    fn issuer(&self, issuer_id: &str) -> impl Future<Output = provider::Result<Issuer>> + Send;

    /// Authorization Server metadata for the specified issuer/server.
    fn server(
        &self, server_id: &str, issuer_id: Option<&str>,
    ) -> impl Future<Output = provider::Result<Server>> + Send;

    /// Used to dynamically register OAuth 2.0 clients with the authorization
    /// server.
    fn register(&self, client: &Client) -> impl Future<Output = provider::Result<Client>> + Send;
}

/// The Subject trait specifies how the library expects issuance subject (user)
/// information to be provided by implementers.
pub trait Subject: Send + Sync {
    /// Authorize issuance of the credential specified by
    /// `credential_configuration_id`. Returns a one or more
    /// `credential_identifier`s the subject (holder) is authorized to
    /// request.
    fn authorize(
        &self, subject_id: &str, credential_configuration_id: &str,
    ) -> impl Future<Output = provider::Result<Vec<String>>> + Send;

    /// Returns a populated `Dataset` object for the given subject (holder) and
    /// credential definition.
    fn dataset(
        &self, subject_id: &str, credential_identifier: &str,
    ) -> impl Future<Output = provider::Result<Dataset>> + Send;
}

/// Supported Holder authentication credential types.
pub enum Credentials {
    /// Username and password.
    Password {
        /// The username.
        username: String,

        /// The password.
        password: String,
    },
    //
    // /// A Verifiable Credential.
    // VerifiableCredential(VerifiableCredential),

    // /// A JWT.
    // Jwt(String),
}

/// The user information returned by the Subject trait.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Dataset {
    /// The credential subject populated for the user.
    pub claims: Map<String, Value>,

    /// Specifies whether user information required for the credential subject
    /// is pending.
    pub pending: bool,
}

/// Request a Credential Offer for a Credential Issuer.
#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct CreateOfferRequest {
    /// The URL of the Credential Issuer the Wallet can use obtain offered
    /// Credentials.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub credential_issuer: String,

    /// Identifies the (previously authenticated) Holder in order that Issuer
    /// can authorize credential issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,

    /// A list of credentials (as identified by their metadata ids) to include
    /// in the offer to the Wallet. Each id identifies one of the keys in
    /// the name/value pairs stored in the
    /// `credential_configurations_supported` Credential Issuer
    /// metadata property. The Wallet uses this string value to obtain the
    /// respective object that contains information about the Credential
    /// being offered. For example, this string value can be used to obtain
    /// scope value to be used in the Authorization Request.
    pub credential_configuration_ids: Vec<String>,

    // TODO: add support for `authorization_details` parameter
    // pub authorization_details: Vec<Authorized>,
    /// Whether the Issuer should provide a pre-authorized offer or not. If not
    /// pre-authorized, the Wallet must request authorization to fulfill the
    /// offer.
    /// When set to `true`, only the
    /// `urn:ietf:params:oauth:grant-type:pre-authorized_code` Grant Type
    /// will be set in the returned Credential Offer.
    #[serde(rename = "pre-authorize")]
    pub pre_authorize: bool,

    /// Specifies whether a Transaction Code (PIN) is required by the `token`
    /// endpoint during the Pre-Authorized Code Flow.
    pub tx_code_required: bool,

    /// The Issuer can specify whether Credential Offer is an object or a URI.
    pub send_type: SendType,
}

/// Determines how the Credential Offer is sent to the Wallet.
#[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum SendType {
    /// The Credential Offer is sent to the Wallet by value — as an object
    /// containing the Credential Offer parameters.
    #[default]
    ByVal,

    /// The Credential Offer is sent to the Wallet by reference — as a string
    /// containing a URL pointing to a location where the offer can be
    /// retrieved.
    ByRef,
}

impl fmt::Display for SendType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ByVal => write!(f, "by_val"),
            Self::ByRef => write!(f, "by_ref"),
        }
    }
}

impl From<String> for SendType {
    fn from(s: String) -> Self {
        match s.as_str() {
            "by_ref" => Self::ByRef,
            _ => Self::ByVal,
        }
    }
}

/// The response to a Credential Offer request.
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateOfferResponse {
    /// A Credential Offer that can be used to initiate issuance with a Wallet.
    /// The offer can be an object or URL pointing to the Credential Offer
    /// Endpoint where A `CredentialOffer` object can be retrieved.
    #[serde(flatten)]
    pub offer_type: OfferType,

    /// A transaction code to be provided by the End-User in order to complete
    /// a credential request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<String>,
}

/// The type of Credential Offer returned in a `CreateOfferResponse`: either an
/// object or a URI.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum OfferType {
    /// A Credential Offer object that can be sent to a Wallet as an HTTP GET
    /// request.
    #[serde(rename = "credential_offer")]
    Object(CredentialOffer),

    /// A URI pointing to the Credential Offer Endpoint where a
    /// `CredentialOffer` object can be retrieved.
    #[serde(rename = "credential_offer_uri")]
    Uri(String),
}

/// A Credential Offer object that can be sent to a Wallet as an HTTP GET
/// request.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialOffer {
    /// The URL of the Credential Issuer, the Wallet is requested to obtain one
    /// or more Credentials from.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub credential_issuer: String,

    /// Credentials offered to the Wallet.
    /// A list of names identifying entries in the
    /// `credential_configurations_supported` `HashMap` in the Credential
    /// Issuer metadata. The Wallet uses the identifier to obtain the
    /// respective Credential Definition containing information about the
    /// Credential being offered. For example, the identifier can be used to
    /// obtain scope value to be used in the Authorization Request.
    ///
    /// # Example
    ///
    /// ```json
    ///    "credential_configuration_ids": [
    ///       "UniversityDegree_JWT",
    ///       "org.iso.18013.5.1.mDL"
    ///    ],
    /// ```
    pub credential_configuration_ids: Vec<String>,

    /// Indicates to the Wallet the Grant Types the Credential Issuer is
    /// prepared to process for this credential offer. If not present, the
    /// Wallet MUST determine the Grant Types the Credential Issuer supports
    /// using the Issuer metadata. When multiple grants are present, it's at
    /// the Wallet's discretion which one to use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grants: Option<Grants>,
}

impl CredentialOffer {
    /// Generate a qrcode for the Credential Offer.
    /// Use the `endpoint` parameter to specify vercre-wallet's endpoint using
    /// deep link or direct call format.
    ///
    /// For example,
    ///
    /// ```http
    ///   openid-credential-offer://credential_offer=
    ///   or GET https://holder.vercre-wallet.io/credential_offer?
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an `Error::ServerError` error if error if the Credential Offer
    /// cannot be serialized.
    pub fn to_qrcode(&self, endpoint: &str) -> anyhow::Result<String> {
        let qs =
            self.to_querystring().map_err(|e| anyhow!("Failed to generate querystring: {e}"))?;

        // generate qr code
        let qr_code = QrCode::new(format!("{endpoint}{qs}"))
            .map_err(|e| anyhow!("Failed to create QR code: {e}"))?;

        // write image to buffer
        let img_buf = qr_code.render::<image::Luma<u8>>().build();
        let mut buffer: Vec<u8> = Vec::new();
        let mut writer = Cursor::new(&mut buffer);
        img_buf
            .write_to(&mut writer, image::ImageFormat::Png)
            .map_err(|e| anyhow!("Failed to create QR code: {e}"))?;

        // base64 encode image
        Ok(format!("data:image/png;base64,{}", Base64::encode_string(buffer.as_slice())))
    }

    /// Generate a query string for the Credential Offer.
    ///
    /// # Errors
    ///
    /// Returns an `Error::ServerError` error if error if the Credential Offer
    /// cannot be serialized.
    pub fn to_querystring(&self) -> anyhow::Result<String> {
        urlencode::to_string(self).map_err(|e| anyhow!("issue creating query string: {e}"))
    }
}

/// Grant Types the Credential Issuer's Authorization Server is prepared to
/// process for this credential offer.
///
/// The Credential Issuer can obtain user information to turn into a Verifiable
/// Credential using user authentication and consent at the Credential Issuer's
/// Authorization Endpoint (Authorization Code Flow) or using out of bound
/// mechanisms outside of the issuance flow (Pre-Authorized Code Flow).
///
/// When multiple grants are present, it's at the Wallet's discretion which one
/// to use.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Grants {
    /// Authorization Code Grant Type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_code: Option<AuthorizationCodeGrant>,

    /// Pre-Authorized Code Grant Type.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
}

/// The Authorization Code Grant Type contains parameters used by the Wallet
/// when requesting the Authorization Code Flow.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuthorizationCodeGrant {
    /// Issuer state is used to link an Authorization Request to the Offer
    /// context. If the Wallet uses the Authorization Code Flow, it MUST
    /// include it in the Authorization Request using the `issuer_state`
    /// parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,

    /// To be used by the Wallet to identify the Authorization Server to use
    /// with this grant type when `authorization_servers` parameter in the
    /// Credential Issuer metadata has multiple entries. MUST NOT be used
    /// otherwise. The value of this parameter MUST match with one of the
    /// values in the Credential Issuer `authorization_servers` metadata
    /// property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
}

/// The Pre-Authorized Code Grant Type contains parameters used by the Wallet
/// when using the Pre-Authorized Code Flow.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PreAuthorizedCodeGrant {
    /// The code representing the Issuer's authorization for the Wallet to
    /// obtain Credentials of the type specified in the offer. This code
    /// MUST be short lived and single-use. If the Wallet decides to use the
    /// Pre-Authorized Code Flow, this parameter MUST be include
    /// in the subsequent Token Request with the Pre-Authorized Code Flow.
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,

    /// The `tx_code` specifies whether the Authorization Server expects
    /// presentation of a Transaction Code by the End-User along with the
    /// Token Request in a Pre-Authorized Code Flow.
    ///
    /// The Transaction Code binds the Pre-Authorized Code to a certain
    /// transaction
    // to prevent replay of this code by an attacker that, for example, scanned the
    /// QR code while standing behind the legitimate End-User.
    ///
    /// It is RECOMMENDED to send the Transaction Code via a separate channel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<TxCode>,

    /// To be used by the Wallet to identify the Authorization Server to use
    /// with this grant type when `authorization_servers` parameter in the
    /// Credential Issuer metadata has multiple entries. MUST NOT be used
    /// otherwise. The value of this parameter MUST match with one of the
    /// values in the Credential Issuer `authorization_servers` metadata
    /// property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
}

/// Specifies whether the Authorization Server expects presentation of a
/// Transaction Code by the End-User along with the Token Request in a
/// Pre-Authorized Code Flow.
///
/// If the Authorization Server does not expect a Transaction Code, this object
/// is absent; this is the default.
///
/// The Transaction Code is used to bind the Pre-Authorized Code to a
/// transaction to prevent replay of the code by an attacker that, for example,
/// scanned the QR code while standing behind the legitimate End-User. It is
/// RECOMMENDED to send the Transaction Code via a separate channel. If the
/// Wallet decides to use the Pre-Authorized Code Flow, the Transaction Code
/// value MUST be sent in the `tx_code` parameter with the respective
/// Token Request as defined in Section 6.1. If no length or description is
/// given, this object may be empty, indicating that a Transaction Code is
/// required.
#[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TxCode {
    /// Specifies the input character set. Possible values are "numeric" (only
    /// digits) and "text" (any characters). The default is "numeric".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_mode: Option<String>,

    /// Specifies the length of the Transaction Code. This helps the Wallet to
    /// render the input screen and improve the user experience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<i32>,

    /// Guidance for the Holder of the Wallet on how to obtain the Transaction
    /// Code, e.g., describing over which communication channel it is
    /// delivered. The Wallet is RECOMMENDED to display this description
    /// next to the Transaction Code input screen to improve the user
    /// experience. The length of the string MUST NOT exceed 300 characters.
    /// The description does not support internationalization, however
    /// the Issuer MAY detect the Holder's language by previous communication or
    /// an HTTP Accept-Language header within an HTTP GET request for a
    /// Credential Offer URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// The Credential Offer Request is used by the Wallet to retrieve a previously
/// generated Credential Offer.
///
/// The Wallet is sent a `credential_offer_uri` containing a unique URL pointing
/// to the Offer. The URI has the form `credential_issuer/credential_offer/id`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialOfferRequest {
    /// The URL of the Credential Issuer the Wallet can use obtain the
    /// Credential Offer.
    pub credential_issuer: String,

    /// The unique identifier for the the previously generated Credential Offer.
    pub id: String,
}

/// The Credential Offer Response is used to return a previously generated
/// Credential Offer.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialOfferResponse {
    /// The Credential Offer generated by the `create_offer` endpoint.
    pub credential_offer: CredentialOffer,
}

/// An Authorization Request type.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum AuthorizationRequest {
    /// A URI referencing the authorization request previously stored at the PAR
    /// endpoint.
    Uri(RequestUri),

    /// An Authorization Request object.
    Object(RequestObject),
}

impl Default for AuthorizationRequest {
    fn default() -> Self {
        Self::Object(RequestObject::default())
    }
}

impl fmt::Display for AuthorizationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = urlencode::to_string(self).map_err(|_| fmt::Error)?;
        write!(f, "{s}")
    }
}

impl FromStr for AuthorizationRequest {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('=') && s.contains('&') {
            Ok(urlencode::from_str(s)?)
        } else {
            Ok(Self::Object(serde_json::from_str(s)?))
        }
    }
}

/// `Claim` requires a custom deserializer as JSON claims are always objects.
/// The A `Claim::Entry` is a single claim definition, while a `Claim::Set` is a
/// set of nested claims.
impl<'de> de::Deserialize<'de> for AuthorizationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RequestVisitor;

        impl<'de> Visitor<'de> for RequestVisitor {
            type Value = AuthorizationRequest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("AuthorizationRequest")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut obj: RequestObject = RequestObject::default();
                let mut uri: RequestUri = RequestUri::default();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        // RequestObject
                        "credential_issuer" => {
                            obj.credential_issuer = map.next_value::<String>()?;
                        }
                        "response_type" => {
                            obj.response_type = map.next_value::<oauth::ResponseType>()?;
                        }
                        "client_id" => obj.client_id = map.next_value::<String>()?,
                        "redirect_uri" => obj.redirect_uri = Some(map.next_value::<String>()?),
                        "state" => obj.state = Some(map.next_value::<String>()?),
                        "code_challenge" => obj.code_challenge = map.next_value::<String>()?,
                        "code_challenge_method" => {
                            obj.code_challenge_method =
                                map.next_value::<oauth::CodeChallengeMethod>()?;
                        }
                        "authorization_details" => {
                            obj.authorization_details =
                                Some(map.next_value::<Vec<AuthorizationDetail>>()?);
                        }
                        "scope" => obj.scope = Some(map.next_value::<String>()?),
                        "resource" => obj.resource = Some(map.next_value::<String>()?),
                        "subject_id" => obj.subject_id = map.next_value::<String>()?,
                        "wallet_issuer" => obj.wallet_issuer = Some(map.next_value::<String>()?),
                        "user_hint" => obj.user_hint = Some(map.next_value::<String>()?),
                        "issuer_state" => obj.issuer_state = Some(map.next_value::<String>()?),

                        // RequestUri
                        "request_uri" => uri.request_uri = map.next_value::<String>()?,
                        _ => {}
                    }
                }

                if uri.request_uri.is_empty() {
                    Ok(AuthorizationRequest::Object(obj))
                } else {
                    Ok(AuthorizationRequest::Uri(uri))
                }
            }
        }

        deserializer.deserialize_map(RequestVisitor)
    }
}

/// A URI referencing the authorization request previously stored at the PAR
/// endpoint.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RequestUri {
    /// The URI of the authorization request.
    pub request_uri: String,
}

/// An Authorization Request is an OAuth 2.0 Authorization Request as defined in
/// section 4.1.1 of [RFC6749], which requests to grant access to the Credential
/// Endpoint.
///
/// [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RequestObject {
    /// The URL of the Credential Issuer the Wallet can use obtain offered
    /// Credentials.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub credential_issuer: String,

    /// Authorization Server's response type.
    pub response_type: oauth::ResponseType,

    /// OAuth 2.0 Client ID used by the Wallet.
    pub client_id: String,

    /// The client's redirection endpoint as previously established during the
    /// client registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    /// Client state is used by the client to maintain state between the request
    /// and callback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// PKCE code challenge, used to prevent authorization code interception
    /// attacks and mitigate the need for client secrets.
    pub code_challenge: String,

    /// PKCE code challenge method. Must be "S256".
    pub code_challenge_method: oauth::CodeChallengeMethod,

    /// Authorization Details may used to convey the details about credentials
    /// the Wallet wants to obtain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<AuthorizationDetail>>,

    /// Credential Issuers MAY support requesting authorization to issue a
    /// credential using OAuth 2.0 scope values.
    /// A scope value and its mapping to a credential type is defined by the
    /// Issuer. A description of scope value semantics or machine readable
    /// definitions could be defined in Issuer metadata. For example,
    /// mapping a scope value to an authorization details object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// The Credential Issuer's identifier to allow the Authorization Server to
    /// differentiate between Issuers. [RFC8707]: The target resource to which
    /// access is being requested. MUST be an absolute URI.
    ///
    /// [RFC8707]: (https://www.rfc-editor.org/rfc/rfc8707)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,

    // TODO: replace `subject_id` with support for authentication
    // <https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest>
    /// A Holder identifier provided by the Wallet. It must have meaning to the
    /// Credential Issuer in order that credentialSubject claims can be
    /// populated.
    pub subject_id: String,

    /// The Wallet's `OpenID` Connect issuer URL. The Credential Issuer can use
    /// the discovery process as defined in [SIOPv2] to determine the Wallet's
    /// capabilities and endpoints. RECOMMENDED in Dynamic Credential Requests.
    ///
    /// [SIOPv2]: (https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_issuer: Option<String>,

    /// An opaque user hint the Wallet MAY use in subsequent callbacks to
    /// optimize the user's experience. RECOMMENDED in Dynamic Credential
    /// Requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_hint: Option<String>,

    /// Identifies a pre-existing Credential Issuer processing context. A value
    /// for this parameter may be passed in the Credential Offer to the
    /// Wallet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,
}

/// Authorization detail type (we only support `openid_credential`).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthorizationDetailType {
    /// OpenID Credential authorization detail type.
    #[default]
    #[serde(rename = "openid_credential")]
    OpenIdCredential,
}

/// Authorization Details is used to convey the details about the Credentials
/// the Wallet wants to obtain.
/// See <https://www.rfc-editor.org/rfc/rfc9396.html>
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationDetail {
    /// Type determines the authorization details type. MUST be
    /// "`openid_credential`".
    #[serde(rename = "type")]
    pub type_: AuthorizationDetailType,

    /// Identifies credential to authorize for issuance using either
    /// `credential_configuration_id` or a supported credential `format`.
    #[serde(flatten)]
    pub credential: CredentialAuthorization,

    // TODO: integrate locations
    /// If the Credential Issuer metadata contains an `authorization_servers`
    /// parameter, the authorization detail's locations field MUST be set to
    /// the Credential Issuer Identifier.
    ///
    /// # Example
    ///
    /// ```text
    /// "locations": [
    ///     "https://credential-issuer.example.com"
    ///  ]
    /// ```
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<String>>,
}

/// Means used to identifiy a Credential's type when requesting a Credential.
#[derive(Clone, Debug, Deserialize, Serialize, Eq)]
#[serde(untagged)]
pub enum CredentialAuthorization {
    /// Identifes the credential to authorize by `credential_configuration_id`.
    ConfigurationId {
        /// The unique identifier of the Credential being requested in the
        /// `credential_configurations_supported` map in  Issuer Metadata.
        credential_configuration_id: String,

        /// A subset of supported claims to authorize for the  issued
        /// credential.
        #[serde(flatten)]
        #[serde(skip_serializing_if = "Option::is_none")]
        claims: Option<ProfileClaims>,
    },

    /// Identifies the credential to authorize using format-specific parameters.
    /// The requested format should resolve to a single supported credential in
    /// the `credential_configurations_supported` map in the Issuer Metadata.
    Format(FormatIdentifier),
}

impl Default for CredentialAuthorization {
    fn default() -> Self {
        Self::ConfigurationId {
            credential_configuration_id: String::new(),
            claims: None,
        }
    }
}

/// `PartialEq` for `CredentialAuthorization` checks for equivalence using
/// `credential_configuration_id` or `format`, ecluding claims.
impl PartialEq for CredentialAuthorization {
    fn eq(&self, other: &Self) -> bool {
        match self {
            Self::ConfigurationId {
                credential_configuration_id,
                ..
            } => {
                let Self::ConfigurationId {
                    credential_configuration_id: other_id,
                    ..
                } = &other
                else {
                    return false;
                };
                credential_configuration_id == other_id
            }
            Self::Format(format) => {
                let Self::Format(other_format) = &other else {
                    return false;
                };
                format == other_format
            }
        }
    }
}

/// The `OpenID4VCI` specification defines commonly used [Credential Format
/// Profiles] to support.  The profiles define Credential format specific
/// parameters or claims used to support a particular format.
///
/// [Credential Format Profiles]: (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-format-profiles)
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "format")]
pub enum FormatIdentifier {
    /// A W3C Verifiable Credential.
    ///
    /// When this format is specified, Credential Offer, Authorization Details,
    /// Credential Request, and Credential Issuer metadata, including
    /// `credential_definition` object, MUST NOT be processed using JSON-LD
    /// rules.
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson(ProfileW3c),

    /// A W3C Verifiable Credential.
    ///
    /// When using this format, data MUST NOT be processed using JSON-LD rules.
    ///
    /// N.B. The `@context` value in the `credential_definition` object can be
    /// used by the Wallet to check whether it supports a certain VC. If
    /// necessary, the Wallet could apply JSON-LD processing to the
    /// Credential issued.
    #[serde(rename = "ldp-vc")]
    LdpVc(ProfileW3c),

    /// A W3C Verifiable Credential.
    ///
    /// When using this format, data MUST NOT be processed using JSON-LD rules.
    ///
    /// N.B. The `@context` value in the `credential_definition` object can be
    /// used by the Wallet to check whether it supports a certain VC. If
    /// necessary, the Wallet could apply JSON-LD processing to the
    /// Credential issued.
    #[serde(rename = "jwt_vc_json-ld")]
    JwtVcJsonLd(ProfileW3c),

    /// ISO mDL.
    ///
    /// A Credential Format Profile for Credentials complying with [ISO.18013-5]
    /// — ISO-compliant driving licence specification.
    ///
    /// [ISO.18013-5]: (https://www.iso.org/standard/69084.html)
    #[serde(rename = "mso_mdoc")]
    IsoMdl(ProfileIsoMdl),

    /// IETF SD-JWT VC.
    ///
    /// A Credential Format Profile for Credentials complying with
    /// [I-D.ietf-oauth-sd-jwt-vc] — SD-JWT-based Verifiable Credentials for
    /// selective disclosure.
    ///
    /// [I-D.ietf-oauth-sd-jwt-vc]: (https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-01)
    #[serde(rename = "vc+sd-jwt")]
    VcSdJwt(ProfileSdJwt),
}

impl FormatIdentifier {
    /// Claims for the format profile.
    #[must_use]
    pub fn claims(&self) -> Option<HashMap<String, Claim>> {
        match self {
            Self::JwtVcJson(w3c) | Self::JwtVcJsonLd(w3c) | Self::LdpVc(w3c) => {
                w3c.credential_definition.credential_subject.clone()
            }
            Self::IsoMdl(iso_mdl) => iso_mdl.claims.clone(),
            Self::VcSdJwt(sd_jwt) => sd_jwt.claims.clone(),
        }
    }
}

impl Default for FormatIdentifier {
    fn default() -> Self {
        Self::JwtVcJson(ProfileW3c::default())
    }
}

impl std::fmt::Display for FormatIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JwtVcJson(_) => write!(f, "jwt_vc_json"),
            Self::LdpVc(_) => write!(f, "ldp_vc"),
            Self::JwtVcJsonLd(_) => write!(f, "jwt_vc_json-ld"),
            Self::IsoMdl(_) => write!(f, "mso_mdoc"),
            Self::VcSdJwt(_) => write!(f, "vc+sd-jwt"),
        }
    }
}

/// Supported [Credential Format Profiles].
///
/// [Credential Format Profiles]: (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-format-profiles)
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum ProfileClaims {
    /// W3C Verifiable Credential profile claims.
    #[serde(rename = "credential_definition")]
    W3c(CredentialDefinition),

    /// `ISO.18013-5` (Mobile Driving License) profile claims
    #[serde(rename = "claims")]
    IsoMdl(HashMap<String, Claim>),

    /// Selective Disclosure JWT ([SD-JWT]) profile claims.
    #[serde(rename = "claims")]
    SdJwt(HashMap<String, Claim>),
}

impl Default for ProfileClaims {
    fn default() -> Self {
        Self::W3c(CredentialDefinition::default())
    }
}

impl ProfileClaims {
    /// Claims for the format profile.
    #[must_use]
    pub fn claims(&self) -> Option<HashMap<String, Claim>> {
        match self {
            Self::W3c(credential_definition) => credential_definition.credential_subject.clone(),
            Self::IsoMdl(claims) | Self::SdJwt(claims) => Some(claims.clone()),
        }
    }
}

/// Credential Format Profile for W3C Verifiable Credentials.
#[derive(Clone, Default, Debug, Deserialize, Serialize, Eq)]
pub struct ProfileW3c {
    /// The Credential's definition.
    pub credential_definition: CredentialDefinition,
}

impl PartialEq for ProfileW3c {
    fn eq(&self, other: &Self) -> bool {
        self.credential_definition.type_ == other.credential_definition.type_
    }
}

/// Credential Format Profile for `ISO.18013-5` (Mobile Driving License)
/// credentials.
#[derive(Clone, Default, Debug, Deserialize, Serialize, Eq)]
pub struct ProfileIsoMdl {
    /// The Credential type, as defined in [ISO.18013-5].
    doctype: String,

    /// A list of claims to include in the issued credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    claims: Option<HashMap<String, Claim>>,
}

impl PartialEq for ProfileIsoMdl {
    fn eq(&self, other: &Self) -> bool {
        self.doctype == other.doctype
    }
}

/// Credential Format Profile for Selective Disclosure JWT ([SD-JWT])
/// credentials.
///
/// [SD-JWT]: <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-04>
#[derive(Clone, Default, Debug, Deserialize, Serialize, Eq)]
pub struct ProfileSdJwt {
    /// The Verifiable Credential type. The `vct` value MUST be a
    /// case-sensitive String or URI serving as an identifier for
    /// the type of the SD-JWT VC.
    vct: String,

    /// A list of claims to include in the issued credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    claims: Option<HashMap<String, Claim>>,
}

impl PartialEq for ProfileSdJwt {
    fn eq(&self, other: &Self) -> bool {
        self.vct == other.vct
    }
}

/// Authorization Response as defined in [RFC6749].
///
/// [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizationResponse {
    /// Authorization code.
    pub code: String,

    /// Client state. An opaque value used by the client to maintain state
    /// between the request and callback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// The client's redirection endpoint from the Authorization request.
    pub redirect_uri: String,
}

/// Pushed Authorization Request (PAR) response as defined in [RFC9126].
///
/// [RFC9126]: (https://www.rfc-editor.org/rfc/rfc9126.html)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PushedAuthorizationRequest {
    /// The authorization request posted.
    #[serde(flatten)]
    pub request: RequestObject,

    /// Client identity assertion using JWT instead of credentials to
    /// authenticate.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub client_assertion: Option<ClientAssertion>,
}

/// Pushed Authorization Request (PAR) response as defined in [RFC9126].
///
/// [RFC9126]: (https://www.rfc-editor.org/rfc/rfc9126.html)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PushedAuthorizationResponse {
    /// The request URI corresponding to the authorization request posted. This
    /// URI is a single-use reference to the respective request data in the
    /// subsequent authorization request.
    pub request_uri: String,

    /// The lifetime of the request URI in seconds. Typically a relatively short
    /// duration (e.g., between 5 and 600 seconds).
    pub expires_in: i64,
}

/// Upon receiving a successful Authorization Response, a Token Request is made
/// as defined in [RFC6749] with extensions to support the Pre-Authorized Code
/// Flow.
///
/// [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct TokenRequest {
    /// The URL of the Credential Issuer the Wallet can use obtain offered
    /// Credentials.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub credential_issuer: String,

    /// OAuth 2.0 Client ID used by the Wallet.
    ///
    /// REQUIRED if the client is not authenticating with the authorization
    /// server. An unauthenticated client MUST send its `client_id` to
    /// prevent itself from inadvertently accepting a code intended for a
    /// client with a different `client_id`.  This protects the client from
    /// substitution of the authentication code.
    ///
    /// For the Pre-Authorized Code Grant Type, authentication of the Client is
    /// OPTIONAL, as described in Section 3.2.1 of OAuth 2.0 [RFC6749], and,
    /// consequently, the `client_id` parameter is only needed when a form
    /// of Client Authentication that relies on this parameter is used.
    pub client_id: Option<String>,

    /// Authorization grant type.
    #[serde(flatten)]
    pub grant_type: TokenGrantType,

    /// Authorization Details is used to convey the details about the
    /// Credentials the Wallet wants to obtain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<AuthorizationDetail>>,

    /// Client identity assertion using JWT instead of credentials to
    /// authenticate.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub client_assertion: Option<ClientAssertion>,
}

/// Token authorization grant types.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "grant_type")]
pub enum TokenGrantType {
    /// Attributes required for the Authorization Code grant type.
    #[serde(rename = "authorization_code")]
    AuthorizationCode {
        /// The authorization code received from the authorization server when
        /// the Wallet use the Authorization Code Flow.
        code: String,

        /// The client's redirection endpoint if `redirect_uri` was included in
        /// the authorization request.
        /// REQUIRED if the `redirect_uri` parameter was included in the
        /// authorization request; values MUST be identical.
        #[serde(skip_serializing_if = "Option::is_none")]
        redirect_uri: Option<String>,

        /// PKCE code verifier provided by the Wallet when using the
        /// Authorization Code Flow. MUST be able to verify the
        /// `code_challenge` provided in the authorization request.
        #[serde(skip_serializing_if = "Option::is_none")]
        code_verifier: Option<String>,
    },

    /// Attributes required for the Pre-Authorized Code grant type
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode {
        /// The pre-authorized code provided to the Wallet in a Credential
        /// Offer.
        #[serde(rename = "pre-authorized_code")]
        pre_authorized_code: String,

        /// The Transaction Code provided to the user during the Credential
        /// Offer process. Must be present if `tx_code` was set to true
        /// in the Credential Offer.
        #[serde(skip_serializing_if = "Option::is_none")]
        tx_code: Option<String>,
    },
}

impl Default for TokenGrantType {
    fn default() -> Self {
        Self::AuthorizationCode {
            code: String::new(),
            redirect_uri: None,
            code_verifier: None,
        }
    }
}

/// Client identity assertion.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "client_assertion_type")]
pub enum ClientAssertion {
    /// OAuth 2.0 Client Assertion using JWT Bearer Token.
    /// See <https://blog.logto.io/client-assertion-in-client-authn>
    #[serde(rename = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")]
    JwtBearer {
        /// The client's JWT assertion.
        client_assertion: String,
    },
}

/// Token Response as defined in [RFC6749].
///
/// [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TokenResponse {
    /// An OAuth 2.0 Access Token that can subsequently be used to request one
    /// or more Credentials.
    pub access_token: String,

    /// The type of the token issued. Must be "`Bearer`".
    pub token_type: TokenType,

    /// The lifetime in seconds of the access token.
    pub expires_in: i64,

    /// A nonce to be used by the Wallet to create a proof of possession of key
    /// material when requesting credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce: Option<String>,

    /// Lifetime in seconds of the `c_nonce`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce_expires_in: Option<i64>,

    /// REQUIRED when `authorization_details` parameter is used to request
    /// issuance of a certain Credential type. MUST NOT be used otherwise.
    ///
    /// The Authorization Details `credential_identifiers` parameter may be
    /// populated for use in subsequent Credential Requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<AuthorizedDetail>>,
}

/// Access token type as defined in [RFC6749]. Per the specification, the only
/// value allowed is "`Bearer`".
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum TokenType {
    /// The only valid value is "`Bearer`".
    #[default]
    Bearer,
}

/// Authorization Details object specifically for use in successful Access Token
/// responses ([`TokenResponse`]).
///
/// It wraps the `AuthorizationDetail` struct and adds `credential_identifiers`
/// parameter for use in Credential requests.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizedDetail {
    /// Reuse (and flatten) the existing [`AuthorizationDetail`] object used in
    /// authorization requests.
    #[serde(flatten)]
    pub authorization_detail: AuthorizationDetail,

    /// Credential Identifiers uniquely identify Credential Datasets that can
    /// be issued. Each Dataset corresponds to a Credential Configuration in the
    /// `credential_configurations_supported` parameter of the Credential
    /// Issuer metadata. The Wallet MUST use these identifiers in Credential
    /// Requests.
    pub credential_identifiers: Vec<String>,
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
    pub credential: CredentialIssuance,

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
#[serde(untagged)]
pub enum CredentialIssuance {
    /// Credential is requested by `credential_identifier`.
    /// REQUIRED when an Authorization Details of type `openid_credential` was
    /// returned from the Token Response.
    Identifier {
        /// Identifies a Credential in the `credential_configurations_supported`
        /// Credential Issuer metadata, but containing different claim values or
        /// different subset of the Credential's claims.
        credential_identifier: String,
    },

    /// Defines the format and type of of the Credential to be issued.  REQUIRED
    /// when `credential_identifiers` was not returned from the Token Response.
    Format(FormatIdentifier),
}

impl Default for CredentialIssuance {
    fn default() -> Self {
        Self::Identifier {
            credential_identifier: String::new(),
        }
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

/// Request to retrieve the Credential Issuer's configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MetadataRequest {
    /// The Credential Issuer Identifier for which the configuration is to be
    /// returned.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub credential_issuer: String,

    /// The language(s) set in HTTP Accept-Language Headers. MUST be values
    /// defined in [RFC3066].
    ///
    /// [RFC3066]: (https://www.rfc-editor.org/rfc/rfc3066)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub languages: Option<String>,
}

/// Response containing the Credential Issuer's configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct MetadataResponse {
    /// The Credential Issuer metadata for the specified Credential Issuer.
    #[serde(flatten)]
    pub credential_issuer: Issuer,
}

/// Request to retrieve the Credential Issuer's authorization server
/// configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OAuthServerRequest {
    /// The Authorization Server identifier for which the configuration is to be
    /// returned.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub credential_issuer: String,

    /// Authorization issuer identifier.
    ///
    /// This identifier can be obtained from the `authorization_servers`
    /// parameter in the Credential Issuer metadata. If that parameter is
    /// not present, the `issuer` parameter should be `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

/// Response containing the Credential Issuer's authorization server
/// configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct OAuthServerResponse {
    /// The OAuth 2.0 Authorization Server metadata for the Issuer.
    pub authorization_server: Server,
}

/// The registration request.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RegistrationRequest {
    /// The Credential Issuer for which the client is being registered.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub credential_issuer: String,

    /// A previously issued Access Token, as extracted from the Authorization
    /// header of the Credential Request. Used to grant access to register a
    /// client.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub access_token: String,

    /// Metadata provided by the client undertaking registration.
    #[serde(flatten)]
    pub client_metadata: Client,
}

/// The registration response for a successful request.
#[derive(Debug, Deserialize, Serialize)]
pub struct RegistrationResponse {
    /// Registered Client metadata.
    #[serde(flatten)]
    pub client_metadata: Client,
}

/// The Credential Issuer's configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Issuer {
    /// The Credential Issuer's identifier.
    #[serde(skip_serializing_if = "String::is_empty", default)]
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

    /// URL of the Credential Issuer's Deferred Credential Endpoint. This URL
    /// MUST use the https scheme and MAY contain port, path, and query
    /// parameter components. If omitted, the Credential Issuer does not
    /// support the Deferred Credential Endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred_credential_endpoint: Option<String>,

    /// URL of the Credential Issuer's Notification Endpoint. This URL
    /// MUST use the https scheme and MAY contain port, path, and query
    /// parameter components.  If omitted, the Credential Issuer does not
    /// support the Notification Endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_endpoint: Option<String>,

    /// Specifies whether (and how) the Credential Issuer supports encryption of
    /// the Credential and Batch Credential Response on top of TLS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<SupportedCredentialResponseEncryption>,

    /// Information about the Issuer's support for batch issuance of
    /// Credentials. The presence of this parameter means that the issuer
    /// supports the proofs parameter in the Credential Request so can issue
    /// more than one Verifiable Credential for the same Credential Dataset in a
    /// single request/response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_credential_issuance: Option<BatchCredentialIssuance>,

    /// A signed JWT containing Credential Issuer metadata parameters as claims.
    /// The signed metadata MUST be secured using JSON Web Signature (JWS)
    /// [RFC7515] and MUST contain an iat (Issued At) claim, an iss (Issuer)
    /// claim denoting the party attesting to the claims in the signed
    /// metadata, and sub (Subject) claim matching the Credential Issuer
    /// identifier. If the Wallet supports signed metadata, metadata values
    /// conveyed in the signed JWT MUST take precedence over the
    /// corresponding values conveyed using plain JSON elements. If the
    /// Credential Issuer wants to enforce use of signed metadata, it omits
    /// the respective metadata parameters from the unsigned part of the
    /// Credential Issuer metadata. A signed_ metadata metadata value MUST
    /// NOT appear as a claim in the JWT. The Wallet MUST establish trust in
    /// the signer of the metadata, and obtain the keys to validate
    /// the signature before processing the metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_metadata: Option<String>,

    /// Credential Issuer display properties for supported languages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Display>,

    /// A list of name/value pairs of credentials supported by the Credential
    /// Issuer. Each name is a unique identifier for the supported
    /// credential described. The identifier is used in the Credential Offer
    /// to communicate to the Wallet which Credential is being offered. The
    /// value is a Credential object containing metadata about specific
    /// credential.
    pub credential_configurations_supported: HashMap<String, CredentialConfiguration>,
}

impl Issuer {
    /// Returns the `credential_configuration_id` for a given format.
    ///
    /// # Errors
    ///
    /// TODO: add error handling
    pub fn credential_configuration_id(&self, fmt: &FormatIdentifier) -> Result<&String> {
        self.credential_configurations_supported
            .iter()
            .find(|(_, cfg)| &cfg.format == fmt)
            .map(|(id, _)| id)
            .ok_or_else(|| anyhow!("Credential Configuration not found"))
    }
}

/// Contains information about whether the Credential Issuer supports encryption
/// of the Credential and Batch Credential Response on top of TLS.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SupportedCredentialResponseEncryption {
    /// JWE [RFC7516] alg algorithm [RFC7518] REQUIRED for encrypting Credential
    /// Responses.
    ///
    /// [RFC7516]: (https://www.rfc-editor.org/rfc/rfc7516)
    /// [RFC7518]: (https://www.rfc-editor.org/rfc/rfc7518)
    pub alg_values_supported: Vec<String>,

    /// JWE [RFC7516] enc algorithm [RFC7518] REQUIRED for encrypting Credential
    /// Responses. If `credential_response_encryption_alg` is specified, the
    /// default for this value is "`A256GCM`".
    ///
    /// [RFC7516]: (https://www.rfc-editor.org/rfc/rfc7516)
    /// [RFC7518]: (https://www.rfc-editor.org/rfc/rfc7518)
    pub enc_values_supported: Vec<String>,

    /// Specifies whether the Credential Issuer requires the additional
    /// encryption on top of TLS for the Credential Response. If the value
    /// is true, the Credential Issuer requires encryption for every
    /// Credential Response and therefore the Wallet MUST provide encryption
    /// keys in the Credential Request. If the value is false, the Wallet
    /// MAY chose whether it provides encryption keys or not.
    pub encryption_required: bool,
}

/// Contains information about the Credential Issuer's support for batch
/// issuance of Credentials on the Credential Endpoint.
///
/// The presence of this parameter means that the issuer supports the proofs
/// parameter in the Credential Request so can issue more than one Verifiable
/// Credential for the same Credential Dataset in a single request/response.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct BatchCredentialIssuance {
    /// The maximum array size for the proofs parameter in a Credential Request.
    pub batch_size: i64,
}

/// Language-based display properties for Issuer or Claim.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Display {
    /// The name to use when displaying the name of the `Issuer` or `Claim` for
    /// the specified locale. If no locale is set, then this value is the
    /// default value.
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
    /// Identifies the format of the credential, e.g. "`jwt_vc_json`" or
    /// "`ldp_vc`". Each object will contain further elements defining the
    /// type and claims the credential MAY contain, as well as information
    /// on how to display the credential.
    ///
    /// See OpenID4VCI [Credential Format Profiles] for more detail.
    ///
    /// [Credential Format Profiles]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-format-profiles
    #[serde(flatten)]
    pub format: FormatIdentifier,

    /// The `scope` value that this Credential Issuer supports for this
    /// credential. The value can be the same accross multiple
    /// `credential_configurations_supported` objects. The Authorization
    /// Server MUST be able to uniquely identify the Credential Issuer based
    /// on the scope value. The Wallet can use this value in
    /// the Authorization Request Scope values in this Credential Issuer
    /// metadata MAY duplicate those in the `scopes_supported` parameter of
    /// the Authorization Server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Identifies how the Credential should be bound to the identifier of the
    /// End-User who possesses the Credential. Is case sensitive.
    ///
    /// Support for keys in JWK format [RFC7517] is indicated by the value
    /// "`jwk`". Support for keys expressed as a COSE Key object [RFC8152]
    /// (for example, used in [ISO.18013-5]) is indicated by the value
    /// "`cose_key`".
    ///
    /// When Cryptographic Binding Method is a DID, valid values MUST be a
    /// "did:" prefix followed by a method-name using a syntax as defined in
    /// Section 3.1 of [DID-Core], but without a ":" and method-specific-id.
    /// For example, support for the DID method with a method-name "example"
    /// would be represented by "did:example". Support for all DID methods
    /// listed in Section 13 of [DID Specification Registries] is indicated
    /// by sending a DID without any method-name.
    ///
    /// [RFC7517]: (https://www.rfc-editor.org/rfc/rfc7517)
    /// [RFC8152]: (https://www.rfc-editor.org/rfc/rfc8152)
    /// [ISO.18013-5]: (https://www.iso.org/standard/69084.html)
    /// [DID-Core]: (https://www.w3.org/TR/did-core/)
    /// [DID Specification Registries]: (https://www.w3.org/TR/did-spec-registries/)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,

    /// Case sensitive strings that identify the cryptographic suites supported
    /// for the `cryptographic_binding_methods_supported`. Cryptographic
    /// algorithms for Credentials in `jwt_vc` format should use algorithm
    /// names defined in IANA JOSE Algorithms Registry. Cryptographic
    /// algorithms for Credentials in `ldp_vc` format should use signature
    /// suites names defined in Linked Data Cryptographic Suite Registry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_signing_alg_values_supported: Option<Vec<String>>,

    /// The key proof(s) that the Credential Issuer supports. This object
    /// contains a list of name/value pairs, where each name is a unique
    /// identifier of the supported proof type(s). Valid values are defined
    /// in Section 7.2.1, other values MAY be used. This identifier is also
    /// used by the Wallet in the Credential Request as defined in Section
    /// 7.2. The value in the name/value pair is an object that contains
    /// metadata about the key proof and contains the following parameters
    /// defined by this specification:
    ///
    ///  - `jwt`: A JWT [RFC7519] is used as proof of possession. A proof object
    ///    MUST include a jwt claim containing a JWT defined in Section 7.2.1.1.
    ///
    ///  - `cwt`: A CWT [RFC8392] is used as proof of possession. A proof object
    ///    MUST include a cwt claim containing a CWT defined in Section 7.2.1.3.
    ///
    ///  - `ldp_vp`: A W3C Verifiable Presentation object signed using the Data
    ///    Integrity Proof as defined in [VC_DATA_2.0] or [VC_DATA], and where
    ///    the proof of possession MUST be done in accordance with
    ///    [VC_Data_Integrity]. When `proof_type` is set to `ldp_vp`, the proof
    ///    object MUST include a `ldp_vp` claim containing a W3C Verifiable
    ///    Presentation defined in Section 7.2.1.2.
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
}

impl CredentialConfiguration {
    /// Verifies that the `claimset` contains required claims and they are
    /// supported for the Credential.
    ///
    /// # Errors
    ///
    /// Returns an error if the `claimset` contains unsupported claims or does
    /// not contain required (mandatory) claims.
    pub fn verify_claims(&self, claimset: &HashMap<String, Claim>) -> Result<()> {
        // ensure `claimset` claims exist in the supported claims
        if !claimset.is_empty() {
            if let Some(claims) = &self.format.claims() {
                let _ = Self::claims_supported(claimset, claims);
            }
        }

        // ensure all mandatory claims are present
        if let Some(claims) = &self.format.claims() {
            return Self::claims_required(claimset, claims);
        }

        Ok(())
    }

    /// Verifies `claimset` claims are supported by the Credential
    fn claims_supported(
        claimset: &HashMap<String, Claim>, supported: &HashMap<String, Claim>,
    ) -> Result<()> {
        for (key, entry) in claimset {
            if !supported.contains_key(key) {
                return Err(anyhow!("{key} claim is not supported"));
            }

            // check nested claims
            if let Claim::Set(req_nested) = &entry {
                if let Claim::Set(sup_nested) = &supported[key] {
                    Self::claims_supported(req_nested, sup_nested)?;
                } else {
                    return Err(anyhow!("{key} claimset is not supported "));
                }
            };
        }

        Ok(())
    }

    /// Verifies `claimset` contains all required claims
    fn claims_required(
        requested: &HashMap<String, Claim>, supported: &HashMap<String, Claim>,
    ) -> Result<()> {
        for (key, entry) in supported {
            match entry {
                Claim::Set(sup_nested) => {
                    #[allow(clippy::or_fun_call)]
                    if let Claim::Set(req_nested) =
                        requested.get(key).unwrap_or(&Claim::Set(HashMap::new()))
                    {
                        Self::claims_required(req_nested, sup_nested)?;
                    } else {
                        return Err(anyhow!("{key} claim is not supported"));
                    }
                }
                Claim::Entry(def) => {
                    if def.mandatory.unwrap_or_default() && requested.get(key).is_none() {
                        return Err(anyhow!("{key} claim is required"));
                    }
                }
            }
        }

        Ok(())
    }
}

/// `ProofTypesSupported` describes specifics of the key proof(s) that the
/// Credential Issuer supports.
///
/// This object contains a list of name/value pairs, where each name is a unique
/// identifier of the supported proof type(s). Valid values are defined in
/// Section 7.2.1, other values MAY be used. This identifier is also used by the
/// Wallet in the Credential Request as defined in Section 7.2. The value in the
/// name/value pair is an object that contains metadata about the key proof.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProofTypesSupported {
    /// One or more case sensitive strings that identify the algorithms that the
    /// Issuer supports for this proof type. The Wallet uses one of them to
    /// sign the proof. Algorithm names used are determined by the key proof
    /// type.
    ///
    /// For example, for JWT, the algorithm names are defined in IANA JOSE
    /// Algorithms Registry.
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

// TODO: split into 2 types or use enum for variations based on format

/// `CredentialDefinition` defines a Supported Credential that may requested by
/// Wallets.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialDefinition {
    /// The @context property is used to map property URIs into short-form
    /// aliases, in accordance with the W3C Verifiable Credentials Data
    /// Model.
    ///
    /// REQUIRED when `format` is "`jwt_vc_json-ld`" or "`ldp_vc`".
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<String>>,

    /// Uniquely identifies the credential type the Credential Definition
    /// display properties are for, in accordance with the W3C Verifiable
    /// Credentials Data Model.
    /// Contains the type values the Wallet requests authorization for at the
    /// Credential Issuer. It MUST be present if the claim format is present in
    /// the root of the authorization details object. It MUST not be present
    /// otherwise.
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<Vec<String>>,

    /// A list of name/value pairs identifying claims offered in the Credential.
    /// A value can be another such object (nested data structures), or an array
    /// of objects. Each claim defines language-based display properties for
    /// `credentialSubject` fields.
    ///
    /// N.B. This property is used by the Wallet to specify which claims it is
    /// requesting to be issued out of all the claims the Credential Issuer is
    /// capable of issuing for this particular Credential (data minimization).
    #[serde(rename = "credentialSubject")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_subject: Option<HashMap<String, Claim>>,
}

/// Claim entry. Either a set of nested `Claim`s or a single `ClaimDefinition`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Claim {
    /// A single claim definition.
    Entry(ClaimDefinition),

    /// Nested claims.
    Set(HashMap<String, Claim>),
}

impl Default for Claim {
    fn default() -> Self {
        Self::Entry(ClaimDefinition::default())
    }
}

/// `Claim` requires a custom deserializer as JSON claims are always objects.
/// The A `Claim::Entry` is a single claim definition, while a `Claim::Set` is a
/// set of nested claims.
impl<'de> de::Deserialize<'de> for Claim {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ClaimVisitor;

        impl<'de> Visitor<'de> for ClaimVisitor {
            type Value = Claim;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("Claim")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut entry = ClaimDefinition::default();
                let mut set = HashMap::<String, Claim>::new();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "mandatory" => entry.mandatory = Some(map.next_value()?),
                        "value_type" => entry.value_type = Some(map.next_value()?),
                        "display" => entry.display = Some(map.next_value()?),
                        _ => _ = set.insert(key, map.next_value::<Claim>()?),
                    }
                }

                // empty claims (e.g. "given_name": {}) will always be an `entry`
                if set.is_empty() {
                    Ok(Claim::Entry(entry))
                } else {
                    Ok(Claim::Set(set))
                }
            }
        }

        deserializer.deserialize_map(ClaimVisitor)
    }
}

/// Claim is used to hold language-based display properties for a
/// credentialSubject field.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClaimDefinition {
    /// When true, indicates that the Credential Issuer will always include this
    /// claim in the issued Credential. When false, the claim is not
    /// included in the issued Credential if the wallet did not request the
    /// inclusion of the claim, and/or if the Credential Issuer chose to not
    /// include the claim. If the mandatory parameter is omitted, the
    /// default value is false. Defaults to false.
    //  #[serde(skip_serializing_if = "std::ops::Not::not")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandatory: Option<bool>,

    /// The type of value of the claim. Defaults to string. Supported values
    /// include `string`, `number`, and `image` media types such as
    /// image/jpeg. See [IANA media type registry] for a complete list of
    /// media types.
    ///
    /// [IANA media type registry]: (https://www.iana.org/assignments/media-types/media-types.xhtml#image)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_type: Option<ValueType>,

    /// Language-based display properties of the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<Display>>,
    //
    // /// Nested claims.
    // #[serde(flatten)]
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub nested: Option<HashMap<String, Claim>>,
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
    /// OAuth 2.0 Client
    #[serde(flatten)]
    pub oauth: OAuthClient,

    /// Used by the Wallet to publish its Credential Offer endpoint. The
    /// Credential Issuer should use "`openid-credential-offer://`" if
    /// unable to perform discovery of the endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_offer_endpoint: Option<String>,
}

/// OAuth 2.0 Authorization Server metadata.
/// See RFC 8414 - Authorization Server Metadata
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Server {
    /// OAuth 2.0 Server
    #[serde(flatten)]
    pub oauth: OAuthServer,

    /// Indicates whether the issuer accepts a Token Request with a
    /// Pre-Authorized Code but without a client id. Defaults to false.
    #[serde(rename = "pre-authorized_grant_anonymous_access_supported")]
    pub pre_authorized_grant_anonymous_access_supported: bool,
}

/// Used by the Wallet to notify the Credential Issuer of certain events for
/// issued Credentials. These events enable the Credential Issuer to take
/// subsequent actions after issuance.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct NotificationRequest {
    /// The Credential Issuer for which the notification is intended.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub credential_issuer: String,

    /// A previously issued Access Token, as extracted from the Authorization
    /// header of the Credential Request. Used to grant access to register a
    /// client.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub access_token: String,

    /// As received from the issuer in the Credential Response.
    pub notification_id: String,

    /// Type of the notification event.
    pub event: NotificationEvent,

    /// Human-readable ASCII text providing additional information, used to
    /// assist the Credential Issuer developer in understanding the event
    /// that occurred.
    ///
    /// Values for the `event_description` parameter MUST NOT include characters
    /// outside the set %x20-21 / %x23-5B / %x5D-7E.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_description: Option<String>,
}

/// Used by the Credential Issuer to notify the Wallet of certain events for
/// issued Credentials. These events enable the Wallet to take subsequent
/// actions after issuance.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NotificationEvent {
    /// Credential was successfully stored in the Wallet.
    CredentialAccepted,

    /// Used in all other unsuccessful cases.
    #[default]
    CredentialFailure,

    /// Used when unsuccessful Credential issuance was caused by a user action.
    CredentialDeleted,
}

/// When the Credential Issuer has successfully received the Notification
/// Request from the Wallet, it MUST respond with an HTTP status code in the 2xx
/// range.
///
/// Use of the HTTP status code 204 (No Content) is RECOMMENDED.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct NotificationResponse {}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;

    use super::*;

    #[test]
    fn credential_offer() {
        let offer = CredentialOffer {
            credential_issuer: "https://example.com".into(),
            credential_configuration_ids: vec!["UniversityDegree_JWT".into()],
            grants: None,
        };

        let offer_str = serde_json::to_string(&offer).expect("should serialize to string");
        let offer2: CredentialOffer =
            serde_json::from_str(&offer_str).expect("should deserialize from string");
        assert_eq!(offer, offer2);
    }

    #[test]
    fn authorization_configuration_id() {
        let request = AuthorizationRequest::Object(RequestObject {
            credential_issuer: "https://example.com".into(),
            response_type: oauth::ResponseType::Code,
            client_id: "1234".into(),
            redirect_uri: Some("http://localhost:3000/callback".into()),
            state: Some("1234".into()),
            code_challenge: "1234".into(),
            code_challenge_method: oauth::CodeChallengeMethod::S256,
            authorization_details: Some(vec![AuthorizationDetail {
                type_: AuthorizationDetailType::OpenIdCredential,
                credential: CredentialAuthorization::ConfigurationId {
                    credential_configuration_id: "EmployeeID_JWT".into(),
                    claims: Some(ProfileClaims::W3c(CredentialDefinition {
                        credential_subject: Some(HashMap::from([
                            ("given_name".to_string(), Claim::default()),
                            ("family_name".to_string(), Claim::default()),
                            ("email".to_string(), Claim::default()),
                        ])),
                        ..CredentialDefinition::default()
                    })),
                },
                ..AuthorizationDetail::default()
            }]),
            subject_id: "1234".into(),
            wallet_issuer: Some("1234".into()),

            ..RequestObject::default()
        });

        assert_snapshot!("authorization_configuration_id", request, {
            ".authorization_details" => "[authorization_details]",
        });

        let AuthorizationRequest::Object(object) = &request else {
            panic!("should be an object request");
        };
        assert_snapshot!("authorization_details", object.authorization_details, {
            "[].credential_definition.credentialSubject" => insta::sorted_redaction(),
        });

        let serialized = request.to_string();
        let deserialized = AuthorizationRequest::from_str(&serialized).expect("should parse");
        assert_eq!(request, deserialized);
    }

    #[test]
    fn authorization_format() {
        let request = AuthorizationRequest::Object(RequestObject {
            credential_issuer: "https://example.com".into(),
            response_type: oauth::ResponseType::Code,
            client_id: "1234".into(),
            redirect_uri: Some("http://localhost:3000/callback".into()),
            state: Some("1234".into()),
            code_challenge: "1234".into(),
            code_challenge_method: oauth::CodeChallengeMethod::S256,
            authorization_details: Some(vec![AuthorizationDetail {
                type_: AuthorizationDetailType::OpenIdCredential,
                credential: CredentialAuthorization::Format(FormatIdentifier::JwtVcJson(
                    ProfileW3c {
                        credential_definition: CredentialDefinition {
                            type_: Some(vec![
                                "VerifiableCredential".into(),
                                "EmployeeIDCredential".into(),
                            ]),
                            ..CredentialDefinition::default()
                        },
                    },
                )),

                ..AuthorizationDetail::default()
            }]),
            subject_id: "1234".into(),
            wallet_issuer: Some("1234".into()),

            ..RequestObject::default()
        });

        let serialized = urlencode::to_string(&request).expect("should serialize to string");
        assert_snapshot!("authorization_format", &serialized, {
            ".code" => "[code]",
        });

        let deserialized: AuthorizationRequest =
            urlencode::from_str(&serialized).expect("should deserialize from string");
        assert_eq!(request, deserialized);
    }

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
            credential: CredentialIssuance::Identifier {
                credential_identifier: "EngineeringDegree2023".into(),
            },
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
            credential: CredentialIssuance::Format(FormatIdentifier::JwtVcJson(ProfileW3c {
                credential_definition: CredentialDefinition {
                    type_: Some(vec!["VerifiableCredential".into(), "EmployeeIDCredential".into()]),
                    ..CredentialDefinition::default()
                },
            })),
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
            credential: CredentialIssuance::Identifier {
                credential_identifier: "EngineeringDegree2023".into(),
            },
            proof: Some(Proof::Multiple(MultipleProofs::Jwt(vec![
                "SomeJWT1".into(),
                "SomeJWT2".into(),
            ]))),
            ..CredentialRequest::default()
        };

        let serialized = serde_json::to_value(&request).expect("should serialize to string");
        assert_eq!(json, serialized);
    }
}
