//! # `OpenID` for Verifiable Credential Issuance

use std::collections::HashMap;
use std::io::Cursor;
use std::str::FromStr;

use anyhow::anyhow;
use base64ct::{Base64, Encoding};
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{self, Err};
use crate::metadata::{
    Claim, Client as ClientMetadata, CredentialDefinition, Issuer as IssuerMetadata,
};
use crate::proof::Jwk;
use crate::{err, stringify, Result};

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// TODO: find a home for these shared types

/// Grant Types supported by the Authorization Server.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum GrantType {
    /// The OAuth 2.0 Grant Type for Authorization Code Flow.
    #[cfg_attr(not(feature = "typegen"), serde(rename = "authorization_code"))]
    AuthorizationCode,

    /// The OAuth 2.0 Grant Type for Pre-Authorized Code Flow.
    #[default]
    #[cfg_attr(
        not(feature = "typegen"),
        serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")
    )]
    PreAuthorizedCode,
}

/// The `OpenID4VCI` specification defines commonly used [Credential Format Profiles]
/// to support.  The profiles define Credential format specific parameters or claims
/// used to support a particular format.
///
///
/// [Credential Format Profiles]: (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-format-profiles)
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub enum Format {
    /// A W3C Verifiable Credential.
    ///
    /// When this format is specified, Credential Offer, Authorization Details,
    /// Credential Request, and Credential Issuer metadata, including
    /// `credential_definition` object, MUST NOT be processed using JSON-LD rules.
    #[default]
    #[cfg_attr(not(feature = "typegen"), serde(rename = "jwt_vc_json"))]
    JwtVcJson,

    /// A W3C Verifiable Credential.
    ///
    /// When using this format, data MUST NOT be processed using JSON-LD rules.
    ///
    /// N.B. The `@context` value in the `credential_definition` object can be used by
    /// the Wallet to check whether it supports a certain VC. If necessary, the Wallet
    /// could apply JSON-LD processing to the Credential issued.
    #[cfg_attr(not(feature = "typegen"), serde(rename = "ldp-vc"))]
    LdpVc,

    /// A W3C Verifiable Credential.
    ///
    /// When using this format, data MUST NOT be processed using JSON-LD rules.
    ///
    /// N.B. The `@context` value in the `credential_definition` object can be used by
    /// the Wallet to check whether it supports a certain VC. If necessary, the Wallet
    /// could apply JSON-LD processing to the Credential issued.
    #[cfg_attr(not(feature = "typegen"), serde(rename = "jwt_vc_json-ld"))]
    JwtVcJsonLd,

    /// ISO mDL.
    ///
    /// A Credential Format Profile for Credentials complying with [ISO.18013-5] —
    /// ISO-compliant driving licence specification.
    ///
    /// [ISO.18013-5]: (https://www.iso.org/standard/69084.html)
    #[cfg_attr(not(feature = "typegen"), serde(rename = "mso_mdoc"))]
    MsoDoc,

    /// IETF SD-JWT VC.
    ///
    /// A Credential Format Profile for Credentials complying with
    /// [I-D.ietf-oauth-sd-jwt-vc] — SD-JWT-based Verifiable Credentials for
    /// selective disclosure.
    ///
    /// [I-D.ietf-oauth-sd-jwt-vc]: (https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-01)
    #[cfg_attr(not(feature = "typegen"), serde(rename = "vc+sd-jwt"))]
    VcSdJwt,

    /// W3C Verifiable Credential.
    #[cfg_attr(not(feature = "typegen"), serde(rename = "jwt_vp_json"))]
    JwtVpJson,
}
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

/// Request a Credential Offer for a Credential Issuer.
#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct InvokeRequest {
    /// The URL of the Credential Issuer the Wallet can use obtain offered
    /// Credentials.
    #[serde(skip)]
    pub credential_issuer: String,

    /// A list of credentials (as identified by their metadata ids) to include in the
    /// offer to the Wallet. Each id identifies one of the keys in the name/value
    /// pairs stored in the `credential_configurations_supported` Credential Issuer
    /// metadata property. The Wallet uses this string value to obtain the respective
    /// object that contains information about the Credential being offered. For
    /// example, this string value can be used to obtain scope value to be used in
    /// the Authorization Request.
    pub credential_configuration_ids: Vec<String>,

    /// Whether the Issuer should provide a pre-authorized offer or not. If not
    /// pre-authorized, the Wallet must request authorization to fulfill the
    /// offer.
    /// When set to `true`, only the `urn:ietf:params:oauth:grant-type:pre-authorized_code`
    /// Grant Type will be set in the returned Credential Offer.
    #[serde(rename = "pre-authorize")]
    pub pre_authorize: bool,

    /// Specifies whether a Transaction Code (PIN) is required by the `token` endpoint
    /// during the Pre-Authorized Code Flow.
    pub tx_code_required: bool,

    /// Identifies the (previously authenticated) Holder in order that Issuer can
    /// authorize credential issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder_id: Option<String>,

    /// An ID that the client application wants to be included in callback
    /// payloads. If no ID is provided, callbacks will not be made.
    pub callback_id: Option<String>,
}

/// The response to a Credential Offer request.
#[derive(Debug, Deserialize, Serialize)]
pub struct InvokeResponse {
    /// A Credential Offer object that can be sent to a Wallet as an HTTP GET
    /// request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_offer: Option<CredentialOffer>,

    // LATER: implement credential offer endpoint for vercre-wallet to call back to
    /// The Credential Offer as an HTTP redirect to the Credential Offer Endpoint
    /// URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_offer_uri: Option<String>,

    /// A user PIN that must be provided by the Wallet in order to complete a
    /// credential request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_code: Option<String>,
}

/// A Credential Offer object that can be sent to a Wallet as an HTTP GET
/// request.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialOffer {
    /// The URL of the Credential Issuer, the Wallet is requested to obtain one
    /// or more Credentials from.
    pub credential_issuer: String,

    /// Credentials offered to the Wallet.
    /// A list of names identifying entries in the `credential_configurations_supported`
    /// `HashMap` in the Credential Issuer metadata. The Wallet uses the identifier to
    /// obtain the respective Credential Definition containing information about the
    /// Credential being offered. For example, the identifier can be used to obtain
    /// scope value to be used in the Authorization Request.
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

    /// Indicates to the Wallet the Grant Types the Credential Issuer is prepared to
    /// process for this credential offer. If not present, the Wallet MUST determine
    /// the Grant Types the Credential Issuer supports using the Issuer metadata. When
    /// multiple grants are present, it's at the Wallet's discretion which one to use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grants: Option<Grants>,
}

impl FromStr for CredentialOffer {
    type Err = error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Ok(res) = serde_json::from_str::<Self>(s) else {
            err!(Err::InvalidRequest, "issue deserializing CredentialOffer");
        };
        Ok(res)
    }
}

impl CredentialOffer {
    /// Generate a qrcode for the Credential Offer.
    /// Use the `endpoint` parameter to specify vercre-wallet's endpoint using deep link or
    /// direct call format.
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
    /// Returns an `Err::ServerError` error if error if the Credential Offer cannot
    /// be serialized.
    pub fn to_qrcode(&self, endpoint: &str) -> Result<String> {
        let Ok(qs) = self.to_querystring() else {
            err!("Failed to generate querystring");
        };

        // generate qr code
        let qr_code = match QrCode::new(format!("{endpoint}{qs}")) {
            Ok(s) => s,
            Err(e) => err!(Err::ServerError(e.into()), "Failed to create QR code"),
        };

        // write image to buffer
        let img_buf = qr_code.render::<image::Luma<u8>>().build();
        let mut buffer: Vec<u8> = Vec::new();
        let mut writer = Cursor::new(&mut buffer);
        if let Err(e) = img_buf.write_to(&mut writer, image::ImageFormat::Png) {
            err!(Err::ServerError(e.into()), "Failed to create QR code");
        }

        // base64 encode image
        Ok(format!("data:image/png;base64,{}", Base64::encode_string(buffer.as_slice())))
    }

    /// Generate a query string for the Credential Offer.
    ///
    /// # Errors
    ///
    /// Returns an `Err::ServerError` error if error if the Credential Offer cannot
    /// be serialized.
    pub fn to_querystring(&self) -> Result<String> {
        Ok(serde_qs::to_string(&self)?)
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
    /// Authorization Code Grant Type = "`authorization_code`".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_code: Option<AuthorizationCodeGrant>,

    /// Pre-Authorized Code Grant Type =
    /// "`urn:ietf:params:oauth:grant-type:pre-authorized_code`".
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

    /// To be used by the Wallet to identify the Authorization Server to use with
    /// this grant type when `authorization_servers` parameter in the Credential Issuer
    /// metadata has multiple entries. MUST NOT be used otherwise.
    /// The value of this parameter MUST match with one of the values in the Credential
    /// Issuer `authorization_servers` metadata property.
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

    /// The `tx_code` specifies whether the Authorization Server expects presentation
    /// of a Transaction Code by the End-User along with the Token Request in a
    /// Pre-Authorized Code Flow.
    ///
    /// The Transaction Code binds the Pre-Authorized Code to a certain transaction
    // to prevent replay of this code by an attacker that, for example, scanned the
    /// QR code while standing behind the legitimate End-User.
    ///
    /// It is RECOMMENDED to send the Transaction Code via a separate channel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<TxCode>,

    /// The minimum amount of time in seconds that the Wallet SHOULD wait between
    /// polling requests to the token endpoint (in case the Authorization Server
    /// responds with error code `authorization_pending`). If no value is provided,
    /// Wallets MUST use 5 as the default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<i32>,

    /// To be used by the Wallet to identify the Authorization Server to use with
    /// this grant type when `authorization_servers` parameter in the Credential Issuer
    /// metadata has multiple entries. MUST NOT be used otherwise.
    /// The value of this parameter MUST match with one of the values in the Credential
    /// Issuer `authorization_servers` metadata property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
}

/// Specifies whether the Authorization Server expects presentation of a Transaction
/// Code by the End-User along with the Token Request in a Pre-Authorized Code Flow.
/// If the Authorization Server does not expect a Transaction Code, this object is
/// absent; this is the default.
///
/// The Transaction Code is used to bind the Pre-Authorized Code to a transaction to
/// prevent replay of the code by an attacker that, for example, scanned the QR code
/// while standing behind the legitimate End-User. It is RECOMMENDED to send the Transaction Code via a
/// separate channel. If the Wallet decides to use the Pre-Authorized Code Flow, the
/// Transaction Code value MUST be sent in the `tx_code` parameter with the respective
/// Token Request as defined in Section 6.1. If no length or description is given, this
/// object may be empty, indicating that a Transaction Code is required.
#[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TxCode {
    /// Specifies the input character set. Possible values are "numeric" (only digits)
    /// and "text" (any characters). The default is "numeric".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_mode: Option<String>,

    /// Specifies the length of the Transaction Code. This helps the Wallet to render
    /// the input screen and improve the user experience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<i32>,

    /// Guidance for the Holder of the Wallet on how to obtain the Transaction Code,
    /// e.g., describing over which communication channel it is delivered. The Wallet
    /// is RECOMMENDED to display this description next to the Transaction Code input
    /// screen to improve the user experience. The length of the string MUST NOT exceed
    /// 300 characters. The description does not support internationalization, however
    /// the Issuer MAY detect the Holder's language by previous communication or an HTTP
    /// Accept-Language header within an HTTP GET request for a Credential Offer URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// An Authorization Request is an OAuth 2.0 Authorization Request as defined in
/// section 4.1.1 of [RFC6749], which requests to grant access to the Credential
/// Endpoint.
///
/// [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AuthorizationRequest {
    /// The URL of the Credential Issuer the Wallet can use obtain offered
    /// Credentials.
    #[serde(skip)]
    pub credential_issuer: String,

    /// Authorization Server's response type. Must be "code".
    pub response_type: String,

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
    pub code_challenge_method: String,

    /// Authorization Details is used to convey the details about the
    /// Credentials the Wallet wants to obtain.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "stringify")]
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

    /// A Holder identifier provided by the Wallet. It must have meaning to the
    /// Credential Issuer in order that credentialSubject claims can be
    /// populated.
    // TODO: align this with spec
    pub holder_id: String,

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

/// Authorization Details is used to convey the details about the Credentials
/// the Wallet wants to obtain.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationDetail {
    /// Type determines the authorization details type. MUST be "`openid_credential`".
    #[serde(rename = "type")]
    pub type_: String,

    /// Specifies the unique identifier of the Credential being described in the
    /// `credential_configurations_supported` map in the Credential Issuer Metadata.
    /// REQUIRED when `format` parameter is not set, otherwise MUST NOT be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_configuration_id: Option<String>,

    /// The format of the Credential the Wallet is requesting. The format determines
    /// further authorization details claims needed to identify the Credential type
    /// in the requested format.
    /// REQUIRED when `credential_configuration_id` parameter is not set. MUST NOT be
    /// set if `credential_configuration_id` parameter is set.
    ///
    /// One of "`jwt_vc_json`", "`jwt_vc_json`-ld", "`ldp_vc`", or "`vc+sd-jwt`".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<Format>,

    /// Contains the type values the Wallet requests authorization for at the Credential
    /// Issuer.
    /// REQUIRED if format is "`vc+sd-jwt`", otherwise, it MUST not be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,

    /// Used by the Wallet to indicate which claims it wants to be included in the
    /// issued Credential.
    /// OPTIONAL when format is "`vc+sd-jwt`", otherwise, it MUST not be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<HashMap<String, Claim>>,

    /// The detailed description of the credential type requested. At a minimum,
    /// the Credential Definition 'type' field MUST be set.
    /// REQUIRED when 'format' is "`jwt_vc_json`", "`jwt_vc_json`-ld", or "`ldp_vc`"
    /// AND `format` parameter is set. OPTIONAL otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_definition: Option<CredentialDefinition>,

    // LATER: integrate locations
    /// If the Credential Issuer metadata contains an `authorization_servers` parameter,
    /// the authorization detail's locations field MUST be set to the Credential Issuer
    /// Identifier.
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
    #[serde(skip)]
    pub credential_issuer: String,

    /// OAuth 2.0 Client ID used by the Wallet.
    ///
    /// REQUIRED if the client is not authenticating with the authorization server.
    /// An unauthenticated client MUST send its `client_id` to prevent itself from
    /// inadvertently accepting a code intended for a client with a different
    /// `client_id`.  This protects the client from substitution of the authentication
    /// code.
    pub client_id: String,

    /// The authorization grant type. One of `PreAuthorizedCode` or `AuthorizationCode`.
    pub grant_type: GrantType,

    /// The authorization code received from the authorization server when the
    /// Wallet use the Authorization Code Flow.
    ///
    /// REQUIRED if `grant_type` is "`authorization_code`".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,

    /// The client's redirection endpoint if `redirect_uri` was included in the
    /// authorization request. Only used when `grant_type` is "`authorization_code`".
    ///
    /// REQUIRED if the `redirect_uri` parameter was included in the authorization
    /// request and values MUST be identical.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    /// PKCE code verifier provided by the Wallet when using the Authorization
    /// Code Flow. MUST be able to verify the `code_challenge` provided in
    /// the authorization request. Only set when `grant_type` is
    /// "`authorization_code`".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,

    /// The pre-authorized code provided to the Wallet in a Credential Offer.
    ///
    /// REQUIRED if `grant_type` is "`urn:ietf:params:oauth:grant-type:pre-authorized_code`".
    #[serde(rename = "pre-authorized_code")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_authorized_code: Option<String>,

    /// The user PIN provided during the Credential Offer process. Must be
    /// present if `tx_code` was set to true in the Credential
    /// Offer. Only set when `grant_type` is
    /// "`urn:ietf:params:oauth:grant-type:pre-authorized_code`".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_code: Option<String>,
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

    /// REQUIRED when `authorization_details` parameter is used to request issuance
    /// of a certain Credential type. MUST NOT be used otherwise.

    /// The Authorization Details `credential_identifiers` parameter may be populated
    /// for use in subsequent Credential Requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<TokenAuthorizationDetail>>,

    /// OPTIONAL if identical to the requested scope, otherwise REQUIRED.
    ///
    /// The authorization and token endpoints allow the client to specify the scope
    /// of the access request using the `scope` request parameter.  In turn, the
    /// authorization server uses the `scope` response parameter to inform the client
    /// of the scope of the access token issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
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
/// responses ([`TokenResponse`]). It wraps the `AuthorizationDetail` struct and adds
/// `credential_identifiers` parameter for use in Credential requests.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenAuthorizationDetail {
    /// Reuse (and flatten) the existing [`AuthorizationDetail`] object used in
    /// authorization requests.
    #[serde(flatten)]
    pub authorization_detail: AuthorizationDetail,

    /// Uniquely identify Credentials that can be issued using the Access Token.
    /// Each Credential is described using the same entry in the
    /// `credential_configurations_supported` Credential Issuer metadata, but can
    /// contain different claim values or different subset of claims within the
    /// Credential type claimset. This parameter can be used to simplify the Credential
    /// Request as it can be used to replaces Credential Request format-specific
    /// parameters. When received, the Wallet MUST use these values together with an
    /// Access Token in the subsequent Credential Request(s).
    ///
    /// # Example
    ///
    /// ```json
    /// "credential_identifiers": [
    ///     "CivilEngineeringDegree-2023",
    ///     "ElectricalEngineeringDegree-2023"
    /// ]
    /// ```
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_identifiers: Option<Vec<String>>,
}

/// `CredentialRequest` is used by the Client to make a Credential Request to the
/// Credential Endpoint.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct CredentialRequest {
    /// The URL of the Credential Issuer the Wallet can use obtain offered
    /// Credentials.
    #[serde(skip)]
    pub credential_issuer: String,

    /// A previously issued Access Token, as extracted from the Authorization
    /// header of the Credential Request.
    #[serde(skip)]
    pub access_token: String,

    /// Determines the format of the Credential to be issued, which may determine
    /// the type and any other information related to the Credential to be issued.
    /// Credential Format Profiles consisting of the Credential format specific set
    /// of parameters are defined in Appendix E. When this parameter is used,
    /// `credential_identifier` parameter MUST NOT be present.
    ///
    /// REQUIRED when `credential_identifiers` was not returned from the Token
    /// Response. Otherwise, MUST NOT be used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<Format>,

    /// Wallet's proof of possession of cryptographic key material the issued Credential
    /// will be bound to.
    ///
    /// REQUIRED if the `proof_types_supported` parameter is non-empty and present in
    /// the `credential_configurations_supported` parameter of the Issuer metadata for
    /// the requested Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,

    /// Identifies the Credential being requested. When this parameter is used, the
    /// format parameter and any other Credential format specific set of parameters
    /// MUST NOT be present.
    ///
    /// REQUIRED when a `credential_identifiers` was returned in the Token Response.
    /// MUST NOT be used otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_identifier: Option<String>,

    /// The detailed description of the credential type requested.
    ///
    /// REQUIRED when `format` is "`jwt_vc_json`", "`jwt_vc_json`-ld", or "`ldp_vc`".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_definition: Option<CredentialDefinition>,

    /// If present, specifies how the Credential Response should be encrypted. If not
    /// present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
}

/// Wallet's proof of possession of the key material the issued Credential is to
/// be bound to.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Proof {
    /// Proof type claim denotes the concrete proof type which determines the
    /// further claims in the proof object and associated processing rules.
    /// MUST be "`jwt`" or "`cwt`".
    pub proof_type: String,

    /// The JWT containing the Wallet's proof of possession of key material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt: Option<String>,

    /// The CWT containing the Wallet's proof of possession of key material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwt: Option<String>,
}

/// Claims containing a Wallet's proof of possession of key material that can be
/// used for binding an issued Credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProofClaims {
    /// The `client_id` of the Wallet client making the credential request.
    pub iss: String,

    /// The Credential Issuer URL of the Credential Issuer.
    pub aud: String,

    /// The time at which the proof was issued, as
    /// [RFC7519] `NumericDate`. For example, "1541493724".
    ///
    /// [RFC7519]: (https://www.rfc-editor.org/rfc/rfc7519)
    pub iat: i64,

    /// The nonce value provided by the Credential Issuer.
    pub nonce: String,
}

/// `CredentialResponseEncryption` contains information about whether the Credential
/// Issuer supports encryption of the Credential and Batch Credential Response on
/// top of TLS.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialResponseEncryption {
    /// The public key used for encrypting the Credential Response.
    pub jwk: Jwk,

    /// JWE [RFC7516] alg algorithm [RFC7518] for encrypting Credential Response.
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

/// The Credential Response can be Synchronous or Deferred. The Credential
/// Issuer MAY be able to immediately issue a requested Credential. In other
/// cases, the Credential Issuer MAY NOT be able to immediately issue a
/// requested Credential and will instead return an `acceptance_token` to be
/// used later to retrieve a Credential when it is ready.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
// #[serde(from = "CredentialFormat")]
pub struct CredentialResponse {
    /// The issued Credential. MUST be present when `acceptance_token` is not
    /// returned.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<Value>,

    /// Identifies a Deferred Issuance transaction. This property is set if the
    /// Credential Issuer was unable to immediately issue the credential. The value
    /// can subsequently be used to obtain the respective Credential with the Deferred
    /// Credential Endpoint. It MUST be present when the credential is not returned.
    /// It MUST be invalidated after the credential for which it was meant has been
    /// obtained by the Wallet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,

    /// A nonce to be used to create a proof of possession of key material when
    /// requesting a Credential. When received, the Wallet MUST use this
    /// value for its subsequent credential requests until the Credential
    /// Issuer provides a fresh nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce: Option<String>,

    /// The lifetime in seconds of the `c_nonce` parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce_expires_in: Option<i64>,
}

/// The Batch Credential Endpoint allows a client to send multiple Credential
/// Request objects to request the issuance of multiple credential at the same
/// time.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BatchCredentialRequest {
    /// The URL of the Credential Issuer the Wallet can use obtain offered
    /// Credentials.
    #[serde(skip)]
    pub credential_issuer: String,

    /// A previously issued Access Token, as extracted from the Authorization
    /// header of the Batch Credential Request.
    #[serde(skip)]
    pub access_token: String,

    /// An array of Credential Request objects.
    pub credential_requests: Vec<CredentialRequest>,
}

/// The Batch Credential Response is a JSON object that contains an array of
/// Credential Response objects.
#[derive(Debug, Deserialize, Serialize)]
pub struct BatchCredentialResponse {
    /// An array of Credential Response and/or Deferred Credential Response
    /// objects. Each entry corresponds to the Credential Request object at
    /// the same array index in the `credential_requests` parameter of the
    /// Batch Credential Request.
    pub credential_responses: Vec<CredentialResponse>,

    /// A nonce to be used to create a proof of possession of key material when
    /// requesting a Credential. When received, the Wallet MUST use this
    /// value for its subsequent credential requests until the Credential
    /// Issuer provides a fresh nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce: Option<String>,

    /// The lifetime in seconds of the `c_nonce` parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce_expires_in: Option<i64>,
}

/// An HTTP POST request, which accepts an `acceptance_token` as the only
/// parameter. The `acceptance_token` parameter MUST be sent as Access Token in
/// the HTTP header.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DeferredCredentialRequest {
    /// The URL of the Credential Issuer the Wallet can use obtain offered
    /// Credentials.
    #[serde(skip)]
    pub credential_issuer: String,

    /// A previously issued Access Token, as extracted from the Authorization
    /// header of the Batch Credential Request.
    #[serde(skip)]
    pub access_token: String,

    /// Identifies a Deferred Issuance transaction from an earlier Credential Request.
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
#[derive(Clone, Debug, Default, Deserialize)]
pub struct MetadataRequest {
    /// The Credential Issuer Identifier for which the configuration is to be
    /// returned.
    #[serde(skip)]
    pub credential_issuer: String,

    /// The language(s) set in HTTP Accept-Language Headers. MUST be values defined
    /// in [RFC3066].
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
    pub credential_issuer: IssuerMetadata,
}

/// The registration request.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RegistrationRequest {
    /// The Credential Issuer for which the client is being registered.
    #[serde(skip)]
    pub credential_issuer: String,

    /// A previously issued Access Token, as extracted from the Authorization
    /// header of the Credential Request. Used to grant access to register a
    /// client.
    #[serde(skip)]
    pub access_token: String,

    /// Metadata provided by the client undertaking registration.
    #[serde(flatten)]
    pub client_metadata: ClientMetadata,
}

/// The registration response for a successful request.
#[derive(Debug, Deserialize, Serialize)]
pub struct RegistrationResponse {
    /// Registered Client metadata.
    #[serde(flatten)]
    pub client_metadata: ClientMetadata,
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;

    use super::*;

    #[test]
    fn credential_offer() {
        let offer = CredentialOffer {
            credential_issuer: String::from("https://example.com"),
            credential_configuration_ids: vec![String::from("UniversityDegree_JWT")],
            grants: None,
        };

        let offer_str = serde_json::to_string(&offer).expect("should serialize to string");
        let offer2: CredentialOffer =
            serde_json::from_str(&offer_str).expect("should deserialize from string");
        assert_eq!(offer, offer2);
    }

    #[test]
    fn authorization_request() {
        let auth_req = AuthorizationRequest {
            credential_issuer: String::new(),
            response_type: String::from("code"),
            client_id: String::from("1234"),
            redirect_uri: Some(String::from("http://localhost:3000/callback")),
            state: Some(String::from("1234")),
            code_challenge: String::from("1234"),
            code_challenge_method: String::from("S256"),
            authorization_details: Some(vec![AuthorizationDetail {
                type_: String::from("openid_credential"),
                format: Some(Format::JwtVcJson),
                credential_definition: Some(CredentialDefinition {
                    context: Some(vec![
                        String::from("https://www.w3.org/2018/credentials/v1"),
                        String::from("https://www.w3.org/2018/credentials/examples/v1"),
                    ]),
                    type_: Some(vec![
                        String::from("VerifiableCredential"),
                        String::from("EmployeeIDCredential"),
                    ]),
                    credential_subject: None,
                }),
                ..Default::default()
            }]),
            scope: None,
            resource: None,
            holder_id: String::from("1234"),
            wallet_issuer: Some(String::from("1234")),
            user_hint: None,
            issuer_state: None,
        };

        let auth_req_str = serde_qs::to_string(&auth_req).expect("should serialize to string");
        assert_snapshot!("authzn-ok", &auth_req_str, {
            ".code" => "[code]",
        });

        let auth_req_new = serde_qs::from_str::<AuthorizationRequest>(&auth_req_str)
            .expect("should deserialize from string");
        assert_eq!(auth_req, auth_req_new);
    }
}
