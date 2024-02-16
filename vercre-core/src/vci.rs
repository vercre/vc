//! # `OpenID` for Verifiable Credential Issuance

use std::io::Cursor;
use std::str::FromStr;

use anyhow::anyhow;
use base64ct::{Base64, Encoding};
use image;
use qrcode_rs::QrCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{self, Err};
use crate::metadata::{Client as ClientMetadata, CredentialDefinition, Issuer as IssuerMetadata};
use crate::{err, stringify, Result};

/// Request a Credential Offer for a Credential Issuer.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct InvokeRequest {
    /// The URL of the Credential Issuer the Wallet can use obtain offered
    /// Credentials.
    #[serde(skip)]
    pub credential_issuer: String,

    /// A list of credentials to include in the offer to the Wallet.
    /// An array of strings that each identify one of the keys in the name/value
    /// pairs stored in the 'credentials_supported' Credential Issuer metadata property.
    /// The Wallet uses this string value to obtain the respective object that contains
    /// information about the Credential being offered. For example, this string value
    /// can be used to obtain scope value to be used in the Authorization Request.
    pub credentials: Vec<String>,

    /// Whether the Issuer should provide a pre-authorized offer or not. If not
    /// pre-authorized, the Wallet must request authorization to fulfill the
    /// offer.
    /// When set to 'true', only the 'urn:ietf:params:oauth:grant-type:pre-authorized_code'
    /// Grant Type will be set in the returned Credential Offer.
    #[serde(rename = "pre-authorize")]
    pub pre_authorize: bool,

    /// Whether a user PIN is required in order for the Wallet to complete a
    /// credential request.
    pub user_pin_required: bool,

    /// Identifies the (previously authenticated) Holder to the Issuer for the
    /// in order that they can authorize credential issuance.
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
    pub user_pin: Option<String>,
}

/// A Credential Offer object that can be sent to a Wallet as an HTTP GET
/// request.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialOffer {
    /// The URL of the Credential Issuer, the Wallet is requested to obtain one
    /// or more Credentials from.
    pub credential_issuer: String,

    /// Credentials offered to the Wallet.
    /// A list of names identifying entries in the 'credentials_supported' HashMap
    /// in the Credential Issuer metadata. The Wallet uses the identifier to obtain
    /// the respective Credential Definition containing information about the
    /// Credential being offered. For example, the identifier can be used to obtain
    /// scope value to be used in the Authorization Request.
    ///
    /// # Example
    ///
    /// ```json
    ///    "credentials": [
    ///       "UniversityDegree_JWT",
    ///       "org.iso.18013.5.1.mDL"
    ///    ],
    /// ```
    pub credentials: Vec<String>,

    /// Indicates to the Wallet the Grant Types the Credential Issuer is
    /// prepared to process for this credential offer.
    /// If not present, the Wallet MUST determine the Grant Types the Credential
    /// Issuer supports using the Issuer metadata. When multiple grants are
    /// present, it's at the Wallet's discretion which one to use.
    pub grants: Option<Grants>,
}

impl FromStr for CredentialOffer {
    type Err = error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Ok(res) = serde_json::from_str::<CredentialOffer>(s) else {
            err!(Err::InvalidRequest, "issue deserializing CredentialOffer");
        };
        Ok(res)
    }
}

impl CredentialOffer {
    /// Generate qrcode for the Credential Offer.
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
        if let Err(e) = img_buf.write_to(&mut writer, image::ImageOutputFormat::Png) {
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
    /// Authorization Code Grant Type: authorization_code.
    pub authorization_code: Option<AuthorizationCodeGrant>,

    /// Pre-Authorized Code Grant Type:
    /// `urn:ietf:params:oauth:grant-type:pre-authorized_code`.
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
    /// this grant type when authorization_servers parameter in the Credential Issuer
    /// metadata has multiple entries. MUST NOT be used otherwise.
    /// The value of this parameter MUST match with one of the values in the Credential
    /// Issuer 'authorization_servers' metadata property.
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

    /// Specifies whether the Issuer expects presentation of a user PIN along
    /// with the Token Request in the Pre-Authorized Code Flow.
    /// The PIN is used to prevent replay of the code by an attacker that, for
    /// example, scanned the QR code while standing behind the legitimate
    /// user. It is RECOMMENDED the PIN be sent via a separate channel. If
    /// the Wallet decides to use the Pre-Authorized Code Flow, a PIN value
    /// MUST be sent in the user_pin parameter with the respective Token
    /// Request.
    /// Default is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_pin_required: Option<bool>,

    /// The minimum amount of time in seconds that the Wallet SHOULD wait between
    /// polling requests to the token endpoint (in case the Authorization Server
    /// responds with error code 'authorization_pending'). If no value is provided,
    /// Wallets MUST use 5 as the default.
    pub interval: Option<i32>,

    /// To be used by the Wallet to identify the Authorization Server to use with
    /// this grant type when authorization_servers parameter in the Credential Issuer
    /// metadata has multiple entries. MUST NOT be used otherwise.
    /// The value of this parameter MUST match with one of the values in the Credential
    /// Issuer 'authorization_servers' metadata property.
    pub authorization_server: Option<String>,
}

/// An Authorization Request is an OAuth 2.0 Authorization Request as defined in
/// section 4.1.1 of [RFC6749], which requests to grant access to the Credential
/// Endpoint.
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,

    /// A Holder identifier provided by the Wallet. It must have meaning to the
    /// Credential Issuer in order that credentialSubject claims can be
    /// populated.
    // TODO: align this with spec
    pub holder_id: String,

    /// The Wallet's `OpenID` Connect issuer URL. The Credential Issuer can use
    /// the discovery process as defined in [SIOPv2] to determine the
    /// Wallet's capabilities and endpoints. RECOMMENDED in Dynamic
    /// Credential Requests.
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
    /// Type determines the authorization details type. MUST be
    /// "openid_credential".
    #[serde(rename = "type")]
    pub type_: String,

    /// The format in which the Credential is requested to be issued. The format
    /// determines further claims in the authorization details object specifically
    /// used to identify the Credential type to be issued.
    ///
    /// One of "jwt_vc_json", "jwt_vc_json-ld", or "ldp_vc".
    pub format: String,

    /// REQUIRED when 'format' is "jwt_vc_json", "jwt_vc_json-ld", or "ldp_vc".
    /// The detailed description of the credential type requested. At a minimum,
    /// the Credential Definition 'type' field MUST be set.
    pub credential_definition: CredentialDefinition,

    // LATER: integrate locations
    /// If the Credential Issuer metadata contains an 'authorization_servers' parameter,
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

    /// Uniquely identify Credentials that can be issued using Access Token.
    /// Each Credential is described using the same entry in the 'credentials_supported'
    /// Credential Issuer metadata, but can contain different claim values or different
    /// subset of claims within the Credential type claimset.
    /// This parameter can be used to simplify the Credential Request as it can be used to
    /// replaces Credential Request format specific parameters.
    /// When received, the Wallet MUST use these values together with an Access Token
    /// in the subsequent Credential Request(s).
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

/// Authorization Response as defined in [RFC6749].
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
    /// An unauthenticated client MUST send its "client_id" to prevent itself from
    /// inadvertently accepting a code intended for a client with a different
    /// "client_id".  This protects the client from substitution of the authentication
    /// code.
    pub client_id: String,

    /// The authorization grant type. One of:
    ///  - "authorization_code"
    ///  - "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    pub grant_type: String,

    /// The authorization code received from the authorization server when the
    /// Wallet use the Authorization Code Flow.
    ///
    /// REQUIRED if grant_type is "authorization_code".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,

    /// The client's redirection endpoint if `redirect_uri` was included in the
    /// authorization request. Only used when grant_type is "authorization_code".
    ///
    /// REQUIRED if the "redirect_uri" parameter was included in the authorization
    /// request and values MUST be identical.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    /// PKCE code verifier provided by the Wallet when using the Authorization
    /// Code Flow. MUST be able to verify the `code_challenge` provided in
    /// the authorization request. Only set when grant_type is
    /// "authorization_code".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,

    /// The pre-authorized code provided to the Wallet in a Credential Offer.
    ///
    /// REQUIRED if grant_type is "urn:ietf:params:oauth:grant-type:pre-authorized_code".
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: Option<String>,

    /// The user PIN provided during the Credential Offer process. Must be
    /// present if user_pin_required was set to true in the Credential
    /// Offer. Only set when grant_type is
    /// "urn:ietf:params:oauth:grant-type:pre-authorized_code".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_pin: Option<String>,
}

/// Token Response as defined in [RFC6749].
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TokenResponse {
    /// An OAuth 2.0 Access Token that can subsequently be used to request one
    /// or more Credentials.
    pub access_token: String,

    /// The type of the token issued. Must be "Bearer".
    pub token_type: String,

    /// The lifetime in seconds of the access token.
    pub expires_in: i64,

    /// A nonce to be used by the Wallet to create a proof of possession of key
    /// material when requesting credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce: Option<String>,

    /// Lifetime in seconds of the c_nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce_expires_in: Option<i64>,

    /// REQUIRED when authorization_details parameter is used to request issuance
    /// of a certain Credential type. MUST NOT be used otherwise.
    ///
    /// The Authorization Details 'credential_identifiers' parameter may be populated
    /// for use in subsequent Credential Requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<AuthorizationDetail>>,

    /// OPTIONAL if identical to the requested scope, otherwise REQUIRED.
    ///
    /// The authorization and token endpoints allow the client to specify the scope
    /// of the access request using the "scope" request parameter.  In turn, the
    /// authorization server uses the "scope" response parameter to inform the client
    /// of the scope of the access token issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
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

    /// REQUIRED when a 'credential_identifier' was returned in the Token Response.
    /// MUST NOT be used otherwise.
    ///
    /// Identifies the Credential being requested. When this parameter is used, the
    /// format parameter and any other Credential format specific set of parameters
    /// MUST NOT be present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_identifier: Option<String>,

    /// REQUIRED when 'credential_identifier' was not returned from the Token
    /// Response. Otherwise, MUST NOT be used.
    ///
    /// Determines the format of the Credential to be issued, which may determine
    /// the type and any other information related to the Credential to be issued.
    /// Credential Format Profiles consisting of the Credential format specific set
    /// of parameters are defined in Appendix E. When this parameter is used,
    /// 'credential_identifier' parameter MUST NOT be present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// REQUIRED when 'format' is "jwt_vc_json", "jwt_vc_json-ld", or "ldp_vc".
    ///
    /// The detailed description of the credential type requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_definition: Option<CredentialDefinition>,

    /// Wallet's proof of possession of cryptographic key material the issued Credential
    /// will be bound to.
    pub proof: Proof,

    /// A public key as a JWK to be used for encrypting the Credential Response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_encryption_jwk: Option<Value>,

    /// JWE [RFC7516] alg algorithm [RFC7518] REQUIRED for encrypting Credential
    /// Responses. If omitted, no encryption is intended to be performed. When present,
    /// the 'credential_encryption_jwk' MUST also be present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption_alg: Option<String>,

    /// JWE [RFC7516] enc algorithm [RFC7518] REQUIRED for encrypting Credential
    /// Responses. If credential_response_encryption_alg is specified, the default for
    /// this value is A256GCM. When credential_response_encryption_enc is included,
    /// 'credential_response_encryption_alg' MUST also be provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption_enc: Option<String>,
}

/// Wallet's proof of possession of the key material the issued Credential is to
/// be bound to.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Proof {
    /// Proof type claim denotes the concrete proof type which determines the
    /// further claims in the proof object and associated processing rules.
    /// MUST be "jwt" or "cwt".
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
    /// The client_id of the Wallet client making the credential request.
    pub iss: String,

    /// The Credential Issuer URL of the Credential Issuer.
    pub aud: String,

    /// The time at which the proof was issued, as [RFC7519] NumericDate.
    /// For example, "1541493724".
    pub iat: i64,

    /// The nonce value provided by the Credential Issuer.
    pub nonce: String,
}

/// The Credential Response can be Synchronous or Deferred. The Credential
/// Issuer MAY be able to immediately issue a requested Credential. In other
/// cases, the Credential Issuer MAY NOT be able to immediately issue a
/// requested Credential and will instead return an `acceptance_token` to be
/// used later to retrieve a Credential when it is ready.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
// #[serde(from = "CredentialFormat")]
pub struct CredentialResponse {
    /// Used to denote the format of the issued Credential. One of
    /// "jwt_vc_json", "jwt_vc_json-ld", or "ldp_vc".
    pub format: Option<String>,

    /// The issued Credential. MUST be present when `acceptance_token` is not
    /// returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
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
            credential_issuer: "https://example.com".to_string(),
            credentials: vec!["UniversityDegree_JWT".to_string()],
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
            response_type: "code".to_string(),
            client_id: "1234".to_string(),
            redirect_uri: Some("http://localhost:3000/callback".to_string()),
            state: Some("1234".to_string()),
            code_challenge: "1234".to_string(),
            code_challenge_method: "S256".to_string(),
            authorization_details: Some(vec![AuthorizationDetail {
                type_: "openid_credential".to_string(),
                format: "jwt_vc_json".to_string(),
                credential_definition: CredentialDefinition {
                    context: Some(vec![
                        "https://www.w3.org/2018/credentials/v1".to_string(),
                        "https://www.w3.org/2018/credentials/examples/v1".to_string(),
                    ]),
                    type_: vec![
                        "VerifiableCredential".to_string(),
                        "EmployeeIDCredential".to_string(),
                    ],
                    credential_subject: None,
                },
                locations: None,
                credential_identifiers: None,
            }]),
            scope: None,
            resource: None,
            holder_id: "1234".to_string(),
            wallet_issuer: Some("1234".to_string()),
            user_hint: None,
            issuer_state: None,
        };

        let auth_req_str = serde_qs::to_string(&auth_req).expect("should serialize to string");
        assert_snapshot!("authzn-ok", auth_req_str, {
            ".code" => "[code]",
        });

        let auth_req_new = serde_qs::from_str::<AuthorizationRequest>(&auth_req_str)
            .expect("should deserialize from string");
        assert_eq!(auth_req, auth_req_new);
    }
}
