//! # `OpenID` for Verifiable Presentations (`OpenID4VP`)

use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;
use std::future::Future;
use std::io::Cursor;

use anyhow::anyhow;
use base64ct::{Base64, Encoding};
use credibil_did::DidResolver;
pub use credibil_infosec::Signer;
use qrcode::QrCode;
use serde::de::{self, Deserializer, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

use super::provider::{Result, StateStore};
use crate::core::{Kind, urlencode};
use crate::dif_exch::{InputDescriptor, PresentationDefinition, PresentationSubmission};
use crate::openid::oauth::{OAuthClient, OAuthServer};
use crate::w3c_vc::model::VerifiablePresentation;

/// Verifier Provider trait.
pub trait Provider: Metadata + StateStore + Signer + DidResolver + Clone {}

/// The `Metadata` trait is used by implementers to provide `Verifier` (client)
/// metadata to the library.
pub trait Metadata: Send + Sync {
    /// Verifier (Client) metadata for the specified verifier.
    fn verifier(&self, verifier_id: &str) -> impl Future<Output = Result<Verifier>> + Send;

    /// Wallet (Authorization Server) metadata.
    fn wallet(&self, wallet_id: &str) -> impl Future<Output = Result<Wallet>> + Send;

    /// Used by OAuth 2.0 clients to dynamically register with the authorization
    /// server.
    fn register(&self, verifier: &Verifier) -> impl Future<Output = Result<Verifier>> + Send;
}

/// The Request Object Request is created by the Verifier to generate an
/// Authorization Request Object.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct CreateRequestRequest {
    #[allow(rustdoc::bare_urls)]
    /// The Verifier ID. It MUST be a valid URI. For example,
    /// `"https://credibil.io"` or `"did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg"`.
    pub client_id: String,

    /// The reason the Verifier is requesting the Verifiable Presentation.
    pub purpose: String,

    /// Input Descriptors describing the information required from the
    /// Holder.
    pub input_descriptors: Vec<InputDescriptor>,

    /// The Verifier can specify whether Authorization Requests and Responses
    /// are to be passed between endpoints on the same device or across devices
    pub device_flow: DeviceFlow,

    /// The Client ID
    pub client_id_scheme: String,
}

/// Used to specify whether Authorization Requests and Responses are to be
/// passed between endpoints on the same device or across devices
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum DeviceFlow {
    /// With the cross-device flow the Verifier renders the Authorization
    /// Request as a QR Code which the User scans with the Wallet. In
    /// response, the Verifiable Presentations are sent to a URL controlled
    /// by the Verifier using HTTPS POST.
    ///
    /// To initiate this flow, the Verifier specifies a Response Type of
    /// "`vp_token`" and a Response Mode of "`direct_post`" in the Request
    /// Object.
    ///
    /// In order to keep the size of the QR Code small and be able to sign and
    /// optionally encrypt the Request Object, the Authorization Request only
    /// contains a Request URI which the wallet uses to retrieve the actual
    /// Authorization Request data.
    ///
    /// It is RECOMMENDED that Response Mode "`direct_post`" and `request_uri`
    /// are used for cross-device flows, as Authorization Request size might
    /// be large and may not fit in a QR code.
    #[default]
    CrossDevice,

    /// The same-device flow uses HTTP redirects to pass Authorization Request
    /// and Response between Verifier and Wallet. Verifiable Presentations
    /// are returned to the Verifier in the fragment part of the redirect
    /// URI, when the Response Mode is "`fragment`".
    SameDevice,
}

/// The response to the originator of the Request Object Request.
// TODO: Should this be an enum?
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CreateRequestResponse {
    /// The generated Authorization Request Object, ready to send to the Wallet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object: Option<RequestObject>,

    /// A URI pointing to a location where the Authorization Request Object can
    /// be retrieved by the Wallet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uri: Option<String>,
}

impl CreateRequestResponse {
    /// Convenience method to convert the `CreateRequestResponse` to a QR code.
    ///
    /// If the `request_object` is set, the method will generate a QR code for
    /// that in favour of the `request_uri`.
    ///
    /// TODO: Revisit the logic to determine default type if this struct is made
    /// an enum.
    ///
    /// # Errors
    /// Returns an error if the neither the `request_object` nor `request_uri` is
    /// set or the respective field cannot be represented as a base64-encoded PNG
    /// image of a QR code.
    pub fn to_qrcode(&self, endpoint: Option<&str>) -> anyhow::Result<String> {
        if let Some(req_obj) = &self.request_object {
            let Some(endpoint) = endpoint else {
                return Err(anyhow!("no endpoint provided for object-type response"));
            };
            req_obj.to_qrcode(endpoint)
        } else {
            let Some(request_uri) = &self.request_uri else {
                return Err(anyhow!("response has no request object or request uri"));
            };
            // generate qr code
            let qr_code =
                QrCode::new(request_uri).map_err(|e| anyhow!("Failed to create QR code: {e}"))?;

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
    }
}

/// The Authorization Request follows the definition given in [RFC6749].
///
/// The Verifier may send an Authorization Request as Request Object by value or
/// by reference as defined in JWT-Secured Authorization Request (JAR)
/// [RFC9101].
///
/// [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
/// [RFC9101]:https://www.rfc-editor.org/rfc/rfc9101
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RequestObject {
    /// The type of response expected from the Wallet (as Authorization Server).
    ///
    /// If Response Type is:
    ///  - "`vp_token`": a VP Token is returned in an Authorization Response.
    ///  - "`vp_token id_token`" AND the `scope` parameter contains "`openid`":
    ///    a VP Token and a Self-Issued ID Token are returned in an
    ///    Authorization Response.
    ///  - "`code`": a VP Token is returned in a Token Response.
    ///
    /// The default Response Mode is "fragment": response parameters are encoded
    /// in the fragment added to the `redirect_uri` when redirecting back to the
    /// Verifier.
    pub response_type: ResponseType,

    /// The Verifier ID. MUST be a valid URI.
    pub client_id: String,

    /// The URI to redirect to the Verifier's redirection endpoint as
    /// established during client registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    /// While the `response_type` parameter informs the Authorization Server
    /// (Wallet) of the desired authorization flow, the `response_mode`
    /// parameter informs it of the mechanism to use when returning an
    /// Authorization Response.
    ///
    /// A Response Mode of "`direct_post`" allows the Wallet to send the
    /// Authorization Response to an endpoint controlled by the Verifier as
    /// an HTTPS POST request.
    ///
    /// If not set, the default value is "`fragment`".
    ///
    /// Response parameters are returned using the
    /// "application/x-www-form-urlencoded" content type. The flow can end
    /// with an HTTPS POST request from the Wallet to the Verifier, or it
    /// can end with a redirect that follows the HTTPS POST request,
    /// if the Verifier responds with a redirect URI to the Wallet.
    ///
    /// Response Mode "`direct_post.jwt`" causes the Wallet to send the
    /// Authorization Response as an HTTPS POST request (as for
    /// "`direct_post`") except the Wallet sets a `response` parameter to a
    /// JWT containing the Authorization Response. See [JARM] for more
    /// detail.
    ///
    /// [JARM]: (https://openid.net/specs/oauth-v2-jarm-final.html)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,

    /// OPTIONAL. MUST be set when the Response Mode "`direct_post`" is used.
    ///
    /// The URI to which the Wallet MUST send the Authorization Response using
    /// an HTTPS POST request as defined by the Response Mode
    /// "`direct_post`".
    ///
    /// When `response_uri` is set, `redirect_uri` MUST NOT be set. If set when
    /// Response Mode is "`direct_post`", the Wallet MUST return an
    /// "`invalid_request`" error.
    ///
    /// Note: If the Client Identifier scheme `redirect_uri` is used in
    /// conjunction with the Response Mode "`direct_post`", and the
    /// `response_uri` parameter is present, the `client_id` value MUST be
    /// equal to the `response_uri` value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_uri: Option<String>,

    /// The Wallet MAY allow Verifiers to request presentation of Verifiable
    /// Credentials by utilizing a pre-defined scope value. Defined in
    /// [RFC6749].
    ///
    /// [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// The nonce is used to securely bind the requested Verifiable
    /// Presentation(s) provided by the Wallet to the particular
    /// transaction. Returned in the VP's Proof.challenge parameter.
    pub nonce: String,

    /// State is used to maintain state between the Authorization Request and
    /// subsequent callback from the Wallet ('Authorization Server').
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// The Presentation Definition
    pub presentation_definition: Kind<PresentationDefinition>,

    /// The `client_id_scheme` is used to specify how the Wallet should to
    /// obtain and validate Verifier metadata. The following values indicate
    /// how the Wallet should interpret the value of the `client_id`
    /// parameter.
    ///
    /// - If not set, the Wallet MUST behave as specified in [RFC6749].
    /// - If the same Client Identifier is used with different Client Identifier
    ///   schemes, those occurences MUST be treated as different Verifiers. The
    ///   Verifier needs to determine which Client Identifier schemes the Wallet
    ///   supports prior to sending the Authorization Request in order to choose
    ///   a supported scheme.
    ///
    /// [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
    /// [RFC5280]: (https://www.rfc-editor.org/rfc/rfc5280)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_scheme: Option<ClientIdScheme>,

    /// Client Metadata contains Verifier metadata values.
    pub client_metadata: Verifier,
}

/// The type of response expected from the Wallet (as Authorization Server).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum ResponseType {
    /// A VP Token is returned in an Authorization Response
    #[default]
    #[serde(rename = "vp_token")]
    VpToken,

    /// A VP Token and a Self-Issued ID Token are returned in an Authorization
    /// Response (if `scope` is set to "openid").
    #[serde(rename = "vp_token id_token")]
    VpTokenIdToken,

    /// A VP Token is returned in a Token Response
    #[serde(rename = "code")]
    Code,
}

/// The type of response expected from the Wallet (as Authorization Server).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum ClientIdScheme {
    /// The Client Identifier is the redirect URI (or response URI).
    /// The Authorization Request MUST NOT be signed, the Verifier MAY omit the
    /// `redirect_uri` parameter, and all Verifier metadata parameters MUST be
    /// passed using the `client_metadata` parameter.
    /// If used in conjunction with the Response Mode "`direct_post`", and the
    /// `response_uri` parameter is present, the `client_id` value MUST be equal
    /// to the `response_uri` value.
    #[default]
    #[serde(rename = "redirect_uri")]
    RedirectUri,

    /// The Client Identifier is a DID.
    /// The request MUST be signed with a private key associated with the DID. A
    /// public key to verify the signature MUST be obtained from the
    /// `verificationMethod` property of a DID Document. Since DID Document may
    /// include multiple public keys, a particular public key used to sign the
    /// request in question MUST be identified by the `kid` in the JOSE Header.
    /// To obtain the DID Document, the Wallet MUST use DID  Resolution defined
    /// by the DID method used by the Verifier. All Verifier metadata other than
    /// the public key MUST be obtained from the `client_metadata` parameter.
    #[serde(rename = "did")]
    Did,
    // ---------------------------------------------------------------------
    // Unsupported schemes
    // ---------------------------------------------------------------------
    // /// The Verifier authenticates using a JWT.
    // /// The Client Identifier MUST equal the `sub` claim value in the Verifier
    // /// attestation JWT. The request MUST be signed with the private key corresponding
    // /// to the public key in the `cnf` claim in the Verifier attestation JWT. This
    // /// serves as proof of possesion of this key. The Verifier attestation JWT MUST be
    // /// added to the `jwt` JOSE Header of the request object. The Wallet
    // /// MUST validate the signature on the Verifier attestation JWT. The `iss` claim
    // /// of the Verifier Attestation JWT MUST identify a party the Wallet trusts
    // /// for issuing Verifier Attestation JWTs. If the Wallet cannot establish trust,
    // /// it MUST refuse the request. If the issuer of the Verifier Attestation JWT
    // /// adds a `redirect_uris` claim to the attestation, the Wallet MUST ensure the
    // /// `redirect_uri` request parameter value exactly matches one of the `redirect_uris`
    // /// claim entries. All Verifier metadata other than the public key MUST be
    // /// obtained from the `client_metadata`.
    // #[serde(rename = "verifier_attestation")]
    // VerifierAttestation,

    // /// The Client Identifier is already known to the Wallet.
    // /// This value represents the [RFC6749] default behavior, i.e. the Client
    // /// Identifier needs to be known to the Wallet in advance of the Authorization
    // /// Request. Verifier metadata is obtained from metadata endpoint
    // /// [RFC7591] or out-of-band an mechanism.
    // #[serde(rename = "pre-registered")]
    // PreRegistered,

    // /// The Client Identifier is an OpenID.Federation Entity ID.
    // /// OpenID.Federation processing rules are followed, OpenID.Federation automatic
    // /// registration is used, the request may contain a `trust_chain` parameter, the
    // /// Wallet only obtains Verifier metadata from Entity Statement(s),
    // /// `client_metadata`.
    // #[serde(rename = "entity_id")]
    // EntityId,

    // /// The Client Identifier is a DNS name.
    // /// The DNS name MUST match a dNSName Subject Alternative Name (SAN) [RFC5280]
    // /// entry in the leaf certificate passed with the request.
    // #[serde(rename = "x509_san_dns")]
    // X509SanDns,

    // /// The Client Identifier is a URI.
    // /// The URI MUST match a uniformResourceIdentifier Subject Alternative Name (SAN)
    // /// [RFC5280] entry in the leaf certificate passed with the request.
    // #[serde(rename = "x509_san_uri")]
    // X509SanUri,
}

// /// The type of Presentation Definition returned by the `RequestObject`:
// either an object /// or a URI.
// #[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
// #[allow(clippy::module_name_repetitions)]
// pub enum PresentationDefinitionType {
//     /// A Presentation Definition object embedded in the `RequestObject`.
//     #[serde(rename = "presentation_definition")]
//     Object(PresentationDefinition),

//     /// A URI pointing to where a Presentation Definition object can be
//     /// retrieved. This parameter MUST be set when neither
//     /// `presentation_definition` nor a Presentation Definition scope value
//     /// are set.
//     #[serde(rename = "presentation_definition_uri")]
//     Uri(String),
// }

// impl Default for PresentationDefinitionType {
//     fn default() -> Self {
//         Self::Object(PresentationDefinition::default())
//     }
// }

impl RequestObject {
    /// Generate qrcode for Request Object.
    /// Use the `endpoint` parameter to specify the Wallet's endpoint using deep
    /// link or direct call format.
    ///
    /// For example,
    ///
    /// ```http
    ///   openid-vc://?request_uri=
    ///   or GET https://holder.wallet.io/authorize?
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an `Error::ServerError` error if the Request Object cannot be
    /// serialized.
    pub fn to_qrcode(&self, endpoint: &str) -> Result<String> {
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

    /// Generate a query string for the Request Object.
    ///
    /// # Errors
    ///
    /// Returns an `Error::ServerError` error if the Request Object cannot be
    /// serialized.
    pub fn to_querystring(&self) -> Result<String> {
        urlencode::to_string(self).map_err(|e| anyhow!("issue creating query string: {e}"))
    }
}

/// The Request Object Request is used (indirectly) by the Wallet to retrieve a
/// previously generated Authorization Request Object.
///
/// The Wallet is sent a `request_uri` containing a unique URL pointing to the
/// Request Object. The URI has the form `client_id/request/state_key`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct RequestObjectRequest {
    /// The ID of the Verifier to retrieve the Authorization Request Object for.
    #[serde(default)]
    pub client_id: String,

    /// The unique identifier of the the previously generated Request Object.
    pub id: String,
}

/// The Request Object Response returns a previously generated Authorization
/// Request Object.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestObjectResponse {
    /// The Authorization Request Object generated by the `request` endpoint
    /// either as an object or serialised to a JWT.
    pub request_object: RequestObjectType,
}

/// The type of Authorization Request Object returned in the `RequestObject`:
/// either an object or a JWT.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum RequestObjectType {
    /// The repsonse contains an Authorization Request Object objet.
    #[serde(rename = "request_object")]
    Object(RequestObject),

    /// The response contains an Authorization Request Object encoded as a JWT.
    #[serde(rename = "jwt")]
    Jwt(String),
}

impl Default for RequestObjectType {
    fn default() -> Self {
        Self::Object(RequestObject::default())
    }
}

/// Serialize to 'unwrapped' JWT if Request Object is JWT (`jwt parameter is
/// set`).
impl Serialize for RequestObjectResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.request_object {
            RequestObjectType::Object(_) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("request_object", &self.request_object)?;
                map.end()
            }
            RequestObjectType::Jwt(jwt) => jwt.serialize(serializer),
        }
    }
}

/// Deserialize from JSON or 'unwrapped' JWT if Request Object is JWT.
impl<'de> Deserialize<'de> for RequestObjectResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VisitorImpl;

        impl<'de> Visitor<'de> for VisitorImpl {
            type Value = RequestObjectResponse;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a RequestObjectResponse or JWT")
            }

            fn visit_str<E>(self, value: &str) -> Result<RequestObjectResponse, E>
            where
                E: de::Error,
            {
                Ok(RequestObjectResponse {
                    request_object: RequestObjectType::Jwt(value.to_string()),
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<RequestObjectResponse, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut resp = RequestObjectResponse::default();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "request_object" => {
                            resp.request_object = RequestObjectType::Object(map.next_value()?);
                        }
                        "jwt" => resp.request_object = RequestObjectType::Jwt(map.next_value()?),
                        _ => {
                            return Err(de::Error::unknown_field(&key, &["request_object", "jwt"]));
                        }
                    }
                }

                Ok(resp)
            }
        }

        deserializer.deserialize_any(VisitorImpl)
    }
}

/// Authorization Response request object is used by Wallets to send a VP Token
/// and Presentation Submission to the Verifier who initiated the verification.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ResponseRequest {
    /// One or more Verifiable Presentations represented as base64url encoded
    /// strings and/or JSON objects. The VP format determines the encoding.
    /// The encoding follows the same format-based rules as for Credential
    /// issuance (Appendix E of the [OpenID4VCI] specification).
    ///
    /// When a single Verifiable Presentation is returned, array syntax MUST NOT
    /// be used.
    ///
    /// [OpenID4VCI]: (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_token: Option<Vec<Kind<VerifiablePresentation>>>,

    /// The `presentation_submission` element as defined in
    /// [DIF.PresentationExchange]. It contains mappings between the
    /// requested Verifiable Credentials and where to find them within the
    /// returned VP Token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation_submission: Option<PresentationSubmission>,

    /// The client state value from the Authorization Request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

impl ResponseRequest {
    /// Create a `HashMap` representation of the `ResponseRequest` suitable for
    /// use in an HTML form post.
    ///
    /// # Errors
    /// Will return an error if any nested objects cannot be serialized and
    /// URL-encoded.
    pub fn form_encode(&self) -> anyhow::Result<HashMap<String, String>> {
        let mut map = HashMap::new();
        if let Some(vp_token) = &self.vp_token {
            let as_json = serde_json::to_string(vp_token)?;
            map.insert("vp_token".into(), urlencoding::encode(&as_json).to_string());
        }
        if let Some(presentation_submission) = &self.presentation_submission {
            let as_json = serde_json::to_string(presentation_submission)?;
            map.insert("presentation_submission".into(), urlencoding::encode(&as_json).to_string());
        }
        if let Some(state) = &self.state {
            map.insert("state".into(), state.into());
        }
        Ok(map)
    }

    /// Create a `ResponseRequest` from a `HashMap` representation.
    ///
    /// Suitable for
    /// use in a verifier's response endpoint that receives a form post before
    /// passing the `ResponseRequest` to the `response` handler.
    ///
    /// # Errors
    /// Will return an error if any nested objects cannot be deserialized from
    /// URL-encoded JSON strings.
    pub fn form_decode(map: &HashMap<String, String>) -> anyhow::Result<Self> {
        let mut req = Self::default();
        if let Some(vp_token) = map.get("vp_token") {
            let decoded = urlencoding::decode(vp_token)?;
            let vp_token: Vec<Kind<VerifiablePresentation>> = serde_json::from_str(&decoded)?;
            req.vp_token = Some(vp_token);
        }
        if let Some(presentation_submission) = map.get("presentation_submission") {
            let decoded = urlencoding::decode(presentation_submission)?;
            let presentation_submission: PresentationSubmission = serde_json::from_str(&decoded)?;
            req.presentation_submission = Some(presentation_submission);
        }
        if let Some(state) = map.get("state") {
            req.state = Some(state.to_string());
        }
        Ok(req)
    }
}

/// Authorization Response response object is used to return a `redirect_uri` to
/// the Wallet following successful processing of the presentation submission.
#[derive(Debug, Deserialize, Serialize)]
pub struct ResponseResponse {
    /// When the redirect parameter is used the Wallet MUST send the User Agent
    /// to the provided URI. The redirect URI allows the Verifier to
    /// continue the interaction with the End-User on the device where the
    /// Wallet resides after the Wallet has sent the Authorization Response.
    /// It especially enables the Verifier to prevent session fixation
    /// attacks.
    ///
    /// The URI — an absolute URI — is chosen by the Verifier. It MUST include a
    /// fresh, cryptographically random number to ensure only the receiver
    /// of the redirect can fetch and process the Authorization Response.
    /// The number could be added as a path component or a parameter to the
    /// URL. It is RECOMMENDED to use a cryptographic random value of 128
    /// bits or more.
    ///
    /// # Example
    ///
    /// ```http
    /// redirect_uri": "https://client.example.org/cb#response_code=091535f699ea575c7937fa5f0f454aee"
    /// ```
    /// If the response does not contain a parameter, the Wallet is not required
    /// to perform any further steps.
    pub redirect_uri: Option<String>,

    /// A cryptographically random number with sufficient entropy used to link
    /// the Authorization Response to the Authorization Request. The
    /// `response_code` is returned to the Verifier when the Wallet follows
    /// the redirect in the `redirect_uri` parameter.
    pub response_code: Option<String>,
}

/// Request to retrieve the Verifier's  client metadata.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct MetadataRequest {
    /// The Verifier's Client Identifier for which the configuration is to be
    /// returned.
    #[serde(default)]
    pub client_id: String,
}

/// Response containing the Verifier's client metadata.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct MetadataResponse {
    /// The Client metadata for the specified Verifier.
    #[serde(flatten)]
    pub client: Verifier,
}

/// Used to define the format and proof types of Verifiable Presentations and
/// Verifiable Credentials that a Verifier supports.
///
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

/// OAuth 2 client metadata used for registering clients of the issuance and
/// wallet authorization servers.
///
/// In the case of Issuance, the Wallet is the Client and the Issuer is the
/// Authorization Server.
///
/// In the case of Presentation, the Wallet is the Authorization Server and the
/// Verifier is the Client.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Verifier {
    /// OAuth 2.0 Client
    #[serde(flatten)]
    pub oauth: OAuthClient,

    /// An object defining the formats and proof types of Verifiable
    /// Presentations and Verifiable Credentials that a Verifier supports.
    /// For specific values that can be used.
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

/// The `OpenID4VCI` specification defines commonly used [Credential Format
/// Profiles] to support.  The profiles define Credential format specific
/// parameters or claims used to support a particular format.
///
/// [Credential Format Profiles]: (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-format-profiles)
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub enum Format {
    /// W3C Verifiable Credential.
    #[serde(rename = "jwt_vp_json")]
    JwtVpJson,
}

/// OAuth 2.0 Authorization Server metadata.
/// See RFC 8414 - Authorization Server Metadata
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Wallet {
    /// OAuth 2.0 Server
    #[serde(flatten)]
    pub oauth: OAuthServer,

    /// Specifies whether the Wallet supports the transfer of
    /// `presentation_definition` by reference, with true indicating support.
    /// If omitted, the default value is true.
    pub presentation_definition_uri_supported: bool,

    /// A list of key value pairs, where the key identifies a Credential format
    /// supported by the Wallet.
    pub vp_formats_supported: Option<HashMap<String, VpFormat>>,
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;

    use super::*;
    use crate::dif_exch::{DescriptorMap, PathNested};

    #[test]
    fn response_request_form_encode() {
        let request = ResponseRequest {
            vp_token: Some(vec![Kind::String("eyJ.etc".into())]),
            presentation_submission: Some(PresentationSubmission {
                id: "07b0d07c-f51e-4909-a1ab-d35e2cef20b0".into(),
                definition_id: "4b93b6aa-2157-4458-80ff-ffcefa3ff3b0".into(),
                descriptor_map: vec![DescriptorMap {
                    id: "employment".into(),
                    format: "jwt_vc_json".into(),
                    path: "$".into(),
                    path_nested: PathNested {
                        format: "jwt_vc_json".into(),
                        path: "$.verifiableCredential[0]".into(),
                    },
                }],
            }),
            state: Some("Z2VVKkglOWt-MkNDbX5VN05RRFI4ZkZeT01ZelEzQG8".into()),
        };
        let map = request.form_encode().expect("should condense to hashmap");
        assert_snapshot!("response_request_form_encoded", &map, {
            "." => insta::sorted_redaction(),
        });
        let req = ResponseRequest::form_decode(&map).expect("should expand from hashmap");
        assert_snapshot!("response_request_form_decoded", &req);
    }
}
