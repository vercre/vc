//! # `OpenID` for Verifiable Presentations (`OpenID4VP`)

use std::fmt;
use std::io::Cursor;

use anyhow::anyhow;
use base64ct::{Base64, Encoding};
use dif_exch::{InputDescriptor, PresentationDefinition, PresentationSubmission};
use qrcode::QrCode;
use serde::de::{self, Deserializer, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::Client as ClientMetadata;
use crate::error::Err;
use crate::{stringify, Result};

/// The Request Object Request is created by the Verifier to generate an
/// Authorization Request Object.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct CreateRequestRequest {
    #[allow(rustdoc::bare_urls)]
    /// The Verifier ID. It MUST be a valid URI. For example,
    /// `"https://vercre.io"` or `"did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg"`.
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

    /// An ID that the client application wants to be included in callback
    /// payloads. If no ID is provided, callbacks will not be made.
    pub callback_id: Option<String>,
}

/// Used to specify whether Authorization Requests and Responses are to be passed
/// between endpoints on the same device or across devices
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum DeviceFlow {
    /// With the cross-device flow the Verifier renders the Authorization Request
    /// as a QR Code which the User scans with the Wallet. In response, the
    /// Verifiable Presentations are sent to a URL controlled by the Verifier
    /// using HTTPS POST.
    ///
    /// To initiate this flow, the Verifier specifies a Response Type of "`vp_token`"
    /// and a Response Mode of "`direct_post`" in the Request Object.
    ///
    /// In order to keep the size of the QR Code small and be able to sign and
    /// optionally encrypt the Request Object, the Authorization Request only
    /// contains a Request URI which the wallet uses to retrieve the actual
    /// Authorization Request data.
    ///
    /// It is RECOMMENDED that Response Mode "`direct_post`" and `request_uri` are
    /// used for cross-device flows, as Authorization Request size might be large
    /// and may not fit in a QR code.
    #[default]
    CrossDevice,

    /// The same-device flow uses HTTP redirects to pass Authorization Request and
    /// Response between Verifier and Wallet. Verifiable Presentations are returned
    /// to the Verifier in the fragment part of the redirect URI, when the Response
    /// Mode is "`fragment`".
    SameDevice,
}

/// The response to the originator of the Request Object Request.
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

/// The Authorization Request follows the definition given in [RFC6749]. The Verifier
/// may send an Authorization Request as Request Object by value or by reference as
/// defined in JWT-Secured Authorization Request (JAR) [RFC9101].
///
/// [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
/// [RFC9101]:https://www.rfc-editor.org/rfc/rfc9101
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct RequestObject {
    /// The type of response expected from the Wallet (as Authorization Server).
    /// MUST be one of "`vp_token`", "`vp_token id_token`", or "`code`".
    ///
    /// If Response Type is:
    ///  - "`vp_token`": a VP Token is returned in an Authorization Response.
    ///
    ///  - "`vp_token id_token`" AND the `scope` parameter contains "`openid`": a
    ///    VP Token and a Self-Issued ID Token are returned in an Authorization
    ///    Response.
    ///
    ///  - "`code`": a VP Token is returned in a Token Response.
    ///
    /// The default Response Mode is "fragment": response parameters are encoded
    /// in the fragment added to the `redirect_uri` when redirecting back to the
    /// Verifier.
    pub response_type: String,

    /// The Verifier ID. MUST be a valid URI.
    pub client_id: String,

    /// The URI to redirect to the Verifier's redirection endpoint as established
    /// during client registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    /// While the `response_type` parameter informs the Authorization Server
    /// (Wallet) of the desired authorization flow, the `response_mode` parameter
    /// informs it of the mechanism to use when returning an Authorization Response.
    ///
    /// A Response Mode of "`direct_post`" allows the Wallet to send the Authorization
    /// Response to an endpoint controlled by the Verifier as an HTTPS POST request.
    ///
    /// If not set, the default value is "`fragment`".
    ///
    /// Response parameters are returned using the "application/x-www-form-urlencoded"
    /// content type. The flow can end with an HTTPS POST request from the Wallet to
    /// the Verifier, or it can end with a redirect that follows the HTTPS POST request,
    /// if the Verifier responds with a redirect URI to the Wallet.
    ///
    /// Response Mode "`direct_post.jwt`" causes the Wallet to send the Authorization
    /// Response as an HTTPS POST request (as for "`direct_post`") except the Wallet
    /// sets a `response` parameter to a JWT containing the Authorization Response.
    /// See [JARM] for more detail.
    ///
    /// [JARM]: (https://openid.net/specs/oauth-v2-jarm-final.html)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,

    /// OPTIONAL. MUST be set when the Response Mode "`direct_post`" is used.
    ///
    /// The URI to which the Wallet MUST send the Authorization Response using an
    /// HTTPS POST request as defined by the Response Mode "`direct_post`".
    ///
    /// When `response_uri` is set, `redirect_uri` MUST NOT be set. If set when
    /// Response Mode is "`direct_post`", the Wallet MUST return an "`invalid_request`"
    /// error.
    ///
    /// Note: If the Client Identifier scheme `redirect_uri` is used in conjunction
    /// with the Response Mode "`direct_post`", and the `response_uri` parameter is
    /// present, the `client_id` value MUST be equal to the `response_uri` value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_uri: Option<String>,

    /// The Wallet MAY allow Verifiers to request presentation of Verifiable
    /// Credentials by utilizing a pre-defined scope value. Defined in [RFC6749].
    ///
    /// [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// The nonce is used to securely bind the requested Verifiable Presentation(s)
    /// provided by the Wallet to the particular transaction.
    /// Returned in the VP's Proof.challenge parameter.
    pub nonce: String,

    /// State is used to maintain state between the Authorization Request and
    /// subsequent callback from the Wallet ('Authorization Server').
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// A Presentation Definition object. This parameter MUST be set when
    /// neither `presentation_definition_uri`, nor or a Presentation
    /// Definition scope value are set.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "stringify")]
    pub presentation_definition: Option<PresentationDefinition>,

    /// A URL pointing to where a Presentation Definition object can be
    /// retrieved. This parameter MUST be set when neither
    /// `presentation_definition` nor a Presentation Definition scope value
    /// are set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation_definition_uri: Option<String>,

    /// The `client_id_scheme` is used to specify how the Wallet should to obtain and
    /// validate Verifier metadata. The following values indicate how the Wallet
    /// should interpret the value of the `client_id` parameter:
    ///
    ///  - "`redirect_uri`": The Client Identifier is the redirect URI (or response URI).
    ///    The Authorization Request MUST NOT be signed, the Verifier MAY omit the
    ///    `redirect_uri` parameter, and all Verifier metadata parameters MUST be passed
    ///    using the `client_metadata` or `client_metadata_uri` parameter.
    ///    If used in conjunction with the Response Mode "`direct_post`", and the
    ///    `response_uri` parameter is present, the `client_id` value MUST be equal to
    ///    the `response_uri` value.
    ///
    ///  - "`did`": The Client Identifier is a DID.
    ///    The request MUST be signed with a private key associated with the DID. A
    ///    public key to verify the signature MUST be obtained from the
    ///    `verificationMethod` property of a DID Document. Since DID Document may
    ///    include multiple public keys, a particular public key used to sign the
    ///    request in question MUST be identified by the `kid` in the JOSE Header.
    ///    To obtain the DID Document, the Wallet MUST use DID  Resolution defined
    ///    by the DID method used by the Verifier. All Verifier metadata other than
    ///    the public key MUST be obtained from the `client_metadata` or the
    ///    `client_metadata_uri` parameter.
    ///
    /// - "`verifier_attestation`": Unsupported.
    ///   The Verifier authenticates using a JWT.
    ///   The Client Identifier MUST equal the `sub` claim value in the Verifier
    ///   attestation JWT. The request MUST be signed with the private key corresponding
    ///   to the public key in the `cnf` claim in the Verifier attestation JWT. This
    ///   serves as proof of possesion of this key. The Verifier attestation JWT MUST be
    ///   added to the `jwt` JOSE Header of the request object. The Wallet
    ///   MUST validate the signature on the Verifier attestation JWT. The `iss` claim
    ///   of the Verifier Attestation JWT MUST identify a party the Wallet trusts
    ///   for issuing Verifier Attestation JWTs. If the Wallet cannot establish trust,
    ///   it MUST refuse the request. If the issuer of the Verifier Attestation JWT
    ///   adds a `redirect_uris` claim to the attestation, the Wallet MUST ensure the
    ///   `redirect_uri` request parameter value exactly matches one of the `redirect_uris`
    ///   claim entries. All Verifier metadata other than the public key MUST be
    ///   obtained from the `client_metadata` or the `client_metadata_uri` parameter.
    ///
    ///  - "`pre-registered`": Unsupported.
    ///    The Client Identifier is already known to the Wallet.
    ///    This value represents the [RFC6749] default behavior, i.e. the Client
    ///    Identifier needs to be known to the Wallet in advance of the Authorization
    ///    Request. Verifier metadata is obtained from metadata endpoint
    ///    [RFC7591] or out-of-band an mechanism.
    ///
    ///  - "`entity_id`": Unsupported.
    ///    The Client Identifier is an OpenID.Federation Entity ID.
    ///    OpenID.Federation processing rules are followed, OpenID.Federation automatic
    ///    registration is used, the request may contain a `trust_chain` parameter, the
    ///    Wallet only obtains Verifier metadata from Entity Statement(s),
    ///    `client_metadata` or `client_metadata_uri` are not set.
    ///
    /// - "`x509_san_dns`": Unsupported.
    ///    The Client Identifier is a DNS name.
    ///    The DNS name MUST match a dNSName Subject Alternative Name (SAN) [RFC5280]
    ///    entry in the leaf certificate passed with the request.
    ///  
    /// - "`x509_san_uri`": Unsupported.
    ///   The Client Identifier is a URI.
    ///   The URI MUST match a uniformResourceIdentifier Subject Alternative Name (SAN)
    ///   [RFC5280] entry in the leaf certificate passed with the request.
    ///
    /// If the parameter is not present, the Wallet MUST behave as specified in
    /// [RFC6749]. If the same Client Identifier is used with different Client
    /// Identifier schemes, those occurrences MUST be treated as different Verifiers.
    /// The Verifier needs to determine which Client Identifier schemes the Wallet
    /// supports prior to sending the Authorization Request in order to choose a
    /// supported scheme.
    ///
    /// [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
    /// [RFC5280]: (https://www.rfc-editor.org/rfc/rfc5280)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_scheme: Option<String>,

    /// Client Metadata contains Verifier metadata values. It MUST NOT be set if
    /// the `client_metadata_uri` parameter is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "stringify")]
    pub client_metadata: Option<ClientMetadata>,

    /// A URL pointing to a resource where the Verifier metadata can be
    /// retrieved. The URL value MUST be reachable by the Wallet. The
    /// parameter MUST NOT be set if `client_metadata` parameter is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_metadata_uri: Option<String>,
}

impl RequestObject {
    /// Generate qrcode for Request Object.
    /// Use the `endpoint` parameter to specify the Wallet's endpoint using deep link or
    /// direct call format.
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
    /// Returns an `Err::ServerError` error if the Request Object cannot be serialized.
    pub fn to_qrcode(&self, endpoint: &str) -> Result<String> {
        let Ok(qs) = self.to_querystring() else {
            return Err(Err::ServerError(anyhow!("Failed to generate querystring")));
        };

        // generate qr code
        let qr_code = match QrCode::new(format!("{endpoint}{qs}")) {
            Ok(q) => q,
            Err(e) => return Err(Err::ServerError(anyhow!("Failed to create QR code: {e}"))),
        };

        // write image to buffer
        let img_buf = qr_code.render::<image::Luma<u8>>().build();
        let mut buffer: Vec<u8> = Vec::new();
        let mut writer = Cursor::new(&mut buffer);
        if let Err(e) = img_buf.write_to(&mut writer, image::ImageFormat::Png) {
            return Err(Err::ServerError(anyhow!("Failed to create QR code: {e}")));
        }

        // base64 encode image
        Ok(format!("data:image/png;base64,{}", Base64::encode_string(buffer.as_slice())))
    }

    /// Generate a query string for the Request Object.
    ///
    /// # Errors
    ///
    /// Returns an `Err::ServerError` error if the Request Object cannot be serialized.
    pub fn to_querystring(&self) -> Result<String> {
        Ok(serde_qs::to_string(&self)?)
    }
}

/// The Request Object Request is used (indirectly) by the Wallet to retrieve a previously
/// generated Authorization Request Object. The Wallet is sent a `request_uri` containing a
/// unique URL pointing to the Request Object. The URI has the form
/// `client_id/request/state_key`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct RequestObjectRequest {
    /// The ID of the Verifier to retrieve the Authorization Request Object for.
    #[serde(default)]
    pub client_id: String,

    /// The state key used to uniquely identify the previously generated Request
    /// Object.
    pub state: String,
}

/// The Request Object Response is created by the Verifier to generate an
/// Authorization Request Object.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestObjectResponse {
    /// The Authorization Request Object generated by the `request` endpoint.
    pub request_object: Option<RequestObject>,

    /// The Authorization Request Object, encoded as a JWT.
    pub jwt: Option<String>,
}

/// Serialize to 'unwrapped' JWT if Request Object is JWT (`jwt parameter is set`).
impl Serialize for RequestObjectResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // serialize as JWT
        if let Some(jwt) = &self.jwt {
            return jwt.serialize(serializer);
        }

        // serialize as JSON
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("request_object", &self.request_object)?;
        map.end()
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
                    request_object: None,
                    jwt: Some(value.to_string()),
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<RequestObjectResponse, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut resp = RequestObjectResponse::default();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "request_object" => resp.request_object = map.next_value()?,
                        "jwt" => resp.jwt = map.next_value()?,
                        _ => {
                            return Err(de::Error::unknown_field(&key, &["request_object", "jwt"]))
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
    /// One or more Verifiable Presentations represented as base64url encoded strings
    /// and/or JSON objects. The VP format determines the encoding. The encoding follows
    /// the same format-based rules as for Credential issuance (Appendix E of the
    /// [OpenID4VCI] specification).
    ///
    /// When a single Verifiable Presentation is returned, array syntax MUST NOT be used.
    ///
    /// [OpenID4VCI]: (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
    #[serde(skip_serializing_if = "Option::is_none")]
    // #[serde(deserialize_with = "vp_token::deserialize")]
    #[serde(with = "stringify")]
    pub vp_token: Option<Vec<Value>>,

    /// The `presentation_submission` element as defined in [DIF.PresentationExchange].
    /// It contains mappings between the requested Verifiable Credentials and where to
    /// find them within the returned VP Token.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "stringify")]
    pub presentation_submission: Option<PresentationSubmission>,

    /// The client state value from the Authorization Request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// Authorization Response response object is used to return a `redirect_uri` to
/// the Wallet following successful processing of the presentation submission.
#[derive(Debug, Deserialize, Serialize)]
pub struct ResponseResponse {
    /// When the redirect parameter is used the Wallet MUST send the User Agent to the
    /// provided URI. The redirect URI allows the Verifier to continue the interaction
    /// with the End-User on the device where the Wallet resides after the Wallet has
    /// sent the Authorization Response. It especially enables the Verifier to prevent
    /// session fixation attacks.
    ///
    /// The URI — an absolute URI — is chosen by the Verifier. It MUST include a fresh,
    /// cryptographically random number to ensure only the receiver of the redirect can
    /// fetch and process the Authorization Response. The number could be added as a
    /// path component or a parameter to the URL. It is RECOMMENDED to use a
    /// cryptographic random value of 128 bits or more.
    ///
    /// # Example
    ///
    /// ```http
    /// redirect_uri": "https://client.example.org/cb#response_code=091535f699ea575c7937fa5f0f454aee"
    /// ```
    /// If the response does not contain a parameter, the Wallet is not required to
    /// perform any further steps.
    pub redirect_uri: Option<String>,

    /// A cryptographically random number with sufficient entropy used to link the
    /// Authorization Response to the Authorization Request. The `response_code` is
    /// returned to the Verifier when the Wallet follows the redirect in the
    /// `redirect_uri` parameter.
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
    pub client: ClientMetadata,
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
