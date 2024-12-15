//! # Presentation
//!
//! The Presentation endpoints implement the vercre-holder's credential
//! presentation flow.

pub(crate) mod authorize;
pub(crate) mod present;
pub(crate) mod request;

use std::fmt::{Debug, Display};
use std::str::FromStr;
use std::vec;

use anyhow::{anyhow, bail};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vercre_core::{urlencode, Kind};
use vercre_did::DidResolver;
use vercre_dif_exch::{
    Constraints, DescriptorMap, FilterValue, PathNested, PresentationSubmission,
};
use vercre_infosec::jose::jws;
use vercre_openid::verifier::{
    RequestObject, RequestObjectResponse, RequestObjectType, ResponseRequest,
};
use vercre_w3c_vc::model::VerifiablePresentation;
use vercre_w3c_vc::proof::Payload;
use vercre_w3c_vc::verify_key;

use crate::credential::Credential;

/// `PresentationState` maintains app state across steps of the presentation flow.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PresentationState {
    /// The unique identifier for the presentation flow. Not used internally but
    /// passed to providers so that wallet clients can track interactions
    /// with specific flows.
    pub id: String,

    /// The current status of the presentation flow.
    pub status: Status,

    /// The request object received from the verifier.
    pub request: RequestObject,

    /// The list of credentials matching the verifier's request (Presentation
    /// Definition).
    pub credentials: Vec<Credential>,

    /// The `JSONPath` query used to match credentials to the verifier's
    /// request.
    pub filter: Constraints,

    /// The presentation submission token.
    pub submission: PresentationSubmission,
}

impl PresentationState {
    /// Create a new presentation flow.
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            status: Status::Inactive,
            ..Default::default()
        }
    }
}

/// Presentation Status values.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename = "PresentationStatus")]
pub enum Status {
    /// No authorization request is being processed.
    #[default]
    Inactive,

    /// A new authorization request has been received.
    Requested,

    /// Credentials have been selected from the wallet that match the
    /// presentation request.
    CredentialsSet,

    /// The authorization request has been authorized.
    Authorized,

    /// The authorization request has failed, with an error message.
    Failed(String),
}

/// Get a string representation of the `Status`.
impl Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inactive => write!(f, "Inactive"),
            Self::Requested => write!(f, "Requested"),
            Self::CredentialsSet => write!(f, "CredentialsSet"),
            Self::Authorized => write!(f, "Authorized"),
            Self::Failed(e) => write!(f, "Failed: {e}"),
        }
    }
}

/// Parse a `Status` from a string.
impl FromStr for Status {
    // TODO: strongly typed error
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        if s.starts_with("Failed") {
            return Ok(Self::Failed(s[8..].to_string()));
        }
        match s {
            "Inactive" => Ok(Self::Inactive),
            "Requested" => Ok(Self::Requested),
            "Authorized" => Ok(Self::Authorized),
            _ => Err(anyhow!("Invalid status: {s}")),
        }
    }
}

/// Utility to extract a presentation `RequestObject` from a URL-encoded string.
/// If the request string can be decoded but appears to be something other than
/// a `RequestObject`, None is returned.
///
/// Wrapper to the function from `vercre-core`.
///
/// # Errors
/// If the string cannot be decoded or appears to be an encoded `RequestObject`
/// but cannot be successfully deserialized, an error is returned.
pub fn parse_request_object(request: &str) -> anyhow::Result<Option<RequestObject>> {
    let req_obj = if request.contains("&presentation_definition") {
        Some(
            urlencode::from_str::<RequestObject>(request)
                .map_err(|e| anyhow!("failed to parse request object: {e}"))?,
        )
    } else {
        None
    };

    Ok(req_obj)
}

/// A presentation flow is used to orchestrate the change in state as the
/// wallet progresses through a credential verification.
#[derive(Clone, Debug)]
pub struct PresentationFlow<U, R, A> {
    uri: U,
    request: R,
    authorize: A,

    /// Perhaps useful to the wallet for tracking a particular flow instance.
    id: String,
}

impl<U, R, A> PresentationFlow<U, R, A> {
    /// Get the ID of the issuance flow.
    pub fn id(&self) -> String {
        self.id.clone()
    }
}

/// Type guard for a `PresentationFlow` that has been requested with a URI.
#[derive(Clone, Debug)]
pub struct WithUri(String);
/// Type guard for a `PresentationFlow` that has been requested directly with a
/// `RequestObject`, so has no URI,
#[derive(Clone, Debug)]
pub struct WithoutUri;

/// Type guard for a `PresentationFlow` that has a `RequestObject` either
/// because it was requested directly or because it was parsed from a URI.
#[derive(Clone, Debug)]
pub struct WithRequest(RequestObject, PresentationSubmission);
/// Type guard for a `PresentationFlow` that has not yet had a request object
/// resolved.
#[derive(Clone, Debug)]
pub struct WithoutRequest;

/// Type guard for a `PresentationFlow` that has been authorized.
#[derive(Clone, Debug)]
pub struct Authorized(Vec<Credential>);
/// Type guard for a `PresentationFlow` that has not been authorized.
#[derive(Clone, Debug)]
pub struct NotAuthorized;

impl PresentationFlow<WithUri, WithoutRequest, NotAuthorized> {
    /// Create a new presentation flow with a URI.
    #[must_use]
    pub fn new(uri: String) -> Self {
        Self {
            uri: WithUri(uri),
            request: WithoutRequest,
            authorize: NotAuthorized,

            id: Uuid::new_v4().to_string(),
        }
    }

    /// Add a request object to the presentation flow.
    ///
    /// # Errors
    /// Will return an error if the request object does not contain a
    /// presentation definition object: this is the only currently supported
    /// type.
    pub fn request(
        self, request: RequestObject,
    ) -> anyhow::Result<PresentationFlow<WithUri, WithRequest, NotAuthorized>> {
        let submission = create_submission(&request)?;
        Ok(PresentationFlow {
            uri: self.uri,
            request: WithRequest(request, submission),
            authorize: NotAuthorized,

            id: self.id,
        })
    }
}

impl<R, A> PresentationFlow<WithUri, R, A> {
    /// Get the URI of the verifiers request from current state.
    pub fn uri(&self) -> String {
        self.uri.0.clone()
    }
}

impl PresentationFlow<WithoutUri, WithRequest, NotAuthorized> {
    /// Create a new presentation flow with a request object.
    /// 
    /// # Errors
    /// Will return an error if the request object does not contain a
    /// presentation definition object: this is the only currently supported
    /// type.
    pub fn new(request: RequestObject) -> anyhow::Result<Self> {
        let submission = create_submission(&request)?;
        Ok(Self {
            uri: WithoutUri,
            request: WithRequest(request, submission),
            authorize: NotAuthorized,

            id: Uuid::new_v4().to_string(),
        })
    }
}

impl<U> PresentationFlow<U, WithRequest, NotAuthorized> {
    /// Get a filter from the request object on the state.
    /// 
    /// # Errors
    /// Will return an error if the request object does not contain a
    /// presentation definition object: this is the only currently supported
    /// type.
    pub fn filter(&self) -> anyhow::Result<Constraints> {
        let pd = match &self.request.0.presentation_definition {
            Kind::Object(pd) => pd,
            Kind::String(_) => bail!("presentation_definition_uri is unsupported"),
        };
        if pd.input_descriptors.is_empty() {
            bail!("no input descriptors found");
        }
        let constraints = pd.input_descriptors[0].constraints.clone();

        Ok(constraints)
    }

    /// Authorize the presentation flow.
    pub fn authorize(
        self, credentials: &[Credential],
    ) -> PresentationFlow<U, WithRequest, Authorized> {
        PresentationFlow {
            uri: self.uri,
            request: self.request,
            authorize: Authorized(credentials.to_vec()),

            id: self.id,
        }
    }
}

impl<U> PresentationFlow<U, WithRequest, Authorized> {
    /// Construct a presentation payload.
    ///
    /// # Errors
    /// Will return an error if the request object does not contain a
    /// presentation definition object: this is the only currently supported
    /// type.
    pub fn payload(&self, key_identifier: &str) -> anyhow::Result<Payload> {
        let holder_did = key_identifier.split('#').collect::<Vec<&str>>()[0];

        // presentation with 2 VCs: one as JSON, one as base64url encoded JWT
        let mut builder = VerifiablePresentation::builder()
            .add_context(Kind::String("https://www.w3.org/2018/credentials/examples/v1".into()))
            .holder(holder_did);

        let pd = match &self.request.0.presentation_definition {
            Kind::Object(pd) => pd,
            Kind::String(_) => bail!("presentation_definition_uri is unsupported"),
        };

        for input in &pd.input_descriptors {
            if let Some(fields) = &input.constraints.fields {
                for field in fields {
                    if let Some(filter) = &field.filter {
                        if let FilterValue::Const(val) = &filter.value {
                            builder = builder.add_type(val.clone());
                        }
                    }
                }
            }
        }

        for c in &self.authorize.0 {
            builder = builder.add_credential(Kind::String(c.issued.clone()));
        }
        let vp = builder.build()?;

        let payload = Payload::Vp {
            vp,
            client_id: self.request.0.client_id.clone(),
            nonce: self.request.0.nonce.clone(),
        };

        Ok(payload)
    }

    /// Create a presentation response request and the presentation URI from the
    /// current flow state and the provided proof.
    #[must_use]
    pub fn create_response_request(&self, jwt: &str) -> (ResponseRequest, Option<String>) {
        let res_req = ResponseRequest {
            vp_token: Some(vec![Kind::String(jwt.into())]),
            presentation_submission: Some(self.request.1.clone()),
            state: self.request.0.state.clone(),
        };
        let res_uri =
            self.request.0.response_uri.clone().map(|uri| uri.trim_end_matches('/').to_string());
        (res_req, res_uri)
    }
}

/// Utility to extract a presentation `RequestObject` from a
/// `RequestObjectResponse`. Uses a DID resolver to verify the JWT.
///
/// # Errors
/// If decoding or verifying the JWT fails an error is returned.
pub async fn parse_request_object_response(
    res: &RequestObjectResponse, resolver: impl DidResolver,
) -> anyhow::Result<RequestObject> {
    let RequestObjectType::Jwt(token) = &res.request_object else {
        bail!("no serialized JWT found in response");
    };
    let jwt: jws::Jwt<RequestObject> = jws::decode(token, verify_key!(resolver))
        .await
        .map_err(|e| anyhow!("failed to parse JWT: {e}"))?;

    Ok(jwt.claims)
}

// Construct a presentation submission from a request object.
fn create_submission(request: &RequestObject) -> anyhow::Result<PresentationSubmission> {
    let pd = match &request.presentation_definition {
        Kind::Object(pd) => pd,
        Kind::String(_) => bail!("presentation_definition_uri is unsupported"),
    };

    let mut desc_map: Vec<DescriptorMap> = vec![];
    for n in 0..pd.input_descriptors.len() {
        let in_desc = &pd.input_descriptors[n];
        let dm = DescriptorMap {
            id: in_desc.id.clone(),
            path: "$".to_string(),
            path_nested: PathNested {
                format: "jwt_vc_json".to_string(),
                // URGENT: index matched VCs not input descriptors!!
                path: "$.verifiableCredential[0]".to_string(),
            },
            format: "jwt_vc_json".to_string(),
        };
        desc_map.push(dm);
    }
    Ok(PresentationSubmission {
        id: Uuid::new_v4().to_string(),
        definition_id: pd.id.clone(),
        descriptor_map: desc_map,
    })
}
