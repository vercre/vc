//! # Presentation
//!
//! The Presentation endpoint implements the vercre-wallet's credential presentation flow.
use std::fmt::Debug;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;
use vercre_core::error::Err;
use vercre_core::vp::{RequestObject, RequestObjectResponse, ResponseRequest};
use vercre_core::{err, Result};
use vercre_issuer::jose;
use vercre_vc::model::vp::{
    Constraints, DescriptorMap, PathNested, PresentationSubmission, Proof, VerifiablePresentation,
};
use vercre_vc::proof::jose::{Jwt, VpClaims};

use crate::credential::Credential;
use crate::provider::{
    Callback, CredentialStorer, PresentationInput, PresentationListener, Signer, VerifierClient,
};
use crate::Endpoint;

/// `Presentation` maintains app state across steps of the presentation flow.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Presentation {
    /// The unique identifier for the presentation flow. Not used internally but passed to providers
    /// so that wallet clients can track interactions with specific flows.
    pub id: String,

    /// The current status of the presentation flow.
    pub status: Status,

    /// The request object received from the verifier.
    pub request: RequestObject,

    /// The list of credentials matching the verifier's request (Presentation
    /// Definition).
    pub credentials: Vec<Credential>,

    /// The `JSONPath` query used to match credentials to the verifier's request.
    pub filter: Constraints,

    /// The presentation submission token.
    pub submission: PresentationSubmission,
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

    /// The authorization request has been authorized.
    Authorized,

    /// The authorization request has failed, with an error message.
    Failed(String),
}

/// Get a string representation of the `Status`.
impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inactive => write!(f, "Inactive"),
            Self::Requested => write!(f, "Requested"),
            Self::Authorized => write!(f, "Authorized"),
            Self::Failed(e) => write!(f, "Failed: {e}"),
        }
    }
}

/// Parse a `Status` from a string.
impl std::str::FromStr for Status {
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

/// The `ReceivePresentationRequest` is the input to the `receive_request` endpoint. It can be
/// a URI to fetch the request object or the request object itself as a query parameter.
pub type ReceivePresentationRequest = String;

impl<P> Endpoint<P>
where
    P: Callback
        + CredentialStorer
        + PresentationInput
        + PresentationListener
        + VerifierClient
        + Signer
        + Clone
        + Debug,
{
    /// Orchestrates the presentation flow triggered by a presentation request from a verifier.
    #[instrument(level = "debug", skip(self))]
    pub async fn receive_request(&self, request: &ReceivePresentationRequest) -> Result<()> {
        let ctx = Context {
            _p: std::marker::PhantomData,
        };

        vercre_core::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug, Default)]
struct Context<P> {
    _p: std::marker::PhantomData<P>,
}

impl<P> vercre_core::Context for Context<P>
where
    P: Callback
        + CredentialStorer
        + PresentationInput
        + PresentationListener
        + VerifierClient
        + Signer
        + Clone
        + Debug,
{
    type Provider = P;
    type Request = ReceivePresentationRequest;
    type Response = ();

    #[allow(clippy::too_many_lines)]
    async fn process(
        &self, provider: &Self::Provider, req: &Self::Request,
    ) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        // Parse the request and either go fetch the request object or use one embedded in a
        // query parameter.
        let Ok(request) = urlencoding::decode(req) else {
            err!(Err::InvalidRequest, "unable to decode request url string");
        };
        let mut presentation = Presentation {
            id: Uuid::new_v4().to_string(),
            status: Status::Requested,
            ..Default::default()
        };
        provider.notify(&presentation.id, Status::Requested);

        let request_object = if request.contains("&presentation_definition=") {
            match parse_presentation_definition(&request) {
                Ok(req_obj) => req_obj,
                Err(e) => {
                    provider.notify(&presentation.id, Status::Failed(e.to_string()));
                    return Ok(());
                }
            }
        } else {
            match provider.get_request_object(&presentation.id, &request).await {
                Ok(req_obj_res) => match parse_request_object_response(&req_obj_res) {
                    Ok(req_obj) => req_obj,
                    Err(e) => {
                        provider.notify(&presentation.id, Status::Failed(e.to_string()));
                        return Ok(());
                    }
                },
                Err(e) => {
                    provider.notify(&presentation.id, Status::Failed(e.to_string()));
                    return Ok(());
                }
            }
        };
        presentation.request = request_object;

        // Get the credentials from wallet storage that match the verifier's request.
        let filter = match build_filter(&presentation.request) {
            Ok(filter) => filter,
            Err(e) => {
                provider.notify(&presentation.id, Status::Failed(e.to_string()));
                return Ok(());
            }
        };
        presentation.filter = filter.clone();
        let credentials = match provider.find(Some(filter)).await {
            Ok(creds) => creds,
            Err(e) => {
                provider.notify(&presentation.id, Status::Failed(e.to_string()));
                return Ok(());
            }
        };
        presentation.credentials.clone_from(&credentials);

        // Request authorization from the wallet client to proceed with the presentation.
        if !provider.authorize(&presentation.id, credentials).await {
            return Ok(());
        }
        provider.notify(&presentation.id, Status::Authorized);

        // Construct a presentation submission.
        let submission = match create_submission(&presentation) {
            Ok(submission) => submission,
            Err(e) => {
                provider.notify(&presentation.id, Status::Failed(e.to_string()));
                return Ok(());
            }
        };
        presentation.submission = submission.clone();

        // create vp
        let kid = &provider.verification_method();
        let holder_did = kid.split('#').collect::<Vec<&str>>()[0];

        let vp = match create_vp(&presentation, holder_did) {
            Ok(token) => token,
            Err(e) => {
                provider.notify(&presentation.id, Status::Failed(e.to_string()));
                return Ok(());
            }
        };

        let claims = VpClaims::try_from(vp)?;
        let jwt = jose::encode(jose::Typ::Presentation, &claims, provider.clone()).await?;

        let vp_token = match serde_json::to_value(&jwt) {
            Ok(v) => v,
            Err(e) => {
                provider.notify(&presentation.id, Status::Failed(e.to_string()));
                return Ok(());
            }
        };

        // Assemble the presentation response to the verifier and ask the wallet client to send it.
        let res_req = ResponseRequest {
            vp_token: Some(vec![vp_token]),
            presentation_submission: Some(submission),
            state: presentation.request.state.clone(),
        };
        let Some(mut res_uri) = presentation.request.response_uri.clone() else {
            provider.notify(&presentation.id, Status::Failed("no response uri".to_string()));
            return Ok(());
        };
        res_uri = res_uri.trim_end_matches('/').to_string();

        match provider.present(&presentation.id, &res_uri, &res_req).await {
            Ok(()) => Ok(()),
            Err(e) => {
                provider.notify(&presentation.id, Status::Failed(e.to_string()));
                Ok(())
            }
        }
    }
}

/// Extract a presentation request from a query string parameter.
fn parse_presentation_definition(request: &str) -> Result<RequestObject> {
    let req_obj = serde_qs::from_str::<RequestObject>(request)?;
    Ok(req_obj)
}

/// Extract a presentation `RequestObject` from a `RequestObjectResponse`.
fn parse_request_object_response(res: &RequestObjectResponse) -> Result<RequestObject> {
    if res.request_object.is_some() {
        return Ok(res.request_object.clone().unwrap());
    }
    let Some(jwt_enc) = res.jwt.clone() else {
        err!(Err::InvalidRequest, "no serialized JWT found in response");
    };
    let Ok(jwt) = serde_json::from_str::<Jwt<RequestObject>>(&jwt_enc) else {
        err!(Err::InvalidRequest, "failed to parse JWT");
    };
    // Note: commented code below represents case where JWT is encoded and signed.
    // TODO: Check that above simple deserialization is spec compliant (see associated test for
    // simple serialization). If so, remove this comment and code.
    // let Ok(jwt) = jwt_enc.parse::<Jwt<RequestObject>>() else {
    //     err!(Err::InvalidRequest, "failed to parse JWT");
    // };

    Ok(jwt.claims)
}

/// Construct a credential filter (`JSONPath`) from the presentation definition contained in the
/// presentation request.
// TODO: How to handle multiple input descriptors?
fn build_filter(request: &RequestObject) -> Result<Constraints> {
    let Some(pd) = &request.presentation_definition else {
        err!(Err::InvalidRequest, "no presentation definition found");
    };
    if pd.input_descriptors.is_empty() {
        err!(Err::InvalidRequest, "no input descriptors found");
    }
    let constraints = pd.input_descriptors[0].constraints.clone();

    Ok(constraints)
}

/// Create a presentation submission from the presentation request and matched credentials.
fn create_submission(presentation: &Presentation) -> anyhow::Result<PresentationSubmission> {
    let request = presentation.request.clone();
    let Some(pd) = &request.presentation_definition else {
        return Err(anyhow!("No presentation definition on request in context"));
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
    let submission = PresentationSubmission {
        id: Uuid::new_v4().to_string(),
        definition_id: pd.id.clone(),
        descriptor_map: desc_map,
    };
    Ok(submission)
}

/// Construct a Verifiable Presentation.
fn create_vp(
    presentation: &Presentation, holder_did: impl Into<String>,
) -> anyhow::Result<VerifiablePresentation> {
    let request = presentation.request.clone();

    // presentation with 2 VCs: one as JSON, one as base64url encoded JWT
    let mut builder = VerifiablePresentation::builder()
        .add_context(String::from("https://www.w3.org/2018/credentials/examples/v1"))
        .add_type(String::from("EmployeeIDPresentation"))
        .holder(holder_did);

    for c in &presentation.credentials {
        let val = serde_json::to_value(&c.issued)?;
        builder = builder.add_credential(val);
    }

    let mut vp = builder.build()?;

    vp.proof = Some(vec![Proof {
        domain: Some(vec![request.client_id.clone()]),
        challenge: Some(request.nonce),
        ..Proof::default()
    }]);

    Ok(vp)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use insta::assert_yaml_snapshot as assert_snapshot;
    use vercre_core::metadata::CredentialConfiguration;
    use vercre_vc::model::{
        Field, Filter, FilterValue, Format, InputDescriptor, PresentationDefinition,
        VerifiableCredential,
    };
    use vercre_vc::proof::{jose, Algorithm};

    use super::*;
    use crate::provider::example::wallet;

    fn sample_request() -> RequestObject {
        let state_key = "ABCDEF123456";
        let nonce = "1234567890";
        let fmt = Format {
            alg: Some(vec![Algorithm::EdDSA.to_string()]),
            proof_type: None,
        };

        RequestObject {
            response_type: "vp_token".into(),
            client_id: "https://vercre.io/post".into(),
            state: Some(state_key.into()),
            nonce: nonce.into(),
            response_mode: Some("direct_post".into()),
            response_uri: Some("https://vercre.io/post".into()),
            presentation_definition: Some(PresentationDefinition {
                id: "cd4cf88c-adc9-48b9-91cf-12d8643bff73".into(),
                purpose: Some("To verify employment status".into()),
                format: Some(HashMap::from([("jwt_vc".into(), fmt)])),
                name: None,
                input_descriptors: vec![InputDescriptor {
                    id: "EmployeeID_JWT".into(),
                    constraints: Constraints {
                        fields: Some(vec![Field {
                            path: vec!["$.type_".into()],
                            filter: Some(Filter {
                                type_: "string".into(),
                                value: FilterValue::Const("EmployeeIDCredential".into()),
                            }),
                            ..Default::default()
                        }]),
                        limit_disclosure: None,
                    },
                    name: None,
                    purpose: None,
                    format: None,
                }],
            }),
            client_id_scheme: Some("redirect_uri".into()),
            client_metadata: None, // Some(self.client_meta.clone()),
            redirect_uri: None,
            scope: None,
            presentation_definition_uri: None,
            client_metadata_uri: None,
        }
    }

    fn sample_credential() -> Credential {
        let vc = VerifiableCredential::sample();

        let proofs = vc.proof.clone().unwrap_or_default();
        let proof = &proofs[0];

        let jwt = Jwt {
            header: jose::Header {
                alg: jose::Algorithm::ES256K,
                kid: Some(proof.verification_method.clone()),
                ..jose::Header::default()
            },
            claims: vc.to_claims().expect("should get claims"),
        };
        let vc_str = serde_json::to_string(&jwt).expect("should serialize to string");

        let config = CredentialConfiguration::sample();
        Credential {
            issuer: "https://vercre.io".into(),
            id: vc.id.clone(),
            metadata: config,
            vc: vc.clone(),
            issued: vc_str,
            logo: None,
        }
    }

    // TODO: Is this test actually doing anything other than testing serde_qs? Consider removing.
    #[test]
    fn parse_presentation_definition_test() {
        let req_obj = sample_request();
        let req_str = serde_qs::to_string(&req_obj).expect("request object should serialize");
        let decoded = parse_presentation_definition(&req_str).expect("should parse");
        assert_eq!(req_obj, decoded);
    }

    #[test]
    fn parse_request_object_response_test() {
        let obj = sample_request();
        let req_obj_res = RequestObjectResponse {
            request_object: Some(obj.clone()),
            jwt: None,
        };
        let decoded =
            parse_request_object_response(&req_obj_res).expect("should parse with object");
        assert_eq!(obj, decoded);

        let jwt = Jwt {
            header: jose::Header::default(),
            claims: obj.clone(),
        };
        let jwt_str = serde_json::to_string(&jwt).expect("should serialize jwt");

        let req_obj_res = RequestObjectResponse {
            request_object: None,
            jwt: Some(jwt_str),
        };
        let decoded = parse_request_object_response(&req_obj_res).expect("should parse with jwt");
        assert_eq!(obj, decoded);
    }

    #[test]
    fn build_filter_test() {
        let req_obj = sample_request();
        let filter = build_filter(&req_obj).expect("should build filter");
        assert_eq!(
            filter,
            req_obj.presentation_definition.unwrap().input_descriptors[0].constraints
        );
    }

    #[test]
    fn create_submission_test() {
        let req_obj = sample_request();
        let creds = vec![sample_credential()];
        let presentation = Presentation {
            id: "1234".into(),
            status: Status::Requested,
            request: sample_request(),
            credentials: creds,
            filter: build_filter(&req_obj).expect("should build filter"),
            submission: PresentationSubmission::default(),
        };
        let submission = create_submission(&presentation).expect("should create submission");
        assert_snapshot!("create_submission", &submission, {".id" => "[id]"});
    }

    #[test]
    fn vp_token_test() {
        let req_obj = sample_request();
        let creds = vec![sample_credential()];
        let mut presentation = Presentation {
            id: "1234".into(),
            status: Status::Requested,
            request: sample_request(),
            credentials: creds,
            filter: build_filter(&req_obj).expect("should build filter"),
            submission: PresentationSubmission::default(),
        };
        presentation.submission =
            create_submission(&presentation).expect("should create submission");

        let kid = wallet::kid();
        let holder_did = kid.split('#').collect::<Vec<&str>>()[0];
        let vp = create_vp(&presentation, holder_did).expect("should create vp");

        let claims = VpClaims::try_from(vp).expect("should get claims");

        assert_snapshot!("vp_claims", &claims, {".jti" => "[jti]",
            ".nbf" => "[nbf]",
            ".iat" => "[iat]" ,
            ".exp" => "[exp]",
            ".vp.id" => "[vp.id]"
        });
    }
}
