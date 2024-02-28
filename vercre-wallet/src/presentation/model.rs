//! # Credential Model Flow

use anyhow::anyhow;
use chrono::Utc;
use crux_http::Response;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vercre_core::jwt::Jwt;
use vercre_core::vp::{RequestObject, RequestObjectResponse, ResponseRequest};
use vercre_core::w3c::vc::Proof;
use vercre_core::w3c::vp::{
    Claims as VpClaims, Constraints, DescriptorMap, PathNested, PresentationSubmission,
    VerifiablePresentation,
};

use crate::credential::Credential;

// TODO: replace all panics with error returns
// TODO: investigate use of Builder-like pattern to build Model model over
// course of events

/// `Model` maintains app state across the steps of the presentation flow. Model
/// data is surfaced to the shell indirectly via the `ViewModel`.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Model {
    /// The current status of the presentation flow.
    pub(crate) status: Status,

    /// The request object received from the verifier.
    pub(super) request: Option<RequestObject>,

    /// The list of credentials matching the verifier's request (Presentation
    /// Definition).
    pub(super) credentials: Vec<Credential>,

    /// The JSONPath query used to match credentials to the verifier's request.
    pub(super) filter: Option<Constraints>,

    /// The presentation submission token.
    pub(super) submission: Option<PresentationSubmission>,
}

impl Model {
    /// Reset the `Model` to its default state.
    pub fn reset(&mut self) {
        *self = Self { ..Default::default() };
    }

    /// Populate the `Model` from a new `RequestObject`. Verifies the
    /// `RequestObject` and sets the `status` to `Requested`.
    pub(super) fn new_request(&mut self, url_param: &str) -> anyhow::Result<()> {
        let Ok(request_str) = urlencoding::decode(url_param) else {
            return Err(anyhow!("Issue decoding request"));
        };

        // check to see if request passed by ref: fetch request object
        if !request_str.contains("&presentation_definition=") {
            return Ok(());
        }

        // extract RequestObject from query string
        let Ok(req_obj) = serde_qs::from_str::<RequestObject>(&request_str) else {
            return Err(anyhow!("Issue parsing request: {request_str:?}"));
        };

        self.handle_request(&req_obj)
    }

    /// Populate the `Model` from a new `RequestObject`. Verifies the
    /// `RequestObject` and sets the `status` to `Requested`.
    pub(super) fn handle_request(&mut self, req_obj: &RequestObject) -> anyhow::Result<()> {
        // TODO: add further request validation
        // let Some(response_uri) = &req_obj.response_uri else {
        //     return Err(anyhow!("No response uri"));
        // };

        // TODO: build credential query from presentation definition!!
        let Some(pd) = &req_obj.presentation_definition else {
            return Err(anyhow!("No presentation definition"));
        };

        self.filter = Some(pd.input_descriptors[0].constraints.clone());
        self.request = Some(req_obj.clone());
        self.status = Status::Requested;

        Ok(())
    }

    /// Set credential metadata for offered credentials.
    pub(crate) fn request_object_response(
        &mut self, mut response: Response<RequestObjectResponse>,
    ) -> anyhow::Result<()> {
        if !response.status().is_success() {
            return Err(anyhow!("Issue requesting metadata: {:?}", response.body()));
        }
        let Some(resp) = response.take_body() else {
            return Err(anyhow!("Missing response body"));
        };

        let Some(jwt_enc) = resp.jwt else {
            return Err(anyhow!("Missing request object"));
        };
        let Ok(jwt) = jwt_enc.parse::<Jwt<RequestObject>>() else {
            return Err(anyhow!("Invalid request object"));
        };

        if self.handle_request(&jwt.claims).is_err() {
            return Err(anyhow!("Invalid request: {:?}", jwt.claims));
        };
        Ok(())
    }

    // TODO: create a verifiable presentation token that matches Request Object
    // TODO: remove hard-coded values

    // Create a verifiable presentation token
    // presentation with 2 VCs: one as JSON, one as base64url encoded JWT
    pub(super) fn vp_token(&mut self, alg: &str, kid: String) -> anyhow::Result<Jwt<VpClaims>> {
        self.create_submission()?;

        let credentials = &self.credentials;
        let Some(request) = &self.request else {
            return Err(anyhow!("No request"));
        };

        let holder_did = kid.split('#').collect::<Vec<&str>>()[0];

        // presentation with 2 VCs: one as JSON, one as base64url encoded JWT
        let mut builder = VerifiablePresentation::builder()
            .add_context(String::from("https://www.w3.org/2018/credentials/examples/v1"))
            .add_type(String::from("EmployeeIDPresentation"))
            .holder(holder_did.to_string());

        for c in credentials {
            let val = serde_json::to_value(&c.issued)?;
            builder = builder.add_credential(val);
        }

        let mut vp = builder.build()?;

        let proof_type = match alg {
            "EdDSA" => "JsonWebKey2020",
            _ => "EcdsaSecp256k1VerificationKey2019",
        };

        vp.proof = Some(vec![Proof {
            id: Some(format!("urn:uuid:{}", Uuid::new_v4())),
            type_: proof_type.to_string(),
            verification_method: kid,
            created: Some(Utc::now()),
            expires: Utc::now().checked_add_signed(chrono::Duration::hours(1)),
            domain: Some(vec![request.client_id.clone()]),
            challenge: Some(request.nonce.clone()),
            ..Default::default()
        }]);

        // transform VP into signed JWT
        // TODO: support other req.credential.formats

        Ok(vp.to_jwt()?)
    }

    /// Create the Presentation Submission for the selected credentials.
    fn create_submission(&mut self) -> anyhow::Result<()> {
        let Some(request) = &self.request else {
            return Err(anyhow!("No request"));
        };

        let Some(pd) = &request.presentation_definition else {
            return Err(anyhow!("No presentation definition"));
        };

        // build a submission from the definition
        // TODO: follow definition more closely
        let mut desc_map: Vec<DescriptorMap> = vec![];

        for n in 0..pd.input_descriptors.len() {
            let in_desc = &pd.input_descriptors[n];

            let dm = DescriptorMap {
                id: in_desc.id.clone(),
                path: String::from("$"),
                path_nested: PathNested {
                    format: String::from("jwt_vc_json"),
                    // URGENT: index matched VCs not input descriptors!!
                    // path: format!("$.verifiableCredential[{n}]"),
                    path: String::from("$.verifiableCredential[0]"),
                },

                // TODO: set format dynamically
                format: String::from("jwt_vc_json"),
            };
            desc_map.push(dm);
        }

        let submission = PresentationSubmission {
            id: Uuid::new_v4().to_string(),
            definition_id: pd.id.clone(),
            descriptor_map: desc_map,
        };

        self.submission = Some(submission.clone());

        Ok(())
    }

    /// Build a token request to retrieve an access token for use in requested
    /// credentials.
    pub(crate) fn submission_request(
        &mut self, signed: String,
    ) -> anyhow::Result<(String, String)> {
        // TODO: cater for unsigned vp_tokens (JSON objects) in resposne
        // TODO: cater more than 1 vp_token in response
        let Ok(vp_token) = serde_json::to_value(signed) else {
            return Err(anyhow!(String::from("Issue deserializing vp_token")));
        };

        let Some(request) = &self.request else {
            return Err(anyhow!(String::from("Missing request")));
        };

        let req = ResponseRequest {
            vp_token: Some(vec![vp_token]),
            presentation_submission: self.submission.clone(),
            state: request.state.clone(),
        };

        let Some(mut resp_uri) = request.response_uri.clone() else {
            return Err(anyhow!("No response uri"));
        };
        resp_uri = resp_uri.trim_end_matches('/').to_string();

        Ok((resp_uri, serde_urlencoded::to_string(req)?))
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

    /// The authorization request has been authorized.
    Authorized,

    // /// The VP token is being signed (and encrypted?).
    // AwaitingVp,

    // /// The direct_post JWT is being signed .
    // AwaitingJwt,
    //
    /// The authorization request has failed, with an error message.
    Failed(String),
}
