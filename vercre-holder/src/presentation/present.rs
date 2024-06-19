//! # Presentation Present Endpoint
//!
//! The `present` endpoint creates a presentation submission, signs it, and sends it to the
//! verifier.

use std::fmt::Debug;

use anyhow::anyhow;
use openid4vc::error::Err;
use openid4vc::presentation::{ResponseRequest, ResponseResponse};
use openid4vc::{err, Result};
use tracing::instrument;
use uuid::Uuid;
use vercre_exch::{DescriptorMap, PathNested, PresentationSubmission};
use vercre_vc::model::vp::VerifiablePresentation;
use vercre_vc::proof::{self, Format, Payload};

use super::{Presentation, Status};
use crate::provider::{Callback, Signer, StateManager, Verifier, VerifierClient};
use crate::Endpoint;

impl<P> Endpoint<P>
where
    P: Callback + Signer + StateManager + Verifier + VerifierClient + Clone + Debug,
{
    /// Creates a presentation submission, signs it and sends it to the verifier. The `request`
    /// parameter is the presentation flow ID of an authorized presentation request created in
    /// prior steps.
    #[instrument(level = "debug", skip(self))]
    pub async fn present(&self, request: &String) -> Result<ResponseResponse> {
        let ctx = Context {
            presentation: Presentation::default(),
            _p: std::marker::PhantomData,
        };
        core_utils::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug, Default)]
struct Context<P> {
    presentation: Presentation,
    _p: std::marker::PhantomData<P>,
}

impl<P> core_utils::Context for Context<P>
where
    P: Signer + StateManager + VerifierClient + Verifier + Clone + Debug,
{
    type Provider = P;
    type Request = String;
    type Response = ResponseResponse;

    async fn verify(&mut self, provider: &Self::Provider, req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        let current_state = provider.get(req).await?;
        let Ok(presentation) = serde_json::from_slice::<Presentation>(&current_state) else {
            err!(Err::InvalidRequest, "unable to decode presentation state");
        };
        if presentation.status != Status::Authorized {
            err!(Err::InvalidRequest, "Invalid presentation state");
        }
        self.presentation = presentation;

        Ok(self)
    }

    async fn process(
        &self, provider: &Self::Provider, _req: &Self::Request,
    ) -> Result<Self::Response> {
        let mut presentation = self.presentation.clone();

        // Construct a presentation submission.
        let submission = create_submission(&presentation)?;
        presentation.submission = submission.clone();

        // create vp
        let kid = &provider.verification_method();
        let holder_did = kid.split('#').collect::<Vec<&str>>()[0];

        let vp = create_vp(&presentation, holder_did)?;

        let payload = Payload::Vp {
            vp,
            client_id: presentation.request.client_id.clone(),
            nonce: presentation.request.nonce.clone(),
        };
        let jwt = proof::create(Format::JwtVcJson, payload, provider.clone()).await?;

        let vp_token = serde_json::to_value(&jwt)?;

        // Assemble the presentation response to the verifier and ask the wallet client to send it.
        let res_req = ResponseRequest {
            vp_token: Some(vec![vp_token]),
            presentation_submission: Some(submission),
            state: presentation.request.state.clone(),
        };
        let Some(mut res_uri) = presentation.request.response_uri.clone() else {
            err!(Err::InvalidRequest, "no response uri found");
        };
        res_uri = res_uri.trim_end_matches('/').to_string();

        let response = provider.present(&self.presentation.id, &res_uri, &res_req).await?;

        Ok(response)
    }
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
    // presentation with 2 VCs: one as JSON, one as base64url encoded JWT
    let mut builder = VerifiablePresentation::builder()
        .add_context(vercre_vc::model::Context::Url(
            "https://www.w3.org/2018/credentials/examples/v1".into(),
        ))
        .add_type(String::from("EmployeeIDPresentation"))
        .holder(holder_did);

    for c in &presentation.credentials {
        let val = serde_json::to_value(&c.issued)?;
        builder = builder.add_credential(val);
    }

    builder.build()
}
