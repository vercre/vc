//! # Endpoint to authorize a presentation request
//!
//! Updates the status of the flow to `Authorized` and prepares a presentation request ready for
//! the wallet client to send. To reject a presentation request and clear the presentation state,
//! use the reset endpoint.

use std::fmt::Debug;

use anyhow::anyhow;
use chrono::{TimeDelta, Utc};
use tracing::instrument;
use uuid::Uuid;
use vercre_core::error::Err;
use vercre_core::jwt::Jwt;
use vercre_core::vp::ResponseRequest;
use vercre_core::w3c::{
    Claims, DescriptorMap, PathNested, PresentationSubmission, Proof, VerifiablePresentation,
};
use vercre_core::{err, Result};

use crate::credential::Credential;
use crate::presentation::{Presentation, Status};
use crate::provider::{Callback, CredentialStorer, Signer, StateManager};
use crate::Endpoint;

impl<P> Endpoint<P>
where
    P: Callback + Signer + StateManager + Clone + Debug + CredentialStorer,
{
    /// Authorize endpoint updates the presentation status to `Authorized` when the Holder has
    /// accepted a presentation request and constructs a presentation submission for the wallet
    /// client to send to the verifier. Returns the response URI and the presentation.
    ///
    /// # Errors
    ///
    /// Returns an error if the presentation state is invalid or the provider is unavailable.
    #[instrument(level = "debug", skip(self))]
    pub async fn authorize(&self) -> Result<(String, ResponseRequest)> {
        let ctx = Context {
            _p: std::marker::PhantomData,
            presentation: Presentation::default(),
        };

        vercre_core::Endpoint::handle_request(self, &(), ctx).await
    }
}

#[derive(Debug, Default)]
struct Context<P> {
    _p: std::marker::PhantomData<P>,
    presentation: Presentation,
}

impl<P> vercre_core::Context for Context<P>
where
    P: StateManager + Signer + CredentialStorer + Debug,
{
    type Provider = P;
    type Request = ();
    type Response = (String, ResponseRequest);

    async fn verify(&mut self, provider: &P, _req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        // Check we are processing a presentation and we are at the expected point in the flow.
        let Some(stashed) = provider.get_opt("presentation").await? else {
            err!(Err::InvalidRequest, "no presentation in progress");
        };
        let presentation: Presentation = serde_json::from_slice(&stashed)?;
        if presentation.status != Status::Requested {
            err!(Err::InvalidRequest, "invalid presentation status");
        }

        Ok(self)
    }

    async fn process(&self, provider: &P, _req: &Self::Request) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        let mut presentation = self.presentation.clone();
        let request = presentation.request.clone();

        // Get credentials from the wallet's storage that match the constraints in the request.
        let credentials = provider.find(presentation.filter.clone()).await?;

        // Construct a token
        let token = vp_token(
            &presentation,
            &credentials,
            &provider.algorithm().to_string(),
            &provider.verification_method(),
        )?;
        let vp_token = match serde_json::to_value(token) {
            Ok(v) => v,
            Err(e) => err!(Err::ServerError(e.into()), "issue serializing vp_token"),
        };

        // Construct a presentation submission
        let submission = create_submission(&presentation)?;

        // Assemble response and URI
        let req = ResponseRequest {
            vp_token: Some(vec![vp_token]),
            presentation_submission: Some(submission),
            state: request.state.clone(),
        };

        let Some(mut res_uri) = request.response_uri.clone() else {
            err!(Err::InvalidRequest, "no response uri");
        };
        res_uri = res_uri.trim_end_matches('/').to_string();

        // Update the presentation status to `Authorized`, assuming the client will actually make
        // the request.
        presentation.status = Status::Authorized;
        provider.put_opt("presentation", serde_json::to_vec(&presentation)?, None).await?;

        Ok((res_uri, req))
    }
}

fn vp_token(
    presentation: &Presentation, credentials: &[Credential], alg: &str, kid: &str,
) -> anyhow::Result<Jwt<Claims>> {
    let request = presentation.request.clone();
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
        verification_method: kid.to_string(),
        created: Some(Utc::now()),
        expires: Utc::now().checked_add_signed(TimeDelta::try_hours(1).unwrap_or_default()),
        domain: Some(vec![request.client_id.clone()]),
        challenge: Some(request.nonce.clone()),
        ..Default::default()
    }]);

    // transform VP into signed JWT
    // TODO: support other req.credential.formats

    Ok(vp.to_jwt()?)
}

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
