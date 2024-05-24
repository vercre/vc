//! # Endpoint to authorize a presentation request
//!
//! Updates the status of the flow to `Authorized` and prepares a presentation request ready for
//! the wallet client to send. To reject a presentation request and clear the presentation state,
//! use the reset endpoint.

use std::fmt::Debug;

use tracing::instrument;
use vercre_core::error::Err;
use vercre_core::provider::{Callback, Signer, StateManager};
use vercre_core::w3c::PresentationSubmission;
use vercre_core::{err, Result};

use crate::presentation::{Presentation, Status};
use crate::store::CredentialStorer;
use crate::{Endpoint, Flow};

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
    pub async fn authorize(&self) -> Result<PresentationSubmission> {
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
    P: StateManager + Signer + Debug,
{
    type Provider = P;
    type Request = ();
    type Response = PresentationSubmission;

    async fn verify(&mut self, provider: &P, _req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        // Check we are processing a presentation and we are at the expected point in the flow.
        let Some(stashed) = provider.get_opt(&Flow::Presentation.to_string()).await? else {
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

        // Update the presentation status to `Authorized`, assuming the client will actually make
        // the request.
        let mut presentation = self.presentation.clone();
        
        presentation.status = Status::Authorized;
        provider
            .put_opt(&Flow::Presentation.to_string(), serde_json::to_vec(&presentation)?, None)
            .await?;


        todo!();
    }
}

//     // TODO: create a verifiable presentation token that matches Request Object
//     // TODO: remove hard-coded values

//     // Create a verifiable presentation token
//     // presentation with 2 VCs: one as JSON, one as base64url encoded JWT
//     pub(super) fn vp_token(&mut self, alg: &str, kid: String) -> anyhow::Result<Jwt<VpClaims>> {
//         self.create_submission()?;

//         let credentials = &self.credentials;
//         let Some(request) = &self.request else {
//             return Err(anyhow!("No request"));
//         };

//         let holder_did = kid.split('#').collect::<Vec<&str>>()[0];

//         // presentation with 2 VCs: one as JSON, one as base64url encoded JWT
//         let mut builder = VerifiablePresentation::builder()
//             .add_context(String::from("https://www.w3.org/2018/credentials/examples/v1"))
//             .add_type(String::from("EmployeeIDPresentation"))
//             .holder(holder_did.to_string());

//         for c in credentials {
//             let val = serde_json::to_value(&c.issued)?;
//             builder = builder.add_credential(val);
//         }

//         let mut vp = builder.build()?;

//         let proof_type = match alg {
//             "EdDSA" => "JsonWebKey2020",
//             _ => "EcdsaSecp256k1VerificationKey2019",
//         };

//         vp.proof = Some(vec![Proof {
//             id: Some(format!("urn:uuid:{}", Uuid::new_v4())),
//             type_: proof_type.to_string(),
//             verification_method: kid,
//             created: Some(Utc::now()),
//             expires: Utc::now().checked_add_signed(TimeDelta::try_hours(1).unwrap_or_default()),
//             domain: Some(vec![request.client_id.clone()]),
//             challenge: Some(request.nonce.clone()),
//             ..Default::default()
//         }]);

//         // transform VP into signed JWT
//         // TODO: support other req.credential.formats

//         Ok(vp.to_jwt()?)
//     }

//     /// Create the Presentation Submission for the selected credentials.
//     fn create_submission(&mut self) -> anyhow::Result<()> {
//         let Some(request) = &self.request else {
//             return Err(anyhow!("No request"));
//         };

//         let Some(pd) = &request.presentation_definition else {
//             return Err(anyhow!("No presentation definition"));
//         };

//         // build a submission from the definition
//         // TODO: follow definition more closely
//         let mut desc_map: Vec<DescriptorMap> = vec![];

//         for n in 0..pd.input_descriptors.len() {
//             let in_desc = &pd.input_descriptors[n];

//             let dm = DescriptorMap {
//                 id: in_desc.id.clone(),
//                 path: String::from("$"),
//                 path_nested: PathNested {
//                     format: String::from("jwt_vc_json"),
//                     // URGENT: index matched VCs not input descriptors!!
//                     // path: format!("$.verifiableCredential[{n}]"),
//                     path: String::from("$.verifiableCredential[0]"),
//                 },

//                 // TODO: set format dynamically
//                 format: String::from("jwt_vc_json"),
//             };
//             desc_map.push(dm);
//         }

//         let submission = PresentationSubmission {
//             id: Uuid::new_v4().to_string(),
//             definition_id: pd.id.clone(),
//             descriptor_map: desc_map,
//         };

//         self.submission = Some(submission);

//         Ok(())
//     }

//     /// Build a token request to retrieve an access token for use in requested
//     /// credentials.
//     pub(crate) fn submission_request(&self, signed: String) -> anyhow::Result<(String, String)> {
//         // TODO: cater for unsigned vp_tokens (JSON objects) in resposne
//         // TODO: cater more than 1 vp_token in response
//         let Ok(vp_token) = serde_json::to_value(signed) else {
//             return Err(anyhow!(String::from("Issue deserializing vp_token")));
//         };

//         let Some(request) = &self.request else {
//             return Err(anyhow!(String::from("Missing request")));
//         };

//         let req = ResponseRequest {
//             vp_token: Some(vec![vp_token]),
//             presentation_submission: self.submission.clone(),
//             state: request.state.clone(),
//         };

//         let Some(mut resp_uri) = request.response_uri.clone() else {
//             return Err(anyhow!("No response uri"));
//         };
//         resp_uri = resp_uri.trim_end_matches('/').to_string();

//         Ok((resp_uri, serde_urlencoded::to_string(req)?))
//     }
// }
