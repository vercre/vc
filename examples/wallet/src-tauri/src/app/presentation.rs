//! Application state implementation for presentation operations.

use anyhow::bail;
use vercre_holder::credential::Credential;
use vercre_holder::presentation::{
    parse_request_object_response, Authorized, NotAuthorized, PresentationFlow,
};
use vercre_holder::proof::{self, Payload, W3cFormat};
use vercre_holder::provider::{CredentialStorer, Verifier};
use vercre_holder::Signer;

use super::{AppState, SubApp};
use crate::provider::Provider;

/// Presentation flow state.
#[derive(Clone, Debug, Default)]
pub enum PresentationState {
    /// No presentation is in progress.
    #[default]
    Inactive,

    /// A presentation request as a URI has been received and needs to be
    /// resolved.
    Requested(PresentationFlow<NotAuthorized>, Vec<Credential>),

    /// A presentation request has been authorized.
    Authorized(PresentationFlow<Authorized>),
}

impl AppState {
    /// Process a presentation request.
    pub async fn request(&mut self, request: &str, provider: Provider) -> anyhow::Result<()> {
        // Need to determine the type of request - URI or URLEncoded request object.
        let req_obj = if let Some(req) = vercre_holder::presentation::parse_request_object(request)?
        {
            req
        } else {
            let url = urlencoding::decode(request)?;
            let pv = provider.clone();
            let request_object_response = pv.request_object(&url).await?;
            parse_request_object_response(&request_object_response, pv).await?
        };
        let flow = PresentationFlow::<NotAuthorized>::new(req_obj)?;
        let filter = flow.filter()?;
        let credentials = provider.find(Some(filter)).await?;
        let state = PresentationState::Requested(flow, credentials);

        self.presentation = state;
        self.sub_app = SubApp::Presentation;
        Ok(())
    }

    /// Authorize the presentation request.
    pub fn authorize(&mut self) -> anyhow::Result<()> {
        self.presentation = match &self.presentation {
            PresentationState::Requested(flow, credentials) => {
                let flow = flow.clone();
                let flow = flow.authorize(&credentials.clone());
                PresentationState::Authorized(flow)
            }
            _ => bail!("expected requested presentation state"),
        };
        Ok(())
    }

    /// Present the authorized presentation request.
    pub async fn present(&self, provider: Provider) -> anyhow::Result<()> {
        let PresentationState::Authorized(flow) = &self.presentation else {
            bail!("expected authorized presentation state");
        };
        let kid = provider.verification_method().await?;
        let vp = flow.payload(&kid)?;
        let Payload::Vp { vp, client_id, nonce } = vp else {
            bail!("expected verifiable presentation payload type");
        };
        let jwt =
            proof::create(W3cFormat::JwtVcJson, Payload::Vp { vp, client_id, nonce }, &provider)
                .await?;
        let (res_req, uri) = flow.create_response_request(&jwt);
        let _response = provider.present(uri.as_deref(), &res_req).await?;
        Ok(())
    }
}
