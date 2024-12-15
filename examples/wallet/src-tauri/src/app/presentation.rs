//! Application state implementation for presentation operations.

use anyhow::bail;
use vercre_holder::presentation::PresentationState;
use vercre_holder::provider::{CredentialStorer, Verifier};
use vercre_holder::Signer;
use vercre_holder::proof::{self, Payload, W3cFormat};

use super::{AppState, SubApp};
use crate::provider::Provider;

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
            PresentationState::parse_request_object_response(&request_object_response, pv).await?
        };
        let mut state = PresentationState::new();
        let filter = state.request(&req_obj)?;
        let credentials = provider.find(Some(filter)).await?;
        state.credentials(&credentials)?;

        self.presentation = state;
        self.sub_app = SubApp::Presentation;
        Ok(())
    }

    /// Authorize the presentation request.
    pub fn authorize(&mut self) -> anyhow::Result<()> {
        self.presentation.authorize()
    }

    /// Present the authorized presentation request.
    pub async fn present(&mut self, provider: Provider) -> anyhow::Result<()> {
        let kid = provider.verification_method().await?;
        let vp = self.presentation.create_verifiable_presentation_payload(&kid)?;
        let Payload::Vp { vp, client_id, nonce } = vp else {
            bail!("expected verifiable presentation payload type");
        };
        let jwt =
            proof::create(W3cFormat::JwtVcJson, Payload::Vp { vp, client_id, nonce }, &provider)
                .await?;
        let (res_req, uri) = self.presentation.create_response_request(&jwt);
        let _response = provider.present(uri.as_deref(), &res_req).await?;
        Ok(())
    }
}
