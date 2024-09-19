//! Application state implementation for presentation operations.

use serde::{Deserialize, Serialize};
use vercre_holder::Credential;

use super::{AppState, SubApp};
use crate::provider::Provider;

/// Presentation state for the presentation sub-app.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct PresentationState {
    /// Presentation flow identifier to pass to the vercre-holder crate for
    /// state management.
    pub id: String,

    /// Status of the presentation flow.
    pub status: vercre_holder::PresentationStatus,

    /// List of credentials matching the verifier's request.
    pub credentials: Vec<Credential>,
}

impl AppState {
    /// Process a presentation request.
    pub async fn request(&mut self, request: &str, provider: Provider) -> anyhow::Result<()> {
        let response = vercre_holder::request(provider, &request.into()).await?;
        self.presentation = PresentationState {
            id: response.presentation_id,
            status: response.status,
            credentials: response.credentials,
        };
        self.sub_app = SubApp::Presentation;
        Ok(())
    }

    /// Authorize the presentation request.
    pub async fn authorize(&mut self, provider: Provider) -> anyhow::Result<()> {
        let status = vercre_holder::authorize(provider, self.presentation.id.clone()).await?;
        self.presentation.status = status;
        Ok(())
    }

    /// Present the authorized presentation request.
    pub async fn present(&self, provider: Provider) -> anyhow::Result<()> {
        let _response = vercre_holder::present(provider, self.presentation.id.clone()).await?;
        Ok(())
    }
}
