//! Application state implementation for presentation operations.

use super::{AppState, SubApp};
use crate::provider::Provider;

impl AppState {
    /// Process a presentation request.
    pub async fn request(&mut self, request: &str, provider: Provider) -> anyhow::Result<()> {
        let presentation = vercre_holder::request(provider, &request.into()).await?;
        self.presentation = presentation;
        self.sub_app = SubApp::Presentation;
        Ok(())
    }

    /// Authorize the presentation request.
    pub async fn authorize(&mut self, provider: Provider) -> anyhow::Result<()> {
        let presentation = vercre_holder::authorize(provider, self.presentation.id.clone()).await?;
        self.presentation = presentation;
        Ok(())
    }

    /// Present the authorized presentation request.
    pub async fn present(&self, provider: Provider) -> anyhow::Result<()> {
        let _response = vercre_holder::present(provider, self.presentation.id.clone()).await?;
        Ok(())
    }
}
