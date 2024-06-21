//! Application state implementation for presentation operations.

use vercre_holder::Endpoint;

use crate::provider::Provider;
use super::{AppState, SubApp};

impl AppState {
    /// Process a presentation request.
    pub async fn request(&mut self, request: &str, provider: Provider) -> anyhow::Result<()> {
        let presentation = Endpoint::new(provider).request(&request.into()).await?;
        self.presentation = presentation;
        self.sub_app = SubApp::Presentation;
        Ok(())
    }

    /// Authorize the presentation request.
    pub async fn authorize(&mut self, provider: Provider) -> anyhow::Result<()> {
        let presentation = Endpoint::new(provider).authorize(self.presentation.id.clone()).await?;
        self.presentation = presentation;
        Ok(())
    }

    /// Present the authorized presentation request.
    pub async fn present(&self, provider: Provider) -> anyhow::Result<()> {
        let _response = Endpoint::new(provider).present(self.presentation.id.clone()).await?;
        Ok(())
    }
}
