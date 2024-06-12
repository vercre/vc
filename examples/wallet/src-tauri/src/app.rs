//! This module has types for the application state. The application is divided into sub-apps,
//! so the shape of the state depends on whether the application is managing credentials,
//! responding to an offer of issuance, or responding to a request for presentation. The underlying
//! application state is translated into a view model for the shell to render.

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use vercre_holder::credential::Credential;
use vercre_holder::issuance::Issuance;
use vercre_holder::presentation::Presentation;
use vercre_holder::provider::CredentialStorer;

use crate::view;

/// Application state
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct AppState {
    /// The sub-app currently active
    pub sub_app: view::SubApp,
    /// Credentials stored in the wallet
    pub credential: Vec<Credential>,
    /// State of issuance flow (if active)
    pub issuance: Issuance,
    /// State of presentation flow (if active)
    pub presentation: Presentation,
    /// Error information
    pub error: Option<String>,
}

impl AppState {
    /// Set the application state to a startup state.
    pub fn init(&mut self) {
        self.sub_app = view::SubApp::Splash;
        self.credential = Vec::new();
        self.issuance = Issuance::default();
        self.presentation = Presentation::default();
        self.error = None;
    }

    /// Reset the application state to its default values.
    ///
    /// # Error
    ///
    /// If loading the credentials from the credential store fails, an error is returned.
    pub async fn reset(&mut self, credential_store: impl CredentialStorer) -> anyhow::Result<()> {
        self.error = None;
        let credentials = match credential_store.find(None).await {
            Ok(creds) => creds,
            Err(e) => {
                self.error = Some(e.to_string());
                return Err(anyhow!("Failed to load credentials"));
            }
        };
        self.sub_app = view::SubApp::Credential;
        self.credential = credentials;
        self.issuance = Issuance::default();
        self.presentation = Presentation::default();
        Ok(())
    }

    /// Remove a credential from the wallet.
    pub async fn delete(
        &mut self, id: &str, credential_store: impl CredentialStorer,
    ) -> anyhow::Result<()> {
        match credential_store.remove(id).await {
            Ok(()) => {
                self.credential.retain(|c| c.id != id);
                Ok(())
            }
            Err(e) => {
                self.error = Some(e.to_string());
                Err(anyhow!("Failed to delete credential"))
            }
        }
    }
}
