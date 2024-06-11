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

use crate::model;

/// Application state
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct AppState {
    /// The sub-app currently active
    pub sub_app: model::SubApp,
    /// Credentials stored in the wallet
    pub credential: CredentialState,
    /// State of issuance flow (if active)
    pub issuance: Issuance,
    /// State of presentation flow (if active)
    pub presentation: Presentation,
    /// Error information
    pub error: Option<String>,
}

impl AppState {
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
        self.sub_app = model::SubApp::Credential;
        self.credential = CredentialState {
            credentials,
            current: None,
        };
        self.issuance = Issuance::default();
        self.presentation = Presentation::default();
        Ok(())
    }
}

/// Credential sub-app state
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CredentialState {
    /// List of credentials
    pub credentials: Vec<Credential>,
    /// Current credential being viewed
    pub current: Option<Credential>,
}
