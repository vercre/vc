use anyhow::anyhow;
use vercre_holder::Issuance;
use vercre_holder::Presentation;
use vercre_holder::provider::CredentialStorer;

use crate::app::{AppState, SubApp};

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
        self.sub_app = SubApp::Credential;
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
