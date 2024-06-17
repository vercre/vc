//! Application state implementation for issuance operations.

// use vercre_holder::credential::Credential;
use vercre_holder::issuance::{CredentialOffer, OfferRequest};
use vercre_holder::Endpoint;

use super::{AppState, SubApp};
use crate::provider::Provider;
use crate::CLIENT_ID;

impl AppState {
    /// Process a credential issuance offer.
    pub async fn offer<R>(
        &mut self, encoded_offer: &str, provider: Provider<R>,
    ) -> anyhow::Result<()>
    where
        R: tauri::Runtime,
    {
        let offer_str = urlencoding::decode(encoded_offer)?;
        let offer = serde_json::from_str::<CredentialOffer>(&offer_str)?;
        let request = OfferRequest {
            client_id: CLIENT_ID.into(),
            offer,
        };
        let new_state = Endpoint::new(provider).offer(&request).await?;
        self.issuance = new_state;
        self.sub_app = SubApp::Issuance;
        Ok(())
    }

    /// Accept a credential issuance offer.
    pub async fn accept<R>(&mut self, provider: Provider<R>) -> anyhow::Result<()>
    where
        R: tauri::Runtime,
    {
        let new_state = Endpoint::new(provider).accept(self.issuance.id.clone()).await?;
        self.issuance = new_state;
        Ok(())
    }

    /// Set a PIN
    pub async fn pin<R>(&mut self, provider: Provider<R>) -> anyhow::Result<()>
    where
        R: tauri::Runtime,
    {
        let new_state = Endpoint::new(provider).pin(self.issuance.id.clone()).await?;
        self.issuance = new_state;
        Ok(())
    }

    // /// Get the credentials for the accepted issuance offer.
    // pub async fn get_credentials<R>(&mut self, _provider: Provider<R>) -> anyhow::Result<Vec<Credential>>
    // where
    //     R: tauri::Runtime,
    // {
    //     // let new_state = Endpoint::new(provider).get_credentials(self.issuance.id.clone()).await?;
    //     // self.issuance = new_state;
    //     todo!();
    // }
}
