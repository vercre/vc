//! Application state implementation for issuance operations.

use vercre_holder::issuance::{CredentialOffer, OfferRequest};
use vercre_holder::Endpoint;

use crate::app::AppState;
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
}
