//! Application state implementation for issuance operations.

use vercre_holder::{CredentialOffer, OfferRequest, PinRequest};

use super::{AppState, SubApp};
use crate::provider::Provider;
use crate::CLIENT_ID;

impl AppState {
    /// Process a credential issuance offer.
    pub async fn offer(&mut self, encoded_offer: &str, provider: Provider) -> anyhow::Result<()> {
        let offer_str = urlencoding::decode(encoded_offer)?;
        let offer = serde_json::from_str::<CredentialOffer>(&offer_str)?;
        let request = OfferRequest {
            client_id: CLIENT_ID.into(),
            offer,
        };
        let issuance = vercre_holder::offer(provider, &request).await?;
        self.issuance = issuance;
        self.sub_app = SubApp::Issuance;
        Ok(())
    }

    /// Accept a credential issuance offer.
    pub async fn accept(&mut self, provider: Provider) -> anyhow::Result<()> {
        let issuance = vercre_holder::accept(provider, self.issuance.id.clone()).await?;
        self.issuance = issuance;
        Ok(())
    }

    /// Set a PIN
    pub async fn pin(&mut self, provider: Provider, pin: &str) -> anyhow::Result<()> {
        let request = PinRequest {
            id: self.issuance.id.clone(),
            pin: pin.into(),
        };
        let issuance = vercre_holder::pin(provider, &request).await?;
        self.issuance = issuance;
        Ok(())
    }

    /// Get the credentials for the accepted issuance offer.
    pub async fn get_credentials(&mut self, provider: Provider) -> anyhow::Result<()> {
        vercre_holder::get_credentials(provider,self.issuance.id.clone()).await?;
        self.sub_app = SubApp::Credential;
        Ok(())
    }
}
