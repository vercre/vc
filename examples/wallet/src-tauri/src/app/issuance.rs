//! Application state implementation for issuance operations.

// use vercre_holder::credential::Credential;
use vercre_holder::issuance::{CredentialOffer, OfferRequest, PinRequest};
use vercre_holder::Endpoint;

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
        let new_state = Endpoint::new(provider).offer(&request).await?;
        self.issuance = new_state;
        self.sub_app = SubApp::Issuance;
        Ok(())
    }

    /// Accept a credential issuance offer.
    pub async fn accept(&mut self, provider: Provider) -> anyhow::Result<()> {
        let issuance = Endpoint::new(provider).accept(self.issuance.id.clone()).await?;
        self.issuance = issuance;
        Ok(())
    }

    /// Set a PIN
    pub async fn pin(&mut self, provider: Provider, pin: &str) -> anyhow::Result<()> {
        let request = PinRequest {
            id: self.issuance.id.clone(),
            pin: pin.into(),
        };
        let issuance = Endpoint::new(provider).pin(&request).await?;
        self.issuance = issuance;
        Ok(())
    }

    /// Get the credentials for the accepted issuance offer.
    pub async fn get_credentials(&mut self, provider: Provider) -> anyhow::Result<()> {
        Endpoint::new(provider).get_credentials(self.issuance.id.clone()).await?;
        self.sub_app = SubApp::Credential;
        Ok(())
    }
}
