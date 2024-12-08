//! Application state implementation for issuance operations.

use anyhow::bail;
use test_utils::issuer::NORMAL_USER;
use vercre_holder::issuance::{AcceptRequest, CredentialsRequest, FlowType, IssuanceState, PinRequest};
use vercre_holder::provider::Issuer;
use vercre_holder::{CredentialOffer, MetadataRequest, OAuthServerRequest};

use super::{AppState, SubApp};
use crate::provider::Provider;
use crate::CLIENT_ID;

impl AppState {
    /// Process a credential issuance offer.
    pub async fn offer(&mut self, encoded_offer: &str, provider: Provider) -> anyhow::Result<()> {
        let offer_str = urlencoding::decode(encoded_offer)?;
        let offer = serde_json::from_str::<CredentialOffer>(&offer_str)?;

        // Check the offer has a pre-authorized grant. This is the only flow
        // type supported by this example.
        let Some(grants) = &offer.grants else {
            bail!("no grants in offer is not supported");
        };
        if grants.pre_authorized_code.is_none() {
            bail!("grant other than pre-authorized code is not supported");
        }

        // Initiate flow state.
        let mut state = IssuanceState::new(FlowType::IssuerPreAuthorized, CLIENT_ID, NORMAL_USER);

        // Add issuer metadata to flow state.
        let metadata_request = MetadataRequest {
            credential_issuer: offer.credential_issuer.clone(),
            languages: None,
        };
        let issuer_metadata = provider.metadata(metadata_request).await?;
        state.issuer(issuer_metadata.credential_issuer)?;

        // Add authorization server metadata to flow state.
        let auth_request = OAuthServerRequest {
            credential_issuer: offer.credential_issuer.clone(),
            issuer: None,
        };
        let auth_metadata = provider.oauth_server(auth_request).await?;
        state.authorization_server(auth_metadata.authorization_server)?;

        // Unpack the offer into the flow state.
        state.offer(&offer)?;
    
        self.issuance = state;
        self.sub_app = SubApp::Issuance;
        Ok(())
    }

    /// Accept a credential issuance offer.
    pub async fn accept(&self, provider: Provider) -> anyhow::Result<()> {
        // Just accept whatever is offered. In a real app, the user would need
        // to select which credentials to accept.
        let req = AcceptRequest {
            issuance_id: self.issuance.id.clone(),
            accept: None, // implies accept all
        };
        vercre_holder::issuance::accept(provider, &req).await?;
        Ok(())
    }

    /// Set a PIN
    pub async fn pin(&mut self, provider: Provider, pin: &str) -> anyhow::Result<()> {
        let request = PinRequest {
            issuance_id: self.issuance.id.clone(),
            pin: pin.into(),
        };
        vercre_holder::issuance::pin(provider, &request).await?;
        self.issuance.pin = Some(pin.into());
        Ok(())
    }

    /// Get the credentials for the accepted issuance offer.
    pub async fn credentials(&self, provider: Provider) -> anyhow::Result<()> {
        log::info!("Getting an access token for issuance {}", self.issuance.id);
        vercre_holder::issuance::token(provider.clone(), &self.issuance.id).await?;

        log::info!("Getting credentials for issuance {}", self.issuance.id);
        let request = CredentialsRequest {
            issuance_id: self.issuance.id.clone(),
            credential_identifiers: None,
            format: None,
        };
        vercre_holder::issuance::credentials(provider, &request).await?;
        Ok(())
    }

    /// Save the credential to storage.
    pub async fn save(&self, provider: Provider) -> anyhow::Result<()> {
        let request = vercre_holder::issuance::SaveRequest {
            issuance_id: self.issuance.id.clone(),
        };
        vercre_holder::issuance::save(provider, &request).await?;
        Ok(())
    }
}
