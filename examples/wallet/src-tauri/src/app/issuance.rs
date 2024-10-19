//! Application state implementation for issuance operations.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use vercre_holder::issuance::{AcceptRequest, CredentialsRequest, OfferRequest, PinRequest};
use vercre_holder::{CredentialConfiguration, CredentialOffer, TxCode};

use super::{AppState, SubApp};
use crate::provider::Provider;
use crate::CLIENT_ID;

/// Application state for the issuance sub-app.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct IssuanceState {
    /// Issuance flow identifier to pass to the vercre-holder crate for state
    /// management.
    pub id: String,
    /// Issuer of the credential(s)
    pub issuer: String,
    /// Description of the credential(s) offered, keyed by credential
    /// configuration ID.
    pub offered: HashMap<String, CredentialConfiguration>,
    /// Description of the type of PIN needed to accept the offer.
    pub tx_code: Option<TxCode>,
    /// PIN set by the holder.
    pub pin: Option<String>,
}

impl AppState {
    /// Process a credential issuance offer.
    pub async fn offer(&mut self, encoded_offer: &str, provider: Provider) -> anyhow::Result<()> {
        let offer_str = urlencoding::decode(encoded_offer)?;
        let offer = serde_json::from_str::<CredentialOffer>(&offer_str)?;
        let request = OfferRequest {
            client_id: CLIENT_ID.into(),
            subject_id: test_utils::issuer::NORMAL_USER.into(),
            offer,
        };
        let res = vercre_holder::issuance::offer(provider, &request).await?;

        // This example can only process an issuer-initiated, pre-authorized issuance
        // flow.
        let tx_code = if let Some(grants) = res.grants {
            if let Some(pre_auth_code) = grants.pre_authorized_code {
                pre_auth_code.tx_code
            } else {
                None
            }
        } else {
            None
        };

        self.issuance = IssuanceState {
            id: res.issuance_id,
            issuer: res.issuer,
            offered: res.offered,
            tx_code,
            pin: None,
        };
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
