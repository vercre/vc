//! # Issuance
//!
//! The Issuance endpoints implement the vercre-holder's credential issuance flow.

mod accept;
mod credential;
mod offer;
mod pin;

use std::collections::HashMap;
use std::fmt::Debug;

use chrono::{DateTime, Utc};
pub use offer::OfferRequest;
pub use openid4vc::issuance::{
    CredentialConfiguration, CredentialOffer, CredentialRequest, CredentialResponse, GrantType,
    Issuer, MetadataRequest, MetadataResponse, Proof, ProofClaims, TokenRequest, TokenResponse,
    TxCode,
};
pub use pin::PinRequest;
use serde::{Deserialize, Serialize};

use serde::{Deserialize, Serialize};

use crate::provider::StateManager;
use crate::Endpoint;

/// `Issuance` represents app state across the steps of the issuance flow.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Issuance {
    /// The unique identifier for the issuance flow. Not used internally but passed to providers
    /// so that wallet clients can track interactions with specific flows.
    pub id: String,

    /// Client ID of the holder's agent (eg. wallet)
    pub client_id: String,

    /// The current status of the issuance flow.
    pub status: Status,

    /// The `CredentialOffer` received from the issuer.
    pub offer: CredentialOffer,

    /// A list of `CredentialConfiguration`s, one for each credential offered.
    pub offered: HashMap<String, CredentialConfiguration>,

    /// The user's pin, as set from the shell.
    pub pin: Option<String>,

    /// The `TokenResponse` received from the issuer.
    pub token: TokenResponse,
}

/// Issuance Status values.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename = "IssuanceStatus")]
pub enum Status {
    /// No credential offer is being processed.
    #[default]
    Inactive,

    /// A new credential offer has been received.
    Offered,

    /// Metadata has been retrieved and the offer is ready to be viewed.
    Ready,

    /// The offer requires a user pin to progress.
    PendingPin,

    /// The offer has been accepted and the credential is being issued.
    Accepted,

    /// A credential has been requested.
    Requested,

    /// The credential offer has failed, with an error message.
    Failed(String),
}

/// Get and put issuance state information using the supplied provider.
impl<P> Endpoint<P>
where
    P: StateManager + Debug,
{
    async fn get_issuance(&self, id: &str) -> anyhow::Result<Issuance> {
        let current_state = self.provider.get(id).await?;
        let issuance = serde_json::from_slice::<Issuance>(&current_state)?;
        Ok(issuance)
    }

    async fn put_issuance(&self, issuance: &Issuance) -> anyhow::Result<()> {
        self.provider
            .put(&issuance.id, serde_json::to_vec(&issuance)?, DateTime::<Utc>::MAX_UTC)
            .await?;
        Ok(())
    }
}
