//! # Issuance
//!
//! The Issuance endpoints implement the vercre-holder's credential issuance
//! flow.

pub mod accept;
pub mod cancel;
pub mod credential;
pub mod offer;
pub mod pin;
pub mod token;

use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vercre_openid::issuer::{AuthorizationDetail, CredentialOffer, Issuer, TokenResponse};

/// `Issuance` represents app state across the steps of the issuance flow.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Issuance {
    /// The unique identifier for the issuance flow. Not used internally but
    /// passed to providers so that wallet clients can track interactions
    /// with specific flows.
    pub id: String,

    /// Client ID of the holder's agent (wallet)
    pub client_id: String,

    /// Current status of the issuance flow.
    pub status: Status,

    /// The `CredentialOffer` received from the issuer.
    pub offer: CredentialOffer,

    /// Cached issuer metadata.
    pub issuer: Issuer,

    /// The list of credentials and claims the wallet wants to obtain from those
    /// offered.
    ///
    /// None implies the wallet wants all claims.
    pub accepted: Option<Vec<AuthorizationDetail>>,

    /// The user's pin, as set from the shell.
    pub pin: Option<String>,

    /// The `TokenResponse` received from the issuer.
    pub token: TokenResponse,
}

/// Helper functions for using issuance state.
impl Issuance {
    /// Creates a new issuance flow.
    #[must_use]
    pub fn new(client_id: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            client_id: client_id.to_string(),
            ..Default::default()
        }
    }
}

/// Issuance Status values.
///
/// TODO: Revisit and replace in alignment with Notification endpoint
/// implementation.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub enum Status {
    /// No credential offer is being processed.
    #[default]
    Inactive,

    /// Authorization has been requested.
    AuthRequested,

    /// A new credential offer has been received (issuer-initiated only).
    Offered,

    /// Metadata has been retrieved and the offer is ready to be viewed.
    Ready,

    /// The offer requires a user pin to progress.
    PendingPin,

    /// The offer has been accepted and is ready to get an access token.
    Accepted,

    /// The token response has been received. The user has selected some or all
    /// of the credential identifiers in the token response to progress.
    TokenReceived,

    /// A credential has been requested.
    Requested,

    /// The credential offer has failed, with an error message.
    Failed(String),
}
