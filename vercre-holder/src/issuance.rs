//! # Issuance
//!
//! The Issuance endpoints implement the vercre-holder's credential issuance
//! flow.

pub(crate) mod accept;
pub(crate) mod authorize;
pub(crate) mod cancel;
pub(crate) mod credential;
pub(crate) mod offer;
pub(crate) mod pin;
pub(crate) mod token;

use std::fmt::Debug;

pub use accept::{accept, AcceptRequest, AuthorizationSpec};
pub use authorize::{authorize, AuthorizeRequest, Initiator};
pub use cancel::cancel;
pub use credential::{credentials, CredentialsRequest};
pub use offer::{offer, OfferRequest, OfferResponse};
pub use pin::{pin, PinRequest};
use serde::{Deserialize, Serialize};
pub use token::{token, AuthorizedCredentials};
use uuid::Uuid;
use vercre_issuer::MetadataRequest;
use vercre_openid::issuer::{AuthorizationDetail, CredentialOffer, Issuer, Server, TokenResponse};

use crate::provider::{HolderProvider, Issuer as IssuerProvider};

/// `Issuance` represents app state across the steps of the issuance flow.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Issuance {
    /// The unique identifier for the issuance flow. Not used internally but
    /// passed to providers so that wallet clients can track interactions
    /// with specific flows.
    pub id: String,

    /// Client ID of the holder's agent (wallet)
    pub client_id: String,

    /// ID of the holder
    pub subject_id: String,

    /// Current status of the issuance flow.
    pub status: Status,

    /// The `CredentialOffer` received from the issuer.
    pub offer: CredentialOffer,

    /// Cached issuer metadata.
    pub issuer: Issuer,

    /// Cached authorization server metadata.
    pub authorization_server: Server,

    /// The list of credentials and claims the wallet wants to obtain from those
    /// offered.
    ///
    /// None implies the wallet wants all claims.
    pub accepted: Option<Vec<AuthorizationDetail>>,

    /// The user's pin, as set from the shell.
    pub pin: Option<String>,

    /// PKCE code verifier for the authorization code flow.
    pub code_verifier: Option<String>,

    /// PKCE code challenge for the authorization code flow.
    pub code_challenge: Option<String>,

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

    /// Gets issuer metadata from the provider and sets that information on
    /// the issuance flow state.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider's metadata request fails.
    pub async fn set_issuer(
        &mut self, provider: &impl HolderProvider, credential_issuer: &str,
    ) -> anyhow::Result<()> {
        let md_request = MetadataRequest {
            credential_issuer: credential_issuer.into(),
            languages: None, // The wallet client should provide any specific languages required.
        };
        let md_response = IssuerProvider::metadata(provider, md_request).await?;
        self.issuer = md_response.credential_issuer;
        self.authorization_server = md_response.authorization_server;
        Ok(())
    }
}

/// Issuance flow status values.
///
/// Used to verify the state of a flow before executing the logic for an
/// endpoint.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub enum Status {
    /// No credential offer is being processed.
    #[default]
    Inactive,

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
