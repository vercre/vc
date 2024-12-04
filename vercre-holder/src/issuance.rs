//! # Issuance
//!
//! The Issuance endpoints implement the vercre-holder's credential issuance
//! flow.

pub(crate) mod accept;
pub(crate) mod authorize;
pub(crate) mod cancel;
pub(crate) mod credentials;
pub(crate) mod deferred;
pub(crate) mod offer;
pub(crate) mod pin;
pub(crate) mod save;
pub(crate) mod token;

use std::collections::HashMap;
use std::fmt::Debug;

pub use accept::{accept, AcceptRequest, AuthorizationSpec};
use anyhow::bail;
pub use authorize::{authorize, AuthorizeRequest, Initiator};
pub use cancel::{cancel, CancelRequest};
pub use credentials::{credentials, CredentialsRequest, CredentialsResponse};
pub use deferred::{deferred, DeferredRequest};
pub use offer::{offer, OfferRequest, OfferResponse};
pub use pin::{pin, PinRequest};
pub use save::{save, SaveRequest};
use serde::{Deserialize, Serialize};
pub use token::{token, AuthorizedCredentials};
use uuid::Uuid;
use vercre_issuer::{
    AuthorizationDetail, CredentialOffer, Format, MetadataRequest, OAuthServerRequest, TokenResponse
};
use vercre_openid::issuer::{Issuer, Server};

use crate::credential::Credential;
use crate::provider::{HolderProvider, Issuer as IssuerProvider};

/// Types of issuance flow.
///
/// There are options within each flow type. This enum is used to simplify
/// validation logic.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum FlowType {
    /// Initiated by the issuer, where the holder is pre-authorized.
    #[default]
    IssuerPreAuthorized,

    /// Initiated by the issuer but requires the holder to be authorized.
    IssuerAuthorized,

    /// Initiated by the holder.
    HolderInitiated {
        /// Identifier (URL) of the credential issuer.
        issuer: String,

        /// Credential Issuers MAY support requesting authorization to issue a
        /// credential using OAuth 2.0 scope values.
        /// A scope value and its mapping to a credential type is defined by the
        /// Issuer. A description of scope value semantics or machine readable
        /// definitions could be defined in Issuer metadata. For example,
        /// mapping a scope value to an authorization details object.
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
    },
}

/// Type of credential request that can be made.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum CredentialRequestType {
    /// Request by credential identifiers. This is the default.
    CredentialIdentifiers(Vec<String>),

    /// Request by format. Used when the issuance flow is scope-based.
    Format(Format),
}

/// `Issuance` represents app state across the steps of the issuance flow.
///
/// The data accumulates as the flow progresses, so not all fields can be
/// trusted at all times. The `status` field should be used to determine which
/// step of the flow the issuance is in and therefore which state fields can be
/// used to support the next step.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IssuanceState {
    /// The unique identifier for the issuance flow.
    ///
    /// Generated by this crate but not used internally. Used by wallet
    /// client providers as a key for stashing state.
    pub id: String,

    /// High-level flow type. Used to validate flow steps and can be used by the
    /// wallet client to control flow logic.
    pub flow_type: FlowType,

    /// Client ID of the holder's agent (wallet). Must be a client registered
    /// with the issuer.
    pub client_id: String,

    /// ID of the holder.
    pub subject_id: String,

    /// Current status of the issuance flow.
    pub status: Status,

    /// The `CredentialOffer` received from the issuer.
    ///
    /// Will be `None` if the flow is initiated by the holder.
    pub offer: Option<CredentialOffer>,

    /// Cached issuer metadata.
    pub issuer: Option<Issuer>,

    /// Cached authorization server metadata.
    pub authorization_server: Option<Server>,

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
    ///
    /// Will be `None` if the flow is initiated by the holder or if the flow
    /// has not yet reached the token endpoint.
    pub token: Option<TokenResponse>,

    /// Outstanding deferred credential transaction IDs (key) and corresponding
    /// credential configuration IDs (value).
    ///
    /// Will be empty if there are no outstanding deferred credentials.
    // TODO: Remove.
    pub deferred_deprecated: HashMap<String, String>,

    /// Outstanding deferred credential transaction IDs.
    ///
    /// Will be empty if there are no outstanding deferred credentials.
    pub deferred: Vec<String>,

    /// Identifier to pass back to the issuer to notify of the success or
    /// otherwise of the credential issuance.
    pub notification_id: Option<String>,

    /// The credentials received from the issuer, ready to be saved to storage.
    ///
    /// Will be empty until credentials have been issued.
    pub credentials: Vec<Credential>,
}

/// Helper functions for using issuance state.
impl IssuanceState {
    /// Creates a new issuance flow.
    #[must_use]
    pub fn new(flow_type: FlowType, client_id: &str, subject_id: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            flow_type,
            client_id: client_id.to_string(),
            subject_id: subject_id.to_string(),
            status: Status::Inactive,
            ..Default::default()
        }
    }

    /// Add issuer metadata to the issuance flow state.
    ///
    /// # Errors
    /// Will return an error if the flow state is inconsistent with setting
    /// issuer metadata.
    pub fn issuer(&mut self, issuer: Issuer) -> anyhow::Result<()> {
        if self.status != Status::Inactive || self.issuer.is_some() {
            bail!("cannot set issuer metadata on a flow already started");
        }
        self.issuer = Some(issuer);
        self.status = Status::IssuerMetadataSet;
        Ok(())
    }

    /// Add authorization server metadata to the issuance flow state.
    ///
    /// # Errors
    /// Will return an error if the flow state is inconsistent with setting
    /// authorization server metadata.
    pub fn authorization_server(&mut self, authorization_server: Server) -> anyhow::Result<()> {
        if self.status != Status::IssuerMetadataSet {
            bail!("cannot set authorization server metadata on a flow without issuer metadata");
        }
        if self.authorization_server.is_some() {
            bail!("authorization server metadata already set");
        }
        self.authorization_server = Some(authorization_server);
        self.status = Status::AuthServerSet;
        Ok(())
    }

    /// Gets issuer metadata from the provider and sets that information on
    /// the issuance flow state.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider's metadata request fails.
    // TODO: Remove
    pub async fn set_issuer(
        &mut self, provider: &impl HolderProvider, credential_issuer: &str,
    ) -> anyhow::Result<()> {
        let md_request = MetadataRequest {
            credential_issuer: credential_issuer.into(),
            languages: None, // The wallet client should provide any specific languages required.
        };
        let md_response = IssuerProvider::metadata(provider, md_request).await?;
        self.issuer = Some(md_response.credential_issuer);

        // Set the authorization server metadata.
        // TODO: The spec allows the option for the issuer to provide a list of
        // authorization server identifiers, with the default being the
        // issuer's own ID.
        let auth_md_request = OAuthServerRequest {
            credential_issuer: credential_issuer.into(),
            issuer: None,
        };
        let auth_md_response = IssuerProvider::oauth_server(provider, auth_md_request).await?;
        self.authorization_server = Some(auth_md_response.authorization_server);
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

    /// Metadata has been retrieved.
    IssuerMetadataSet,

    /// Authorization server metadata has been retrieved.
    AuthServerSet,

    /// A new credential offer has been received (issuer-initiated only).
    Offered,

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
