use std::future::Future;

use openid::endpoint;
#[allow(clippy::module_name_repetitions)]
pub use openid::endpoint::{Result, StateManager};
pub use openid::issuer::{ClaimDefinition, GrantType, Issuer};
pub use openid::{Client, Server};
pub use proof::jose::jwk::PublicKeyJwk;
pub use proof::signature::{Algorithm, Signer, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Issuer Provider trait.
pub trait IssuerProvider:
    ClientMetadata
    + IssuerMetadata
    + ServerMetadata
    + Subject
    + StateManager
    + Signer
    + Verifier
    + Clone
{
}

/// The `IssuerMetadata` trait is used by implementers to provide Credential Issuer metadata.
pub trait IssuerMetadata: Send + Sync {
    /// Returns the Credential Issuer's metadata.
    fn metadata(&self, issuer_id: &str) -> impl Future<Output = endpoint::Result<Issuer>> + Send;
}

/// The `ServerMetadata` trait is used by implementers to provide Authorization Server metadata.
pub trait ServerMetadata: Send + Sync {
    /// Returns the Authorization Server's metadata.
    fn metadata(&self, server_id: &str) -> impl Future<Output = endpoint::Result<Server>> + Send;
}

/// The `ClientMetadata` trait is used by implementers to provide `Client` metadata to the
/// library.
pub trait ClientMetadata: Send + Sync {
    /// Returns client metadata for the specified client.
    fn metadata(&self, client_id: &str) -> impl Future<Output = endpoint::Result<Client>> + Send;

    /// Used by OAuth 2.0 clients to dynamically register with the authorization
    /// server.
    fn register(
        &self, client_meta: &Client,
    ) -> impl Future<Output = endpoint::Result<Client>> + Send;
}

/// The user information returned by the Subject trait.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Claims {
    /// The credential subject populated for the user.
    pub claims: Map<String, Value>,

    /// Specifies whether user information required for the credential subject
    /// is pending.
    pub pending: bool,
}

/// The Subject trait specifies how the library expects user information to be
/// provided by implementers.
pub trait Subject: Send + Sync {
    /// Authorize issuance of the credential specified by `credential_configuration_id`.
    /// Returns `true` if the subject (holder) is authorized.
    fn authorize(
        &self, holder_subject: &str, credential_identifier: &str,
    ) -> impl Future<Output = endpoint::Result<bool>> + Send;

    /// Returns a populated `Claims` object for the given subject (holder) and credential
    /// definition.
    fn claims(
        &self, holder_subject: &str, credential_identifier: &str,
    ) -> impl Future<Output = endpoint::Result<Claims>> + Send;
}
