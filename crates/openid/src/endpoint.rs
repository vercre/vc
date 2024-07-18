//! # `OpenID` Core

use std::fmt::Debug;
use std::future::{Future, IntoFuture};

use chrono::{DateTime, Utc};
use proof::signature::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::issuer::Issuer;
use crate::{Client, Server};

/// Result is used for all external errors.
// pub type Result<T> = anyhow::Result<T>;
pub type Result<T, E = anyhow::Error> = std::result::Result<T, E>;

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

/// Issuer Provider trait.
pub trait VerifierProvider:
    VerifierMetadata + WalletMetadata + StateManager + Signer + Verifier + Clone
{
}

/// Request is implemented by all request types.
pub trait Request {
    /// The key used to access state data.
    fn state_key(&self) -> Option<String> {
        None
    }
}

/// Handler is implemented by all request handlers.
pub trait Handler<'a, C, P, R, U, E>: Send
where
    R: Request + Sync,
{
    /// Handle the request.
    fn handle(
        self, context: C, provider: P, request: &'a R,
    ) -> impl Future<Output = Result<U, E>> + Send;
}

// Blanket implementation for all functions that take a provider and a request and return a
// future that resolves to a result.
impl<'a, C, P, R, U, F, Fut, E> Handler<'a, C, P, R, U, E> for F
where
    R: 'a + Request + Sync,
    F: FnOnce(C, P, &'a R) -> Fut + Send,
    Fut: Future<Output = Result<U, E>> + Send,
{
    fn handle(
        self, context: C, provider: P, request: &'a R,
    ) -> impl Future<Output = Result<U, E>> + Send {
        self(context, provider, request)
    }
}

/// The `ClientMetadata` trait is used by implementers to provide `Client` metadata to the
/// library.
pub trait ClientMetadata: Send + Sync {
    /// Returns client metadata for the specified client.
    fn metadata(&self, client_id: &str) -> impl Future<Output = Result<Client>> + Send;

    /// Used by OAuth 2.0 clients to dynamically register with the authorization
    /// server.
    fn register(&self, client: &Client) -> impl Future<Output = Result<Client>> + Send;
}

/// The `IssuerMetadata` trait is used by implementers to provide Credential Issuer metadata.
pub trait IssuerMetadata: Send + Sync {
    /// Returns the Credential Issuer's metadata.
    fn metadata(&self, issuer_id: &str) -> impl Future<Output = Result<Issuer>> + Send;
}

/// The `ServerMetadata` trait is used by implementers to provide Authorization Server metadata.
pub trait ServerMetadata: Send + Sync {
    /// Returns the Authorization Server's metadata.
    fn metadata(&self, server_id: &str) -> impl Future<Output = Result<Server>> + Send;
}

/// The `VerifierMetadata` trait is used by implementers to provide `Verifier` (client)
/// metadata to the library.
pub trait VerifierMetadata: Send + Sync {
    /// Returns client metadata for the specified client.
    fn metadata(&self, verifier_id: &str) -> impl Future<Output = Result<Client>> + Send;

    /// Used by OAuth 2.0 clients to dynamically register with the authorization
    /// server.
    fn register(&self, verifier: &Client) -> impl Future<Output = Result<Client>> + Send;
}

/// The `WalletMetadata` trait is used by implementers to provide Wallet
/// (Authorization Server) metadata.
pub trait WalletMetadata: Send + Sync {
    /// Returns the Authorization Server's metadata.
    fn metadata(&self, wallet_id: &str) -> impl Future<Output = Result<Server>> + Send;
}

/// `StateManager` is used to store and manage server state.
pub trait StateManager: Send + Sync {
    /// `StateStore` data (state) by provided key. The expiry parameter indicates
    /// when data can be expunged removed from the state store.
    fn put(
        &self, key: &str, data: Vec<u8>, expiry: DateTime<Utc>,
    ) -> impl Future<Output = Result<()>> + Send;

    // /// Put data into the store with optional expiry.
    // /// TODO: remove this method and refactor `put` to accept optional expiry.
    // fn put_opt(
    //     &self, key: &str, data: Vec<u8>, expiry: Option<DateTime<Utc>>,
    // ) -> impl Future<Output = Result<()>> + Send {
    //     let exp = expiry.unwrap_or_else(|| Utc::now() + Duration::days(1));
    //     self.put(key, data, exp)
    // }

    /// Retrieve data using the provided key.
    fn get(&self, key: &str) -> impl Future<Output = Result<Vec<u8>>> + Send;

    /// Remove data using the key provided.
    fn purge(&self, key: &str) -> impl Future<Output = Result<()>> + Send;

    /// Retrieve data that may not be present in the store.
    /// TODO: remove this method and refactor `get` to return option.
    fn get_opt(&self, key: &str) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send {
        let v = async {
            match self.get(key).await {
                Ok(data) => Ok(Some(data)),
                Err(e) => Err(e),
            }
        };
        v.into_future()
    }
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
    ) -> impl Future<Output = Result<bool>> + Send;

    /// Returns a populated `Claims` object for the given subject (holder) and credential
    /// definition.
    fn claims(
        &self, holder_subject: &str, credential_identifier: &str,
    ) -> impl Future<Output = Result<Claims>> + Send;
}
