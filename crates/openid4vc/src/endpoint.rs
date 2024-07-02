//! # `OpenID` Core

mod callback;
#[allow(clippy::module_inception)]
pub mod endpoint;
mod subject;

use std::future::{Future, IntoFuture};

use chrono::{DateTime, Utc};
pub use core_utils::signature::{Algorithm, Jwk, Signer, Verifier};

pub use self::callback::{Payload, Status};
pub use self::endpoint::{Context, Endpoint};
pub use self::subject::{Claims, Subject};
use crate::issuance::Issuer;
use crate::{Client, Server};

/// Result is used for all external errors.
// pub type Result<T> = anyhow::Result<T>;
pub type Result<T, E = anyhow::Error> = std::result::Result<T, E>;

/// The `ClientMetadata` trait is used by implementers to provide `Client` metadata to the
/// library.
pub trait ClientMetadata: Send + Sync {
    /// Returns client metadata for the specified client.
    fn metadata(&self, client_id: &str) -> impl Future<Output = Result<Client>> + Send;

    /// Used by OAuth 2.0 clients to dynamically register with the authorization
    /// server.
    fn register(&self, client_meta: &Client) -> impl Future<Output = Result<Client>> + Send;
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

/// Callback describes behaviours required for notifying a client application of
/// issuance or presentation flow status.
pub trait Callback: Send + Sync {
    /// Callback method to process status updates.
    fn callback(&self, pl: &callback::Payload) -> impl Future<Output = Result<()>> + Send;
}
