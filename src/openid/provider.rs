//! # `OpenID` Core

use std::future::Future;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Result is used for all external errors.
pub type Result<T, E = anyhow::Error> = std::result::Result<T, E>;

/// `StateStore` is used to store and retrieve server state between requests.
pub trait StateStore: Send + Sync {
    /// Store state using the provided key. The expiry parameter indicates
    /// when data can be expunged from the state store.
    fn put(
        &self, key: &str, state: impl Serialize + Send, expiry: DateTime<Utc>,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Retrieve data using the provided key.
    fn get<T: DeserializeOwned>(&self, key: &str) -> impl Future<Output = Result<T>> + Send;

    /// Remove data using the key provided.
    fn purge(&self, key: &str) -> impl Future<Output = Result<()>> + Send;
}

// /// `State` is used to persist server state between issuance or presentation
// steps. pub trait State: Serialize + DeserializeOwned + Send + Sync {
//     /// The time when the state entry should expire.
//     fn expires_at(&self) -> DateTime<Utc>;
// }
