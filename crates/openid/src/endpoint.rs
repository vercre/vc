//! # `OpenID` Core

use std::future::Future;

use chrono::{DateTime, Utc};

/// Result is used for all external errors.
// pub type Result<T> = anyhow::Result<T>;
pub type Result<T, E = anyhow::Error> = std::result::Result<T, E>;

/// Request is implemented by all request types.
pub trait Request {
    /// The key used to access state data.
    fn state_key(&self) -> Option<String> {
        None
    }
}

/// `StateManager` is used to store and manage server state.
pub trait StateManager: Send + Sync {
    /// `StateStore` data (state) by provided key. The expiry parameter indicates
    /// when data can be expunged removed from the state store.
    fn put(
        &self, key: &str, data: Vec<u8>, expiry: DateTime<Utc>,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Retrieve data using the provided key.
    fn get(&self, key: &str) -> impl Future<Output = Result<Vec<u8>>> + Send;

    /// Remove data using the key provided.
    fn purge(&self, key: &str) -> impl Future<Output = Result<()>> + Send;
}
