//! # `OpenID` Core

use std::future::{Future, IntoFuture};

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
