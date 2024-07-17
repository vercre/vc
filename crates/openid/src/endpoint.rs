//! # `OpenID` Core

mod callback;
mod subject;

use std::fmt::Debug;
use std::future::{Future, IntoFuture};

use chrono::{DateTime, Utc};
use proof::signature::{Signer, Verifier};
use tracing::instrument;

pub use self::callback::{Payload, Status};
pub use self::subject::{Claims, Subject};
use crate::error::Err;
use crate::issuance::Issuer;
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

/// The Endpoint trait is implemented by issuance and presentation endpoints in order
/// to provide a common basis for request handling.
pub trait Endpoint: Debug {
    /// The provider type to use with the endpoint.
    type Provider: Callback;

    /// Access to the endpoint's provider.
    fn provider(&self) -> &Self::Provider;

    /// Wrap the processing of individual requests for shared handling of callbacks,
    /// errors, etc..
    ///
    /// Each endpoint implements a request-specific `Endpoint::call` method which then
    /// calls `Endpoint::handle_request` to handle shared functionality.
    #[allow(async_fn_in_trait)]
    #[instrument(level = "debug", skip(self))]
    async fn handle_request<R, C, U>(&self, request: &R, mut ctx: C) -> crate::Result<U>
    where
        C: Context<Request = R, Response = U, Provider = Self::Provider>,
        R: Default + Clone + Debug + Send + Sync,
    {
        if let Some(callback_id) = ctx.callback_id() {
            let pl = Payload {
                id: callback_id.clone(),
                status: Status::PresentationRequested,
                context: String::new(),
            };
            self.provider()
                .callback(&pl)
                .await
                .map_err(|e| Err::ServerError(format!("callback issue: {e}")))?;
        }

        let res = match ctx.verify(self.provider(), request).await {
            Ok(res) => res,
            Err(e) => {
                tracing::error!(target:"Endpoint::verify", ?e);
                self.try_callback(ctx, &e)
                    .await
                    .map_err(|e| Err::ServerError(format!("callback issue: {e}")))?;
                return Err(e);
            }
        };

        match res.process(self.provider(), request).await {
            Ok(res) => Ok(res),
            Err(e) => {
                tracing::error!(target:"Endpoint::process", ?e);
                self.try_callback(ctx, &e)
                    .await
                    .map_err(|e| Err::ServerError(format!("callback issue: {e}")))?;
                Err(e)
            }
        }
    }

    /// Try to send a callback to the client. If the callback fails, log the error.
    #[allow(async_fn_in_trait)]
    #[instrument(level = "debug", skip(self))]
    async fn try_callback<R, C, U>(&self, ctx: C, e: &Err) -> Result<()>
    where
        C: Context<Request = R, Response = U>,
        R: Default + Clone + Send + Sync + Debug,
    {
        if let Some(callback_id) = ctx.callback_id() {
            tracing::debug!("Endpoint::try_callback");

            let pl = Payload {
                id: callback_id.clone(),
                status: Status::Error,
                context: format!("{e}"),
            };
            return self.provider().callback(&pl).await;
        }
        Ok(())
    }
}

/// Context is implemented by every endpoint to set up a context for each
/// request.
// TODO: replace async fn in trait with async trait
#[allow(async_fn_in_trait)]
pub trait Context: Send + Sync + Debug {
    /// The provider type for the request context.
    type Provider;

    /// The request type for the request context.
    type Request;

    /// The response type for the request context.
    type Response;

    /// Callback ID is used to identify the initial request when sending status
    /// updates to the client. Defaults to no callback.
    fn callback_id(&self) -> Option<String> {
        None
    }

    /// Verify the request.
    #[allow(clippy::unused_async)]
    async fn verify(&mut self, _: &Self::Provider, _: &Self::Request) -> crate::Result<&Self> {
        Ok(self)
    }

    /// Process the request.
    async fn process(
        &self, provider: &Self::Provider, request: &Self::Request,
    ) -> crate::Result<Self::Response>;
}

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
