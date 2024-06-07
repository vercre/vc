//! # `OpenID` Core

// generic member access API on the error trait
// https://github.com/rust-lang/rust/issues/99301
#![feature(error_generic_member_access)]

pub mod callback;
pub mod error;
pub mod gen;
pub mod jwt;
pub mod metadata;
pub mod proof;
pub mod provider;
pub mod stringify;
pub mod subject;
pub mod vci;
pub mod vp;

use std::fmt::Debug;

use tracing::instrument;

use crate::callback::{Payload, Status};
use crate::error::Error;
use crate::provider::Callback;

// LATER: investigate `async_fn_in_trait` warning

/// Result type for `OpenID` for Verifiable Credential Issuance and Verifiable
/// Presentations.
pub type Result<T, E = error::Error> = std::result::Result<T, E>;

/// Context is implemented by every endpoint to set up a context for each
/// request.
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
    async fn verify(&mut self, _: &Self::Provider, _: &Self::Request) -> Result<&Self> {
        Ok(self)
    }

    /// Process the request.
    async fn process(
        &self, provider: &Self::Provider, request: &Self::Request,
    ) -> Result<Self::Response>;
}

// TODO: replace async fn in trait with async trait

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
    async fn handle_request<R, C, U>(&self, request: &R, mut ctx: C) -> Result<U>
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
            self.provider().callback(&pl).await?;
            // self.try_callback(ctx, &e).await?;
        }

        let res = match ctx.verify(self.provider(), request).await {
            Ok(res) => res,
            Err(e) => {
                tracing::error!(target:"Endpoint::verify", ?e);
                self.try_callback(ctx, &e).await?;
                return Err(e);
            }
        };

        match res.process(self.provider(), request).await {
            Ok(res) => Ok(res),
            Err(e) => {
                tracing::error!(target:"Endpoint::process", ?e);
                self.try_callback(ctx, &e).await?;
                Err(e)
            }
        }
    }

    /// Try to send a callback to the client. If the callback fails, log the error.
    #[allow(async_fn_in_trait)]
    #[instrument(level = "debug", skip(self))]
    async fn try_callback<R, C, U>(&self, ctx: C, e: &Error) -> provider::Result<()>
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
