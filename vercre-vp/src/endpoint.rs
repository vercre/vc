//! Endpoints for Verifiable Presentation API.
//!
//! See [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).

mod invoke;
mod metadata;
mod request;
mod response;

use std::fmt::Debug;

use tracing::instrument;
use vercre_core::callback::{Payload, Status};
use vercre_core::error::Error;
pub use vercre_core::vp::{
    InvokeRequest, InvokeResponse, RequestObject, RequestObjectRequest, RequestObjectResponse,
    ResponseRequest, ResponseResponse,
};
use vercre_core::{Callback, Client, Result, Signer, StateManager};

// TODO: remove double borrow for traits (i.e. &self -> self)
// TODO: reintroduce impl Provider trait + lifetimes for Endpoint

/// Endpoint is used to surface the public Verifiable Presentation endpoints to
/// clients.
#[derive(Debug)]
pub struct Endpoint<P>
where
    P: Client + StateManager + Signer + Callback + Debug,
{
    provider: P,
}

/// Endpoint is used to provide a thread-safe way of handling endpoint requests.
/// Each request passes through a number of steps with request state required to
/// be maintained between steps.
///
/// The Endpoint also provides common top-level tracing, error handling, and client
/// callback functionality for all endpoints. The act of setting a request causes
/// the Endpoint to select the endpoint implementation of `Endpoint::call` specific
/// to the request.
impl<P> Endpoint<P>
where
    P: Client + StateManager + Signer + Callback + Clone + Debug,
{
    /// Create a new endpoint instance.
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    /// Wrap the processing of individual requests for shared handling of callbacks,
    /// errors, etc..
    ///
    /// Each endpoint implements a request-specific `Endpoint::call` method which then
    /// calls `Endpoint::handle_request` to handle shared functionality.
    #[instrument]
    async fn handle_request<R, C, U>(&self, request: R, ctx: C) -> Result<U>
    where
        C: Context<Request = R, Response = U>,
        R: Default + Clone + Debug + Send + Sync,
    {
        if let Some(callback_id) = ctx.callback_id() {
            let pl = Payload {
                id: callback_id.clone(),
                status: Status::PresentationRequested,
                context: String::new(),
            };
            self.provider.callback(&pl).await?;
        }

        let res = match ctx.verify(&self.provider, &request).await {
            Ok(res) => res,
            Err(e) => {
                tracing::error!(target:"Endpoint::verify", ?e);
                self.try_callback(ctx, &e).await?;
                return Err(e);
            }
        };

        match res.process(&self.provider, &request).await {
            Ok(res) => Ok(res),
            Err(e) => {
                tracing::error!(target:"Endpoint::process", ?e);
                self.try_callback(ctx, &e).await?;
                Err(e)
            }
        }
    }

    /// Try to send a callback to the client. If the callback fails, log the error.
    #[instrument]
    async fn try_callback<R, C, U>(&self, ctx: C, e: &Error) -> anyhow::Result<()>
    where
        C: Context<Request = R, Response = U>,
        R: Default + Clone + Send + Sync + Debug,
    {
        if let Some(callback_id) = ctx.callback_id() {
            tracing::trace!("Endpoint::try_callback");

            let pl = Payload {
                id: callback_id.clone(),
                status: Status::Error,
                context: format!("{e}"),
            };
            return self.provider.callback(&pl).await;
        }
        Ok(())
    }
}

/// Context is implemented by every endpoint to set up a context for each
/// request.
#[allow(async_fn_in_trait)]
pub trait Context: Send + Sync + Debug {
    /// The request type for the request context.
    type Request;

    /// The response type for the request context.
    type Response;

    /// Callback ID is used to identify the initial request when sending status
    /// updates to the client.
    fn callback_id(&self) -> Option<String>;

    /// Verify the request.
    #[allow(clippy::unused_async)]
    async fn verify<P>(&self, _: &P, _: &Self::Request) -> Result<&Self>
    where
        P: Client + StateManager + Signer + Callback + Clone + Debug,
    {
        Ok(self)
    }

    /// Process the request.
    async fn process<P>(&self, provider: &P, request: &Self::Request) -> Result<Self::Response>
    where
        P: Client + StateManager + Signer + Callback + Clone + Debug;
}

#[cfg(test)]
mod tests {
    use test_utils::vp_provider::Provider;
    use vercre_core::err;
    use vercre_core::error::Err;

    use super::*;

    #[tokio::test]
    async fn test_ok() {
        let request = TestRequest { return_ok: true };
        let response = Endpoint::new(Provider::new()).test(request).await;

        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn test_err() {
        let request = TestRequest { return_ok: false };
        let response = Endpoint::new(Provider::new()).test(request).await;

        assert!(response.is_err());
    }

    // ------------------------------------------------------------------------
    // Mock Endpoint
    // ------------------------------------------------------------------------
    #[derive(Clone, Debug, Default)]
    pub(super) struct TestRequest {
        return_ok: bool,
    }

    pub(super) struct TestResponse {}

    impl<P> Endpoint<P>
    where
        P: Client + StateManager + Signer + Callback + Clone + Debug,
    {
        async fn test(&mut self, request: TestRequest) -> Result<TestResponse> {
            self.handle_request(request, Context::new()).await
        }
    }

    #[derive(Debug)]
    pub(super) struct Context;

    impl Context {
        pub fn new() -> Self {
            Self {}
        }
    }

    impl super::Context for Context {
        type Request = TestRequest;
        type Response = TestResponse;

        fn callback_id(&self) -> Option<String> {
            Some("callback_id".to_string())
        }

        async fn process<P>(&self, _provider: &P, request: &Self::Request) -> Result<Self::Response>
        where
            P: Client + StateManager + Debug,
        {
            match request.return_ok {
                true => Ok(TestResponse {}),
                false => err!(Err::InvalidRequest, "invalid request"),
            }
        }
    }
}
