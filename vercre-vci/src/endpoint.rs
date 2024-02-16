//! Endpoints for Verifiable Credential Issuance API.
//!
//! See [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).

pub mod authorize;
pub mod batch;
pub mod credential;
pub mod deferred;
pub mod invoke;
pub mod metadata;
pub mod register;
pub mod token;

use std::fmt::Debug;

use tracing::instrument;
use vercre_core::callback::{Payload, Status};
use vercre_core::error::Error;
pub use vercre_core::vci::{
    AuthorizationDetail, AuthorizationRequest, AuthorizationResponse, BatchCredentialRequest,
    BatchCredentialResponse, CredentialOffer, CredentialRequest, CredentialResponse,
    DeferredCredentialRequest, DeferredCredentialResponse, Grants, InvokeRequest, InvokeResponse,
    MetadataRequest, MetadataResponse, RegistrationRequest, RegistrationResponse, TokenRequest,
    TokenResponse,
};
use vercre_core::{
    Callback, Client, Context, Holder, Issuer, Result, Server, Signer, StateManager,
};

/// Handler is used to surface the public Verifiable Credential Issuance endpoints to
/// clients.
#[derive(Debug)]
pub struct Handler<P, R>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Debug,
    R: Send + Sync + Debug,
{
    provider: P,
    request: R,
}

/// Handler is used to provide a thread-safe way of handling endpoint requests.
/// Each request passes through a number of steps with request state required to
/// be maintained between steps.
///
/// The Handler also provides common top-level tracing, error handling, and client
/// callback functionality for all endpoints. The act of setting a request causes
/// the Handler to select the endpoint implementation of `Handler::call` specific
/// to the request.
impl<P, R> Handler<P, R>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone + Debug,
    R: Clone + Send + Sync + Debug,
{
    /// Create a new endpoint instance.
    pub fn new(provider: P, request: R) -> Self {
        Self { provider, request }
    }

    /// Wrap the processing of individual requests for shared handling of callbacks,
    /// errors, etc..
    ///
    /// Each endpoint implements a request-specific `Handler::call` method which then
    /// calls `Handler::handle_request` to handle shared functionality.
    #[instrument]
    async fn handle_request<C, U>(&self, mut ctx: C) -> Result<U>
    where
        C: Context<Request = R, Response = U, Provider = P>,
    {
        if let Some(callback_id) = ctx.callback_id() {
            let pl = Payload {
                id: callback_id.clone(),
                status: Status::PresentationRequested,
                context: String::new(),
            };
            self.provider.callback(&pl).await?;
        }

        let res = match ctx.init(&self.request, self.provider.clone()).await {
            Ok(res) => res,
            Err(e) => {
                tracing::error!(target:"Handler::prepare", "{e}");
                self.try_callback(ctx, &e).await?;
                return Err(e);
            }
        };

        let res = match res.verify(&self.request).await {
            Ok(res) => res,
            Err(e) => {
                tracing::error!(target:"Handler::verify", "{e}");
                self.try_callback(ctx, &e).await?;
                return Err(e);
            }
        };

        match res.process(&self.request).await {
            Ok(res) => Ok(res),
            Err(e) => {
                tracing::error!(target:"Handler::process", "{e}");
                self.try_callback(ctx, &e).await?;
                Err(e)
            }
        }
    }

    /// Try to send a callback to the client. If the callback fails, log the error.
    #[instrument]
    async fn try_callback<C, U>(&self, ctx: C, e: &Error) -> anyhow::Result<()>
    where
        C: Context<Request = R, Response = U, Provider = P>,
    {
        if let Some(callback_id) = ctx.callback_id() {
            tracing::trace!("Handler::try_callback");

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
