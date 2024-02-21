//! An API for the issuance of Verifiable Credentials based on the
//! [OpenID for Verifiable Credential Issuance] specification.
//!
//! # [OpenID for Verifiable Credential Issuance]
//!
//! This library implements an OAuth protected API for the issuance of Verifiable
//! Credentials as specified by [OpenID for Verifiable Credential Issuance].
//!
//! Verifiable Credentials are similar to identity assertions, like ID Tokens in
//! [OpenID Connect], in that they allow a Credential Issuer to assert End-User claims.
//! A Verifiable Credential follows a pre-defined schema (the Credential type) and MAY
//! be bound to a certain holder, e.g., through Cryptographic Holder Binding. Verifiable
//! Credentials can be securely presented for the End-User to the RP, without
//! involvement of the Credential Issuer.
//!
//! Access to this API is authorized using OAuth 2.0 [RFC6749],
//! i.e., Wallets use OAuth 2.0 to obtain authorization to receive Verifiable
//! Credentials. This way the issuance process can benefit from the proven security,
//! simplicity, and flexibility of OAuth 2.0, use existing OAuth 2.0 deployments, and
//! [OpenID Connect] OPs can be extended to become Credential Issuers.
//!
//! # Design
//!
//! **Endpoints**
//!
//! The library is architected around the [OpenID4VCI] endpoints, each with its own
//! `XxxRequest` and `XxxResponse` types. The types serialize to and from JSON, in
//! accordance with the specification.
//!
//! The endpoints are designed to be used with Rust-based HTTP servers, such as
//! [axum](https://docs.rs/axum/latest/axum/).
//!
//! Endpoints can be combined to implement both the [OpenID4VCI] Authorization Code Flow
//! and Pre-Authorized Code Flow.
//!
//! **Running**
//!
//! Per the OAuth 2.0 specification, endpoints are exposed using HTTP. The library
//! will work with most common Rust HTTP servers with a few lines of 'wrapper' code
//! for each endpoint.
//!
//! In addition, implementors need to implement 'Provider' traits that are responsible
//! for handling externals such as  storage, authorization, external communication,
//! etc.. See [`vercre_core`](https://docs.rs/vercre-core/latest/vercre_core/).
//!
//! # Example
//!
//! The following example demonstrates how a single endpoint might be surfaced.
//!
//! A number of elements have been excluded for brevity. A more complete example can be
//! found in the `examples` directory.
//!  
//! ```compile_fail
//! #[tokio::main]
//! async fn main() {
//!     // `Provider` implements the `Provider` traits
//!     let endpoint = Arc::new(Endpoint::new(Provider::new()));
//!
//!     let router = Router::new()
//!         // --- other routes ---
//!         .route("/credential", post(credential))
//!         // --- other routes ---
//!         .with_state(endpoint);
//!
//!     let listener = TcpListener::bind("0.0.0.0:8080").await.expect("should bind");
//!     axum::serve(listener, router).await.expect("server should run");
//! }
//!
//! // Credential endpoint
//! async fn credential(
//!     State(endpoint): State<Arc<Endpoint<Provider>>>, TypedHeader(host): TypedHeader<Host>,
//!     TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
//!     Json(mut req): Json<CredentialRequest>,
//! ) -> AxResult<CredentialResponse> {
//!     // set credential issuer and access token from HTTP header
//!     req.credential_issuer = format!("http://{}", host);
//!     req.access_token = auth.token().to_string();
//!
//!     // call endpoint
//!     endpoint.credential(req).await.into()
//! }
//! ```
//!
//! [OpenID for Verifiable Credential Issuance]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
//! [OpenID4VCI]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
//! [OpenID Connect]: https://openid.net/specs/openid-connect-core-1_0.html
//! [RFC6749]: https://www.rfc-editor.org/rfc/rfc6749.html

// // #[doc(no_inline)]
// pub use vercre_core::vci::{
//     AuthorizationCodeGrant, AuthorizationDetail, AuthorizationRequest, AuthorizationResponse,
//     BatchCredentialRequest, BatchCredentialResponse, CredentialOffer, CredentialRequest,
//     CredentialResponse, DeferredCredentialRequest, DeferredCredentialResponse, Grants,
//     InvokeRequest, InvokeResponse, MetadataRequest, MetadataResponse, PreAuthorizedCodeGrant,
//     Proof, ProofClaims, RegistrationRequest, RegistrationResponse, TokenRequest, TokenResponse,
// };

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
mod state;
pub mod token;

use std::fmt::Debug;

use tracing::instrument;
use vercre_core::callback::{Payload, Status};
use vercre_core::error::Error;
use vercre_core::{Callback, Client, Holder, Issuer, Result, Server, Signer, StateManager};

/// Endpoint is used to surface the public Verifiable Presentation endpoints to
/// clients.
#[derive(Debug)]
pub struct Endpoint<P>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Debug,
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
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone + Debug,
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
trait Context: Send + Sync + Debug {
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
        P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone + Debug,
    {
        Ok(self)
    }

    /// Process the request.
    async fn process<P>(&self, provider: &P, request: &Self::Request) -> Result<Self::Response>
    where
        P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone + Debug;
}

#[cfg(test)]
mod tests {
    use test_utils::vci_provider::Provider;
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
        P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone + Debug,
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
