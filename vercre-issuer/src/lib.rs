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
//! ```rust,ignore
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
//! [OpenID for Verifiable Credential Issuance]: (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
//! [OpenID4VCI]: (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
//! [OpenID Connect]: (https://openid.net/specs/openid-connect-core-1_0.html)
//! [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)

pub mod authorize;
pub mod batch;
pub mod create_offer;
pub mod credential;
pub mod deferred;
pub mod metadata;
pub mod register;
mod state;
pub mod token;

use std::fmt::Debug;

pub use vercre_core::error::Error;
use vercre_core::provider::{
    Callback, ClientMetadata, IssuerMetadata, ServerMetadata, StateManager, Subject,
};
// TODO: move Claims into jwt module
pub use openid4vc::issuance::{GrantType, ProofClaims};
pub use vercre_core::{provider, Result};
use vercre_vc::proof::Signer;

/// Endpoint is used to surface the public Verifiable Presentation endpoints to
/// clients.
#[derive(Debug)]
pub struct Endpoint<P>
where
    P: ClientMetadata
        + IssuerMetadata
        + ServerMetadata
        + Subject
        + StateManager
        + Signer
        + Callback
        + Clone
        + Debug,
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
    P: ClientMetadata
        + IssuerMetadata
        + ServerMetadata
        + Subject
        + StateManager
        + Signer
        + Callback
        + Clone
        + Debug,
{
    /// Create a new endpoint instance.
    pub const fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P> vercre_core::Endpoint for Endpoint<P>
where
    P: ClientMetadata
        + IssuerMetadata
        + ServerMetadata
        + Subject
        + StateManager
        + Signer
        + Callback
        + Clone
        + Debug,
{
    type Provider = P;

    fn provider(&self) -> &P {
        &self.provider
    }
}

#[cfg(test)]
mod tests {
    use providers::issuance::Provider;
    use vercre_core::err;
    use vercre_core::error::Err;

    use super::*;

    #[tokio::test]
    async fn test_ok() {
        let request = TestRequest { return_ok: true };
        let response = Endpoint::new(Provider::new()).test(&request).await;

        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn test_err() {
        let request = TestRequest { return_ok: false };
        let response = Endpoint::new(Provider::new()).test(&request).await;

        assert!(response.is_err());
    }

    struct TestResponse {}
    // ------------------------------------------------------------------------
    // Mock Endpoint
    // ------------------------------------------------------------------------
    #[derive(Clone, Debug, Default)]
    struct TestRequest {
        return_ok: bool,
    }

    impl<P> Endpoint<P>
    where
        P: ClientMetadata
            + IssuerMetadata
            + ServerMetadata
            + Subject
            + StateManager
            + Signer
            + Callback
            + Clone
            + Debug,
    {
        async fn test(&mut self, request: &TestRequest) -> Result<TestResponse> {
            let ctx = Context {
                _p: std::marker::PhantomData,
            };
            vercre_core::Endpoint::handle_request(self, request, ctx).await
        }
    }

    #[derive(Debug)]
    struct Context<P> {
        _p: std::marker::PhantomData<P>,
    }

    impl<P> vercre_core::Context for Context<P>
    where
        P: ClientMetadata
            + IssuerMetadata
            + ServerMetadata
            + Subject
            + StateManager
            + Signer
            + Callback
            + Clone
            + Debug,
    {
        type Provider = P;
        type Request = TestRequest;
        type Response = TestResponse;

        fn callback_id(&self) -> Option<String> {
            Some("callback_id".into())
        }

        async fn process(
            &self, _provider: &Self::Provider, request: &Self::Request,
        ) -> Result<Self::Response> {
            match request.return_ok {
                true => Ok(TestResponse {}),
                false => err!(Err::InvalidRequest, "invalid request"),
            }
        }
    }
}
