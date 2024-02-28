//! # `OpenID` Core

#![feature(error_generic_member_access)]

pub mod callback;
pub mod error;
pub mod gen;
pub mod holder;
pub mod jwt;
pub mod metadata;
pub mod proof;
pub mod stringify;
pub mod vci;
pub mod vp;
pub mod w3c;

use std::fmt::{Debug, Display};

use chrono::{DateTime, Utc};
use tracing::instrument;

use crate::callback::{Payload, Status};
use crate::error::Error;
use crate::metadata::{
    Client as ClientMetadata, CredentialDefinition, Issuer as IssuerMetadata,
    Server as ServerMetadata,
};

/// LATER: investigate `async_fn_in_trait` warning

/// Result type for `OpenID` for Verifiable Credential Issuance and Verifiable
/// Presentations.
pub type Result<T, E = error::Error> = std::result::Result<T, E>;

/// The Client trait is used by implementers to provide Client metadata to the
/// library.
#[allow(async_fn_in_trait)]
pub trait Client: Send + Sync {
    /// Returns client metadata for the specified client.
    async fn metadata(&self, client_id: &str) -> anyhow::Result<ClientMetadata>;

    /// Used by OAuth 2.0 clients to dynamically register with the authorization
    /// server.
    async fn register(&self, client_meta: &ClientMetadata) -> anyhow::Result<ClientMetadata>;
}

/// The Issuer trait is used by implementers to provide Credential Issuer
/// metadata.
#[allow(async_fn_in_trait)]
pub trait Issuer: Send + Sync {
    /// Returns the Credential Issuer's metadata.
    async fn metadata(&self, issuer_id: &str) -> anyhow::Result<IssuerMetadata>;
}

/// The Issuer trait is used by implementers to provide Authorization Server
/// metadata.
#[allow(async_fn_in_trait)]
pub trait Server: Send + Sync {
    /// Returns the Authorization Server's metadata.
    async fn metadata(&self, server_id: &str) -> anyhow::Result<ServerMetadata>;
}

/// `StateManager` is used to store and manage server state.
#[allow(async_fn_in_trait)]
pub trait StateManager: Send + Sync {
    /// `StateStore` data (state) by provided key. The expiry parameter indicates
    /// when data can be expunged removed from the state store.
    async fn put(&self, key: &str, data: Vec<u8>, expiry: DateTime<Utc>) -> anyhow::Result<()>;

    /// Retrieve data using the provided key.
    async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>>;

    /// Remove data using the key provided.
    async fn purge(&self, key: &str) -> anyhow::Result<()>;
}

/// Callback describes behaviours required for notifying a client application of
/// issuance or presentation flow status.
#[allow(async_fn_in_trait)]
pub trait Callback: Send + Sync {
    /// Callback method to process status updates.
    async fn callback(&self, pl: &callback::Payload) -> anyhow::Result<()>;
}

/// The Holder trait specifies how the library expects user information to be
/// provided by implementers.
#[allow(async_fn_in_trait)]
pub trait Holder: Send + Sync {
    /// Authorize issuance of the credential specified by `credential_configuration_id`.
    /// Returns `true` if the holder is authorized.
    async fn authorize(
        &self, holder_id: &str, credential_configuration_id: &str,
    ) -> anyhow::Result<bool>;

    /// Returns a populated `Claims` object for the given holder and credential
    /// definition.
    async fn claims(
        &self, holder_id: &str, credential: &CredentialDefinition,
    ) -> anyhow::Result<holder::Claims>;
}

/// Signer is used by implementers to provide signing functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
#[allow(async_fn_in_trait)]
pub trait Signer: Debug {
    /// Algorithm returns the algorithm used by the signer.
    fn algorithm(&self) -> Algorithm;

    /// The verification method the verifier should use to verify the signer's
    /// signature. This is typically a DID URL + # + verification key ID.
    fn verification_method(&self) -> String;

    /// Sign is a convenience method for infallible Signer implementations.
    async fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.try_sign(msg).await.expect("should sign")
    }

    /// `TrySign` is the fallible version of Sign.
    async fn try_sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>>;
}

/// Algorithm is used to specify the signing algorithm used by the signer.
pub enum Algorithm {
    /// Algorithm for the secp256k1 curve
    ES256K,

    /// Algorithm for the Ed25519 curve
    EdDSA,
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::ES256K => write!(f, "ES256K"),
            Algorithm::EdDSA => write!(f, "EdDSA"),
        }
    }
}

impl Algorithm {
    /// Returns the key type as a string.
    #[must_use]
    pub fn proof_type(&self) -> String {
        match self {
            Algorithm::ES256K => String::from("EcdsaSecp256k1VerificationKey2019"),
            Algorithm::EdDSA => String::from("JsonWebKey2020"),
        }
    }
}

/// Context is implemented by every endpoint to set up a context for each
/// request.
#[allow(async_fn_in_trait)]
pub trait Context: Send + Sync + Debug {
    type Provider;

    /// The request type for the request context.
    type Request;

    /// The response type for the request context.
    type Response;

    /// Callback ID is used to identify the initial request when sending status
    /// updates to the client.
    fn callback_id(&self) -> Option<String>;

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
pub trait Endpoint: Debug {
    type Provider: Callback;

    fn provider(&self) -> &Self::Provider;

    /// Wrap the processing of individual requests for shared handling of callbacks,
    /// errors, etc..
    ///
    /// Each endpoint implements a request-specific `Endpoint::call` method which then
    /// calls `Endpoint::handle_request` to handle shared functionality.
    #[allow(async_fn_in_trait)]
    #[instrument]
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
            return self.provider().callback(&pl).await;
        }
        Ok(())
    }
}
