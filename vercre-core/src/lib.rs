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

use crate::metadata::{
    Client as ClientMetadata, CredentialDefinition, Issuer as IssuerMetadata,
    Server as ServerMetadata,
};
// use crate::vci::CredentialDefinition;

// LATER: reduce cloning by refactoring larger structs into smaller, 'composed' structs
//        see https://rust-unofficial.github.io/patterns/patterns/structural/compose-structs.html

/// Result type for `OpenID` for Verifiable Credential Issuance and Verifiable
/// Presentations.
pub type Result<T, E = error::Error> = core::result::Result<T, E>;

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
    /// Authorize issuance of the specified credential for the holder.
    async fn authorize(
        &self, holder_id: &str, credential_identifiers: &[String],
    ) -> anyhow::Result<()>;

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
            Algorithm::ES256K => "EcdsaSecp256k1VerificationKey2019".to_string(),
            Algorithm::EdDSA => "JsonWebKey2020".to_string(),
        }
    }
}
