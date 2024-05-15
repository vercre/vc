//! # `OpenID` Core

use std::fmt::Display;
use std::future::{Future, IntoFuture};

use chrono::{DateTime, Utc};

use crate::callback;
use crate::holder::Claims;
use crate::metadata::{
    Client as ClientMetadata, CredentialDefinition, Issuer as IssuerMetadata,
    Server as ServerMetadata,
};

/// Result is used for all external errors.
pub type Result<T> = anyhow::Result<T>;

/// The Client trait is used by implementers to provide Client metadata to the
/// library.
pub trait Client: Send + Sync {
    /// Returns client metadata for the specified client.
    fn metadata(&self, client_id: &str) -> impl Future<Output = Result<ClientMetadata>> + Send;

    /// Used by OAuth 2.0 clients to dynamically register with the authorization
    /// server.
    fn register(
        &self, client_meta: &ClientMetadata,
    ) -> impl Future<Output = Result<ClientMetadata>> + Send;
}

/// The Issuer trait is used by implementers to provide Credential Issuer
/// metadata.
pub trait Issuer: Send + Sync {
    /// Returns the Credential Issuer's metadata.
    fn metadata(&self, issuer_id: &str) -> impl Future<Output = Result<IssuerMetadata>> + Send;
}

/// The Issuer trait is used by implementers to provide Authorization Server
/// metadata.
pub trait Server: Send + Sync {
    /// Returns the Authorization Server's metadata.
    fn metadata(&self, server_id: &str) -> impl Future<Output = Result<ServerMetadata>> + Send;
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

/// Callback describes behaviours required for notifying a client application of
/// issuance or presentation flow status.
pub trait Callback: Send + Sync {
    /// Callback method to process status updates.
    fn callback(&self, pl: &callback::Payload) -> impl Future<Output = Result<()>> + Send;
}

/// The Holder trait specifies how the library expects user information to be
/// provided by implementers.
pub trait Holder: Send + Sync {
    /// Authorize issuance of the credential specified by `credential_configuration_id`.
    /// Returns `true` if the holder is authorized.
    fn authorize(
        &self, holder_id: &str, credential_configuration_id: &str,
    ) -> impl Future<Output = Result<bool>> + Send;

    /// Returns a populated `Claims` object for the given holder and credential
    /// definition.
    fn claims(
        &self, holder_id: &str, credential: &CredentialDefinition,
    ) -> impl Future<Output = Result<Claims>> + Send;
}

/// Signer is used by implementers to provide signing functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
pub trait Signer: Send + Sync {
    /// Algorithm returns the algorithm used by the signer.
    fn algorithm(&self) -> Algorithm;

    /// The verification method the verifier should use to verify the signer's
    /// signature. This is typically a DID URL + # + verification key ID.
    fn verification_method(&self) -> String;

    /// Sign is a convenience method for infallible Signer implementations.
    fn sign(&self, msg: &[u8]) -> impl Future<Output = Vec<u8>> + Send {
        let v = async { self.try_sign(msg).await.expect("should sign") };
        v.into_future()
    }

    /// `TrySign` is the fallible version of Sign.
    fn try_sign(&self, msg: &[u8]) -> impl Future<Output = Result<Vec<u8>>> + Send;
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
            Self::ES256K => write!(f, "ES256K"),
            Self::EdDSA => write!(f, "EdDSA"),
        }
    }
}

impl Algorithm {
    /// Returns the key type as a string.
    #[must_use]
    pub fn proof_type(&self) -> String {
        match self {
            Self::ES256K => String::from("EcdsaSecp256k1VerificationKey2019"),
            Self::EdDSA => String::from("JsonWebKey2020"),
        }
    }
}
