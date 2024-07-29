//! # Provider
//!
//! The provider traits exported by this module are used to inject functionality into the wallet
//! such as signing, state management and callbacks.
//!
//! See individual trait documentation for specific details.

use std::future::Future;

pub use datasec::jose::jwk::PublicKeyJwk;
pub use datasec::{Algorithm, Signer, Verifier};
pub use dif_exch::Constraints;
use openid::issuer::{
    CredentialRequest, CredentialResponse, MetadataRequest, MetadataResponse, TokenRequest,
    TokenResponse,
};
pub use openid::issuer::{IssuerMetadata, TxCode};
pub use openid::provider::{Result, StateManager};
use openid::verifier::{RequestObjectResponse, ResponseRequest, ResponseResponse};

use crate::credential::{Credential, Logo};

/// A trait that combines all the provider traits required to be implemented
/// by holder clients.
#[allow(clippy::module_name_repetitions)]
pub trait HolderProvider:
    IssuerClient + VerifierClient + CredentialStorer + StateManager + Signer + Verifier + Clone
{
}

/// This provider allows the wallet to interact with an issuer's services that are compliant with
/// OpenID for VC Issuance. While the specification is oriented towards HTTP, the trait allows the
/// wallet (and issuance services) to be transport layer agnostic.
#[allow(clippy::module_name_repetitions)]
pub trait IssuerClient {
    /// Get issuer metadata. If an error is returned, the wallet will cancel the issuance flow.
    fn get_metadata(
        &self, flow_id: &str, req: &MetadataRequest,
    ) -> impl Future<Output = anyhow::Result<MetadataResponse>> + Send;

    /// Get an access token. If an error is returned, the wallet will cancel the issuance flow.
    fn get_token(
        &self, flow_id: &str, req: &TokenRequest,
    ) -> impl Future<Output = anyhow::Result<TokenResponse>> + Send;

    /// Get a credential. If an error is returned, the wallet will cancel the issuance flow.
    fn get_credential(
        &self, flow_id: &str, req: &CredentialRequest,
    ) -> impl Future<Output = anyhow::Result<CredentialResponse>> + Send;

    /// Get a base64 encoded form of the credential logo. If an error is returned the wallet
    /// library will ignore.
    fn get_logo(
        &self, flow_id: &str, logo_url: &str,
    ) -> impl Future<Output = anyhow::Result<Logo>> + Send;
}

/// This provider allows the wallet to interact with a verifier's services that are compliant with
/// OpenID for Verifiable Presentations. While the specification is oriented towards HTTP, the trait
/// allows the wallet (and verifier's services) to be transport layer agnostic.
#[allow(clippy::module_name_repetitions)]
pub trait VerifierClient {
    /// Get a request object. If an error is returned, the wallet will cancel the presentation flow.
    fn get_request_object(
        &self, flow_id: &str, req: &str,
    ) -> impl Future<Output = anyhow::Result<RequestObjectResponse>> + Send;

    /// Send the presentation to the verifier.
    fn present(
        &self, flow_id: &str, uri: Option<&str>, presentation: &ResponseRequest,
    ) -> impl Future<Output = anyhow::Result<ResponseResponse>> + Send;
}

/// `CredentialStorer` is used by wallet implementations to provide persistent storage of Verifiable
/// Credentials.
#[allow(clippy::module_name_repetitions)]
pub trait CredentialStorer: Send + Sync {
    // TODO: should Credential param be owned?

    /// Save a `Credential` to the store. Overwrite any existing credential with the same ID. Create
    /// a new credential if one with the same ID does not exist.
    fn save(&self, credential: &Credential) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Retrieve a `Credential` from the store with the given ID. Return None if no credential with
    /// the ID exists.
    fn load(&self, id: &str) -> impl Future<Output = anyhow::Result<Option<Credential>>> + Send;

    // TODO: hide filtering by moving into vercre-holder library?

    /// Find the credentials that match the the provided filter. If `filter` is None, return all
    /// credentials in the store.
    fn find(
        &self, filter: Option<Constraints>,
    ) -> impl Future<Output = anyhow::Result<Vec<Credential>>> + Send;

    /// Remove the credential with the given ID from the store. Return an error if the credential
    /// does not exist.
    fn remove(&self, id: &str) -> impl Future<Output = anyhow::Result<()>> + Send;
}
