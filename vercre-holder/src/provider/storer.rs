//! # Credential Storer
//!
//! Trait for the management of credential storage by the wallet client. Used by the wallet
//! endpoints.

use std::future::Future;

use vercre_exch::Constraints;

use crate::credential::Credential;
use crate::provider::Result;

/// `CredentialStorer` is used by wallet implementations to provide persistent storage of Verifiable
/// Credentials.
#[allow(clippy::module_name_repetitions)]
pub trait CredentialStorer: Send + Sync {
    /// Save a `Credential` to the store. Overwrite any existing credential with the same ID. Create
    /// a new credential if one with the same ID does not exist.
    fn save(&self, credential: &Credential) -> impl Future<Output = Result<()>> + Send;

    /// Retrieve a `Credential` from the store with the given ID. Return None if no credential with
    /// the ID exists.
    fn load(&self, id: &str) -> impl Future<Output = Result<Option<Credential>>> + Send;

    /// Find the credentials that match the the provided filter. If `filter` is None, return all
    /// credentials in the store.
    fn find(
        &self, filter: Option<Constraints>,
    ) -> impl Future<Output = Result<Vec<Credential>>> + Send;

    /// Remove the credential with the given ID from the store. Return an error if the credential
    /// does not exist.
    fn remove(&self, id: &str) -> impl Future<Output = Result<()>> + Send;
}
