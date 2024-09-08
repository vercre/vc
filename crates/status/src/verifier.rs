//! # Status (Verifier)
//! 
//! Traits and type for managing the verification of a credential status as a
//! verifier.

use std::future::Future;

pub use vercre_w3c_vc::model::CredentialStatus;

use crate::provider;

/// The `Status` trait is used to proxy the resolution of a credential status.
/// 
/// Given a credential's status look-up information, the implementer should use
/// that to retrieve a published credential status list and look into that for
/// the current status of the credential.
pub trait Status: Send + Sync {
    /// Returns `true` if the credential currently has the requested status,
    /// `false` otherwise. 
    ///
    /// # Errors
    ///
    /// Returns an error if the status list cannot be retrieved or the status
    /// for the given credential cannot be resolved from the list.
    fn status(
        &self,
        status: &CredentialStatus,
        credential_identifier: &str,
    ) -> impl Future<Output = provider::Result<bool>> + Send;
} 