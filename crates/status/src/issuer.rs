//! # Status (Issuer)
//!
//! Traits and types for managing the publication of a credential status as an
//! issuer.

use std::future::Future;

pub use vercre_core::Quota;
pub use vercre_w3c_vc::model::CredentialStatus;

use crate::provider;

/// The `Status` trait specifies how status information can be looked up for a
/// credential.
pub trait Status: Send + Sync {
    /// Returns information on how to look up the status of a credential.
    ///
    /// A default implementation is provided that just returns `None` for cases
    /// where the issuer will not be providing a status endpoint.
    fn status(
        &self, _holder_subject: &str, _credential_identifier: &str,
    ) -> impl Future<Output = provider::Result<Option<Quota<CredentialStatus>>>> + Send {
        async { Ok(None) }
    }
}
