//! User defines traits the library requires to be implemented for dynamically
//! provided user information.

use std::collections::HashMap;
use std::future::Future;

use openid4vc::issuance::ClaimDefinition;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The user information returned by the Subject trait.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Claims {
    /// The credential subject populated for the user.
    pub claims: HashMap<String, Value>,

    /// Specifies whether user information required for the credential subject
    /// is pending.
    pub pending: bool,
}

/// The Subject trait specifies how the library expects user information to be
/// provided by implementers.
pub trait Subject: Send + Sync {
    /// Authorize issuance of the credential specified by `credential_configuration_id`.
    /// Returns `true` if the subject (holder) is authorized.
    fn authorize(
        &self, holder_subject: &str, credential_identifier: &str,
    ) -> impl Future<Output = crate::Result<bool>> + Send;

    /// Returns a populated `Claims` object for the given subject (holder) and credential
    /// definition.
    fn claims(
        &self, holder_subject: &str, credential_identifier: &str,
        credential_subject: Option<HashMap<String, ClaimDefinition>>,
    ) -> impl Future<Output = crate::Result<Claims>> + Send;
}
