//! View model for the presentation sub-app

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use typeshare::typeshare;
use vercre_holder::presentation::Status;

use crate::model::credential::CredentialDisplay;

/// Status of the presentation flow
#[derive(Debug, Default, Deserialize, Serialize)]
#[typeshare]
pub enum PresentationStatus {
    /// No authorization request is being processed.
    #[default]
    Inactive,

    /// A new authorization request has been received.
    Requested,

    /// The authorization request has been authorized.
    Authorized,

    /// The authorization request has failed, with an error message.
    Failed,
}

/// Convert from `vercre_holder::presentation::Status` to `PresentationStatus`
impl From<Status> for PresentationStatus {
    fn from(status: Status) -> Self {
        match status {
            Status::Inactive => Self::Inactive,
            Status::Requested => Self::Requested,
            Status::Authorized => Self::Authorized,
            _ => Self::Failed,
        }
    }
}

/// Presentation flow viewable state
#[derive(Debug, Default, Deserialize, Serialize)]
#[typeshare]
pub struct PresentationView {
    /// Presentation request status
    pub status: PresentationStatus,
    /// Credentials to present
    pub credentials: HashMap<String, CredentialDisplay>,
}
