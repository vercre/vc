//! View model for the presentation sub-app

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::{app::PresentationState, view::credential::CredentialDisplay};

/// Status of the presentation flow. This is re-typed instead of using the status defined by
/// vercre-holder so that we can use typeshare to generate the equivalent TypeScript enum.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[typeshare]
#[allow(clippy::module_name_repetitions)]
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
impl From<vercre_holder::PresentationStatus> for PresentationStatus {
    fn from(status: vercre_holder::PresentationStatus) -> Self {
        match status {
            vercre_holder::PresentationStatus::Inactive => Self::Inactive,
            vercre_holder::PresentationStatus::Requested => Self::Requested,
            vercre_holder::PresentationStatus::Authorized => Self::Authorized,
            vercre_holder::PresentationStatus::Failed(_) => Self::Failed,
        }
    }
}

/// Presentation flow viewable state
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[typeshare]
#[allow(clippy::module_name_repetitions)]
pub struct PresentationView {
    /// Presentation request status
    pub status: PresentationStatus,
    /// Credentials to present
    pub credentials: HashMap<String, CredentialDisplay>,
}

/// Convert underlying presentation flow state to view model
impl From<PresentationState> for PresentationView {
    fn from(state: PresentationState) -> Self {
        let mut creds = HashMap::new();
        for cred in &state.credentials {
            creds.insert(cred.id.clone(), cred.into());
        }
        Self {
            status: state.status.into(),
            credentials: creds,
        }
    }
}
