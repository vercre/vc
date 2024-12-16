//! View model for the presentation sub-app

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::app::presentation::PresentationState;
use crate::view::credential::CredentialDisplay;

/// Status of the presentation flow. This is re-typed instead of using the
/// status defined by vercre-holder so that we can use typeshare to generate the
/// equivalent TypeScript enum.
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
}

/// Convert from `vercre_holder::presentation::Status` to `PresentationStatus`
impl From<PresentationState> for PresentationStatus {
    fn from(status: PresentationState) -> Self {
        match status {
            PresentationState::Inactive => Self::Inactive,
            PresentationState::Requested(_, _) => Self::Requested,
            PresentationState::Authorized(_) => Self::Authorized,
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
        match state.clone() {
            PresentationState::Inactive => (),
            PresentationState::Requested(_flow, credentials) => {
                for cred in &credentials {
                    creds.insert(cred.id.clone(), cred.into());
                }
            }
            PresentationState::Authorized(flow) => {
                let credentials = flow.credentials();
                for cred in &credentials {
                    creds.insert(cred.id.clone(), cred.into());
                }
            }
        }
        Self {
            status: state.into(),
            credentials: creds,
        }
    }
}
