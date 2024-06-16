pub mod credential;
pub mod issuance;
pub mod presentation;

use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::app::{AppState, SubApp};

/// View model for the shell to render. All state is translated into this model.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[typeshare]
#[allow(clippy::module_name_repetitions)]
pub struct ViewModel {
    /// The sub-app currently active
    pub sub_app: SubApp,
    /// Credential sub-app view state.
    pub credential: Option<credential::CredentialView>,
    /// Issuance sub-app view state.
    pub issuance: Option<issuance::IssuanceView>,
    /// Presentation sub-app view state.
    pub presentation: Option<presentation::PresentationView>,
    /// Error message, if any
    pub error: Option<String>,
}

impl From<AppState> for ViewModel {
    fn from(state: AppState) -> Self {
        Self {
            sub_app: state.sub_app.clone(),
            credential: match state.sub_app {
                SubApp::Credential => Some(credential::CredentialView::from(state.credential)),
                _ => None,
            },
            issuance: match state.sub_app {
                SubApp::Issuance => Some(issuance::IssuanceView::from(state.issuance)),
                _ => None,
            },
            presentation: match state.sub_app {
                SubApp::Presentation => Some(presentation::PresentationView::from(state.presentation)),
                _ => None,
            },
            error: None,
        }
    }
}
