mod credential;
mod issuance;
mod presentation;

use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::app::AppState;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[typeshare]
pub enum SubApp {
    #[default]
    Splash,
    Credential,
    Issuance,
    Presentation,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[typeshare]
#[allow(clippy::module_name_repetitions)]
pub struct ViewModel {
    pub sub_app: SubApp,
    pub credential: Option<credential::CredentialView>,
    pub issuance: Option<issuance::IssuanceView>,
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
                SubApp::Issuance => Some(issuance::IssuanceView::default()),
                _ => None,
            },
            presentation: match state.sub_app {
                SubApp::Presentation => Some(presentation::PresentationView::default()),
                _ => None,
            },
            error: None,
        }
    }
}
