mod credential;
mod issuance;
mod presentation;

use serde::{Deserialize, Serialize};
use typeshare::typeshare;

#[derive(Debug, Default, Deserialize, Serialize)]
#[typeshare]
pub enum SubApp {
    #[default]
    Splash,
    Credential,
    Issuance,
    Presentation,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[typeshare]
pub struct ViewModel {
    pub sub_app: SubApp,
    pub credential: Option<credential::CredentialView>,
    pub issuance: Option<issuance::IssuanceView>,
    pub presentation: Option<presentation::PresentationView>,
    /// Error message, if any
    pub error: Option<String>,
}
