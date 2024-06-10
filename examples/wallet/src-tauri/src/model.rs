mod credential;
mod issuance;
mod presentation;

use serde::{Deserialize, Serialize};
use typeshare::typeshare;

#[derive(Deserialize, Serialize)]
#[typeshare]
pub enum SubApp {
    Credential,
    Issuance,
    Presentation,
}

#[derive(Deserialize, Serialize)]
#[typeshare]
pub struct ViewModel {
    sub_app: SubApp,
    credential: Option<credential::CredentialView>,
    issuance: Option<issuance::IssuanceView>,
    presentation: Option<presentation::PresentationView>,
    /// Error message, if any
    pub error: Option<String>,
}
