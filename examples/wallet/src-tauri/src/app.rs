//! This module has types for the application state. The application is divided into sub-apps,
//! so the shape of the state depends on whether the application is managing credentials,
//! responding to an offer of issuance, or responding to a request for presentation. The underlying
//! application state is translated into a view model for the shell to render.

mod credential;
mod issuance;
mod presentation;

use serde::{Deserialize, Serialize};
use typeshare::typeshare;
use vercre_holder::{Credential, Issuance, Presentation};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[typeshare]
#[allow(clippy::module_name_repetitions)]
pub enum SubApp {
    #[default]
    Splash,
    Credential,
    Issuance,
    Presentation,
}

/// Application state
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct AppState {
    /// The sub-app currently active
    pub sub_app: SubApp,
    /// Credentials stored in the wallet
    pub credential: Vec<Credential>,
    /// State of issuance flow (if active)
    pub issuance: Issuance,
    /// State of presentation flow (if active)
    pub presentation: Presentation,
    /// Error information
    pub error: Option<String>,
}

// impl AppState {
//     //Set the application state to a startup state.

//     pub fn init(&mut self) {
//         self.sub_app = SubApp::Splash;
//         self.credential = Vec::new();
//         self.issuance = Issuance::default();
//         self.presentation = Presentation::default();
//         self.error = None;
//     }
// }
