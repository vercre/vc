//! This module has types for the application state. The application is divided into sub-apps,
//! so the shape of the state depends on whether the application is managing credentials,
//! responding to an offer of issuance, or responding to a request for presentation. The underlying
//! application state is translated into a view model for the shell to render.

use vercre_holder::credential::Credential;
use vercre_holder::issuance;
use vercre_holder::presentation;

use crate::model;

/// Application state
#[derive(Debug, Default)]
pub(crate) struct AppState {
    /// The sub-app currently active
    pub sub_app: model::SubApp,
    /// Credentials stored in the wallet
    pub credentials: Vec<Credential>,
    /// State of issuance flow (if active)
    pub issuance: IssuanceState,
    /// State of presentation flow (if active)
    pub presentation: PresentationState,
}

/// Issuance sub-app state
#[derive(Debug, Default)]
pub(crate) struct IssuanceState {
    /// Flow status
    pub status: issuance::Status,
    /// Flow state
    pub state: issuance::Issuance,
}

/// Presentation sub-app state
#[derive(Debug, Default)]
pub(crate) struct PresentationState {
    /// Flow status
    pub status: presentation::Status,
    /// Flow state
    pub state: presentation::Presentation,
}
