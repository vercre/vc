//! View model for the issuance sub-app

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use typeshare::typeshare;
use vercre_holder::issuance::Status;

use crate::model::credential::CredentialDisplay;

/// Status of the issuance flow
#[derive(Debug, Default, Deserialize, Serialize)]
#[typeshare]
pub enum IssuanceStatus {
    /// No credential offer is being processed.
    #[default]
    Inactive,

    /// A new credential offer has been received.
    Offered,

    /// Metadata has been retrieved and the offer is ready to be viewed.
    Ready,

    /// The offer requires a user pin to progress.
    PendingPin,

    /// The offer has been accepted and the credential is being issued.
    Accepted,

    /// A credential has been requested.
    Requested,

    /// The credential offer has failed, with an error message.
    Failed,
}

/// Convert from `vercre_holder::issuance::Status` to `IssuanceStatus`
impl From<Status> for IssuanceStatus {
    fn from(status: Status) -> Self {
        match status {
            Status::Inactive => Self::Inactive,
            Status::Offered => Self::Offered,
            Status::Ready => Self::Ready,
            Status::PendingPin => Self::PendingPin,
            Status::Accepted => Self::Accepted,
            Status::Requested => Self::Requested,
            _ => Self::Failed,
        }
    }
}

/// Issuance flow viewable state
#[derive(Debug, Default, Deserialize, Serialize)]
#[typeshare]
pub struct IssuanceView {
    /// Credential offer status
    pub status: IssuanceStatus,
    /// Credentials on offer
    pub credential: HashMap<String, CredentialDisplay>,
    /// PIN
    pub pin: Option<String>,
}

/// Types of PIN characters
#[derive(Debug, Default, Deserialize, Serialize)]
#[typeshare]
pub enum PinInputMode {
    /// Only digits
    #[default]
    Numeric,
    /// Any characters
    Text,
}

/// Criteria for PIN
#[derive(Debug, Default, Deserialize, Serialize)]
#[typeshare]
pub struct PinSchema {
    /// Input mode for the PIN
    pub input_mode: PinInputMode,

    /// Specifies the length of the PIN. This helps the Wallet to render
    /// the input screen and improve the user experience.
    pub length: i32,

    /// Guidance for the Holder of the Wallet on how to obtain the Transaction Code,
    pub description: Option<String>,
}
