//! View model for the issuance sub-app

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use typeshare::typeshare;
use vercre_holder::issuance::{Issuance, Status, TxCode};

use crate::view::credential::CredentialDisplay;

/// Status of the issuance flow
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[typeshare]
#[allow(clippy::module_name_repetitions)]
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
            Status::Failed(_) => Self::Failed,
        }
    }
}

/// Issuance flow viewable state
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[typeshare]
#[allow(clippy::module_name_repetitions)]
pub struct IssuanceView {
    /// Credential offer status
    pub status: IssuanceStatus,
    /// Credentials on offer
    pub credentials: HashMap<String, CredentialDisplay>,
    /// PIN
    pub pin: Option<String>,
    /// PIN schema
    pub pin_schema: Option<PinSchema>,
}

/// Convert the underlying issuance flow state to a view model of the same
impl From<Issuance> for IssuanceView {
    fn from(state: Issuance) -> Self {
        let mut creds: HashMap<String, CredentialDisplay> = HashMap::new();
        for (id, offered) in &state.offered {
            let mut cred: CredentialDisplay = offered.into();
            cred.issuer = Some(state.offer.credential_issuer.clone());
            creds.insert(id.clone(), cred);
        }
        let mut schema = None;
        if let Some(grants) = state.offer.grants {
            if let Some(pre_authorized_code) = grants.pre_authorized_code {
                if let Some(tx_code) = pre_authorized_code.tx_code {
                    schema = Some(tx_code.into());
                } 
            }
        }
        Self {
            status: state.status.into(),
            credentials: creds,
            pin: state.pin,
            pin_schema: schema,
        }
    }
}

/// Types of PIN characters
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[typeshare]
pub enum PinInputMode {
    /// Only digits
    #[default]
    Numeric,
    /// Any characters
    Text,
}

/// Criteria for PIN
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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

impl From<TxCode> for PinSchema {
    fn from(tx_code: TxCode) -> Self {
        let mut input_mode: PinInputMode = PinInputMode::Numeric;
        if let Some(mode) = tx_code.input_mode {
            if mode == "text" {
                input_mode = PinInputMode::Text;
            }
        }
        Self {
            input_mode,
            length: tx_code.length.unwrap_or(6),
            description: tx_code.description.clone(),
        }
    }
}
