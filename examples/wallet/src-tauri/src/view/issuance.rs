//! View model for the issuance sub-app

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use typeshare::typeshare;
use vercre_holder::TxCode;

use crate::app::issuance::IssuanceState;
use crate::view::credential::CredentialDisplay;

/// Status of the issuance flow.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[typeshare]
#[allow(clippy::module_name_repetitions)]
pub enum IssuanceStatus {
    /// No issuance flow is active.
    #[default]
    Inactive,

    /// An issuance request has been received.
    Offered,

    /// The issuance request has been accepted.
    Accepted,

    /// The issuance request has been accepted but a PIN is required.
    PendingPin,

    /// The issuance request has been tokenized.
    Tokenized,
}

/// Issuance flow viewable state
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[typeshare]
#[allow(clippy::module_name_repetitions)]
pub struct IssuanceView {
    /// Credentials on offer
    pub credentials: HashMap<String, CredentialDisplay>,
    /// PIN
    pub pin: Option<String>,
    /// PIN schema
    pub pin_schema: Option<PinSchema>,
    /// Where we are up to in the flow.
    pub status: IssuanceStatus,
}

/// Convert the underlying issuance flow state to a view model of the same
impl From<IssuanceState> for IssuanceView {
    fn from(state: IssuanceState) -> Self {
        let mut creds: HashMap<String, CredentialDisplay> = HashMap::new();
        let (on_offer, issuer, offer, pin, mut status) = match state {
            IssuanceState::Inactive => return Self::default(),
            IssuanceState::Offered(state) => {
                (state.offered(), state.issuer(), state.offer(), None, IssuanceStatus::Offered)
            }
            IssuanceState::Accepted(state) => (
                state.offered(),
                state.issuer(),
                state.offer(),
                state.pin(),
                IssuanceStatus::Accepted,
            ),
            IssuanceState::Token(state) => (
                state.offered(),
                state.issuer(),
                state.offer(),
                state.pin(),
                IssuanceStatus::Tokenized,
            ),
        };
        for (id, offered) in &on_offer {
            let mut cred: CredentialDisplay = offered.into();
            cred.issuer = Some(issuer.credential_issuer.clone());
            creds.insert(id.clone(), cred);
        }
        let tx_code = match offer.pre_authorized_code() {
            Some(pre_auth) => pre_auth.tx_code,
            None => None,
        };
        if status == IssuanceStatus::Accepted && pin.is_none() && tx_code.is_some() {
            status = IssuanceStatus::PendingPin;
        }
        let schema = tx_code.map(Into::into);
        Self {
            credentials: creds,
            pin,
            pin_schema: schema,
            status,
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

    /// Guidance for the Holder of the Wallet on how to obtain the Transaction
    /// Code,
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
