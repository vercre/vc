//! State is used by the library to persist request information between steps
//! in the issuance process.

use std::collections::HashMap;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use vercre_openid::issuer::{Authorized, CredentialOffer, CredentialRequest};

pub enum Expire {
    Authorized,
    Access,
    Nonce,
}

impl Expire {
    pub fn duration(&self) -> TimeDelta {
        match self {
            Self::Authorized => TimeDelta::try_minutes(5).unwrap_or_default(),
            Self::Access => TimeDelta::try_minutes(15).unwrap_or_default(),
            Self::Nonce => TimeDelta::try_minutes(10).unwrap_or_default(),
        }
    }
}

/// State is used to persist request information between issuance steps
/// for the Credential Issuer.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct State {
    /// Time state should expire.
    pub expires_at: DateTime<Utc>,

    /// Identifies the (previously authenticated) Holder in order that Issuer can
    /// authorize credential issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,

    // Authorized credentials (configuration id and identifier).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<HashMap<String, String>>,

    /// Credential Offer when offer made by reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_offer: Option<CredentialOffer>,

    /// Step-specific issuance state.
    pub current_step: Step,
}

// impl State {
//     /// Determines whether state has expired or not.
//     pub fn expired(&self) -> bool {
//         self.expires_at.signed_duration_since(Utc::now()).num_seconds() < 0
//     }
// }

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum Step {
    #[default]
    Unauthorized,

    /// Pre-authorized state.
    PreAuthorized(PreAuthorized),

    /// Authorization state.
    Authorization(Authorization),

    /// Token state.
    Token(Token),

    /// Deferred issuance state.
    Deferred(Deferred),
}

/// `Auth` is used to store authorization state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PreAuthorized {
    /// Lists credential identifiers that the Wallet is authorized to request.
    pub authorized: Vec<Authorized>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<String>,
}

/// `Auth` is used to store authorization state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Authorization {
    /// PKCE code challenge from the Authorization Request.
    pub code_challenge: String,

    /// PKCE code challenge method from the Authorization Request.
    pub code_challenge_method: String,

    /// Lists credential identifiers that the Wallet is authorized to request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized: Option<Vec<Authorized>>,

    /// Lists credentials (as scope items) that the Wallet is authorized to request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// The `client_id` of the Wallet requesting issuance.
    pub client_id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
}

/// `Token` is used to store token state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Token {
    /// The access token.
    #[allow(clippy::struct_field_names)]
    pub access_token: String,

    /// The nonce to be used by the Wallet when creating a proof of possession of
    /// the key proof.
    pub c_nonce: String,

    /// Number denoting the lifetime in seconds of the `c_nonce`.
    pub c_nonce_expires_at: DateTime<Utc>,
}

impl Token {
    pub fn c_nonce_expires_in(&self) -> i64 {
        self.c_nonce_expires_at.signed_duration_since(Utc::now()).num_seconds()
    }

    pub fn c_nonce_expired(&self) -> bool {
        self.c_nonce_expires_in() < 0
    }
}

/// `Token` is used to store token state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Deferred {
    /// Used to identify a Deferred Issuance transaction. Is used as the
    /// state persistence key.
    pub transaction_id: String,

    /// Save the Credential request when issuance is deferred.
    pub credential_request: CredentialRequest,
}
