//! State is used by the library to persist request information between steps
//! in the issuance process.

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use vercre_openid::issuer::{CredentialRequest, TokenAuthorizationDetail};
use vercre_openid::{Error, Result};

pub enum Expire {
    AuthCode,
    Access,
    Nonce,
}

impl Expire {
    pub fn duration(&self) -> TimeDelta {
        match self {
            Self::AuthCode => TimeDelta::try_minutes(5).unwrap_or_default(),
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

    /// URL of the Credential Issuer.
    pub credential_issuer: String,

    /// The `client_id` of the Wallet requesting issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// Identifiers of credentials offered to/requested by the Wallet.
    pub credential_identifiers: Vec<String>,

    /// Flow-specific issuance state.
    pub flow: Flow,

    /// The subject the credential is to be issued for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Flow {
    #[default]
    Unauthorized,

    /// Authorization state.
    AuthCode(AuthCode),

    /// Token state.
    Token(Token),

    /// Deferred issuance state.
    Deferred(Deferred),
}

/// `Auth` is used to store authorization state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuthCode {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<TokenAuthorizationDetail>>,
}

/// `Token` is used to store token state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Token {
    /// The access token.
    #[allow(clippy::struct_field_names)]
    pub access_token: String,

    /// The type of token issued (should be "Bearer")
    #[allow(clippy::struct_field_names)]
    pub token_type: String,

    /// The refresh token, issued
    #[allow(clippy::struct_field_names)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    /// The nonce to be used by the Wallet when creating a proof of possession of
    /// the key proof.
    pub c_nonce: String,

    /// Number denoting the lifetime in seconds of the `c_nonce`.
    pub c_nonce_expires_at: DateTime<Utc>,
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

impl State {
    /// Serializes this [`State`] object into a byte array.
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        match serde_json::to_vec(self) {
            Ok(res) => Ok(res),
            Err(e) => Err(Error::ServerError(format!("issue serializing state: {e}"))),
        }
    }

    pub fn from_slice(value: &[u8]) -> Result<Self> {
        match serde_json::from_slice::<Self>(value) {
            Ok(res) => {
                if res.expired() {
                    return Err(Error::InvalidRequest("state has expired".into()));
                }
                Ok(res)
            }
            Err(e) => Err(Error::ServerError(format!("failed to deserialize state: {e}"))),
        }
    }

    /// Determines whether state has expired or not.
    pub fn expired(&self) -> bool {
        self.expires_at.signed_duration_since(Utc::now()).num_seconds() < 0
    }
}

impl TryFrom<&[u8]> for State {
    type Error = vercre_openid::Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for State {
    type Error = vercre_openid::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        Self::try_from(value.as_slice())
    }
}

impl Token {
    pub fn c_nonce_expires_in(&self) -> i64 {
        self.c_nonce_expires_at.signed_duration_since(Utc::now()).num_seconds()
    }

    pub fn c_nonce_expired(&self) -> bool {
        self.c_nonce_expires_in() < 0
    }
}
