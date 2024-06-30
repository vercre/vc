//! State is used by the library to persist request information between steps
//! in the issuance process.
use anyhow::anyhow;
use chrono::{DateTime, TimeDelta, Utc};
use derive_builder::Builder;
use openid4vc::error::Err;
use openid4vc::issuance::{CredentialRequest, TokenAuthorizationDetail};
use openid4vc::Result;
use serde::{Deserialize, Serialize};

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
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct State {
    /// The time this state item should expire.
    #[builder(default = "Utc::now() + Expire::Access.duration()")]
    pub expires_at: DateTime<Utc>,

    /// The URL of the Credential Issuer.
    pub credential_issuer: String,

    /// The `client_id` of the Wallet requesting issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(setter(into, strip_option), default)]
    pub client_id: Option<String>,

    /// Identifiers of credentials offered to/requested by the Wallet.
    #[builder(default)]
    pub credential_configuration_ids: Vec<String>,

    /// The subject of the credential Holder.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub holder_id: Option<String>,

    /// The callback ID for the current request.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub callback_id: Option<String>,

    /// Authorization state.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub auth: Option<Auth>,

    /// Token state.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub token: Option<Token>,

    /// Deferred step state.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub deferred: Option<Deferred>,
}

/// `Auth` is used to store authorization state.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[builder(default)]
pub struct Auth {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(setter(into, strip_option))]
    pub redirect_uri: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(setter(into, strip_option))]
    pub code_challenge: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(setter(into, strip_option))]
    pub code_challenge_method: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_code: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<TokenAuthorizationDetail>>,
}

/// `Token` is used to store token state.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Token {
    /// The access token.
    #[allow(clippy::struct_field_names)]
    pub access_token: String,

    /// The type of token issued (should be "Bearer")
    #[allow(clippy::struct_field_names)]
    #[builder(setter(into), default = "String::from(\"Bearer\")")]
    pub token_type: String,

    /// The refresh token, issued
    #[allow(clippy::struct_field_names)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub refresh_token: Option<String>,

    /// The nonce to be used by the Wallet when creating a proof of possession of
    /// the key proof.
    pub c_nonce: String,

    /// Number denoting the lifetime in seconds of the `c_nonce`.
    #[builder(default = "Utc::now() + Expire::Nonce.duration()")]
    pub c_nonce_expires_at: DateTime<Utc>,
}

impl State {
    /// Returns a new [`StateBuilder`], which can be used to build a [State]
    #[must_use]
    pub fn builder() -> StateBuilder {
        StateBuilder::default()
    }

    /// Serializes this [`State`] object into a byte array.
    pub fn to_vec(&self) -> Vec<u8> {
        // TODO: return Result instead of panicking
        match serde_json::to_vec(self) {
            Ok(res) => res,
            Err(e) => panic!("Failed to serialize state: {e}"),
        }
    }

    /// Determines whether state has expired or not.
    pub fn expired(&self) -> bool {
        self.expires_at.signed_duration_since(Utc::now()).num_seconds() < 0
    }
}

impl TryFrom<&[u8]> for State {
    type Error = openid4vc::error::Err;

    fn try_from(value: &[u8]) -> Result<Self> {
        match serde_json::from_slice::<Self>(value) {
            Ok(res) => {
                if res.expired() {
                    return Err(Err::InvalidRequest("state has expired".into()));
                }
                Ok(res)
            }
            Err(e) => Err(Err::ServerError(anyhow!("Failed to deserialize state: {e}"))),
        }
    }
}

impl TryFrom<Vec<u8>> for State {
    type Error = openid4vc::error::Err;

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

/// `Token` is used to store token state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Deferred {
    /// Used to identify a Deferred Issuance transaction. Is used as the
    /// state persistence key.
    pub transaction_id: String,

    /// Save the Credential request when issuance is deferred.
    pub credential_request: CredentialRequest,
}

impl Auth {
    /// Returns a new [`AuthBuilder`], which can be used to build a [`State`]
    #[must_use]
    pub fn builder() -> AuthBuilder {
        AuthBuilder::default()
    }
}

impl Token {
    /// Returns a new [`TokenBuilder`], which can be used to build a [`Token`]
    #[must_use]
    pub fn builder() -> TokenBuilder {
        TokenBuilder::default()
    }
}
