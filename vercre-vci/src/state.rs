//! State is used by the library to persist request information between steps
//! in the issuance process.

use chrono::{DateTime, Duration, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use vercre_core::error::Err;
use vercre_core::vci::{CredentialRequest, TokenAuthorizationDetail};
use vercre_core::{err, Result};
pub(crate) enum Expire {
    AuthCode,
    Access,
    Nonce,
}

impl Expire {
    pub(crate) fn duration(&self) -> Duration {
        match self {
            Expire::AuthCode => Duration::minutes(5),
            Expire::Access => Duration::minutes(15),
            Expire::Nonce => Duration::minutes(10),
        }
    }
}

/// State is used to persist request information between issuance steps
/// for the Credential Issuer.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct State {
    /// The time this state item should expire.
    #[builder(default = "Utc::now() + Expire::Access.duration()")]
    pub(crate) expires_at: DateTime<Utc>,

    /// The URL of the Credential Issuer.
    pub(crate) credential_issuer: String,

    /// The client_id of the Wallet requesting issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(setter(into, strip_option), default)]
    pub(crate) client_id: Option<String>,

    /// Identifiers of credentials offered to/requested by the Wallet.
    #[builder(default)]
    pub(crate) credential_configuration_ids: Vec<String>,

    /// The subject of the credential Holder.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub(crate) holder_id: Option<String>,

    /// The callback ID for the current request.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub(crate) callback_id: Option<String>,

    /// Authorization state.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub(crate) auth: Option<AuthState>,

    /// Token state.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub(crate) token: Option<TokenState>,

    /// Deferred step state.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub(crate) deferred: Option<DeferredState>,
}

/// `AuthState` is used to store authorization state.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[builder(default)]
pub(crate) struct AuthState {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(setter(into, strip_option))]
    pub(crate) redirect_uri: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(setter(into, strip_option))]
    pub(crate) code_challenge: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(setter(into, strip_option))]
    pub(crate) code_challenge_method: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) scope: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) user_code: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) authorization_details: Option<Vec<TokenAuthorizationDetail>>,
}

/// `TokenState` is used to store token state.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct TokenState {
    /// The access token.
    pub(crate) access_token: String,

    /// The type of token issued (should be "Bearer")
    #[builder(setter(into), default = "\"Bearer\".to_string()")]
    pub(crate) token_type: String,

    /// The refresh token, issued
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub(crate) refresh_token: Option<String>,

    /// The nonce to be used by the Wallet when creating a proof of possession of
    /// the key proof.
    pub(crate) c_nonce: String,

    /// Number denoting the lifetime in seconds of the c_nonce.
    #[builder(default = "Utc::now() + Expire::Nonce.duration()")]
    pub(crate) c_nonce_expires_at: DateTime<Utc>,
}

impl State {
    /// Returns a new [`StateBuilder`], which can be used to build a [State]
    #[must_use]
    pub(crate) fn builder() -> StateBuilder {
        StateBuilder::default()
    }

    /// Serializes this [`State`] object into a byte array.
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        // TODO: return Result instead of panicking
        match serde_json::to_vec(self) {
            Ok(res) => res,
            Err(e) => panic!("Failed to serialize state: {e}"),
        }
    }

    /// Determines whether state has expired or not.
    pub(crate) fn expired(&self) -> bool {
        self.expires_at.signed_duration_since(Utc::now()).num_seconds() < 0
    }
}

impl TryFrom<&[u8]> for State {
    type Error = vercre_core::error::Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        match serde_json::from_slice::<Self>(value) {
            Ok(res) => {
                if res.expired() {
                    err!(Err::InvalidRequest, "state has expired");
                }
                Ok(res)
            }
            Err(e) => err!(Err::ServerError(e.into()), "Failed to deserialize state"),
        }
    }
}

impl TryFrom<Vec<u8>> for State {
    type Error = vercre_core::error::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        State::try_from(value.as_slice())
    }
}

impl TokenState {
    pub(crate) fn c_nonce_expires_in(&self) -> i64 {
        self.c_nonce_expires_at.signed_duration_since(Utc::now()).num_seconds()
    }

    pub(crate) fn c_nonce_expired(&self) -> bool {
        self.c_nonce_expires_in() < 0
    }
}

/// `TokenState` is used to store token state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct DeferredState {
    /// Used to identify a Deferred Issuance transaction. Is used as the
    /// state persistence key.
    pub(crate) transaction_id: String,

    /// Save the CredentialRequest when issuance is deferred.
    pub(crate) credential_request: CredentialRequest,
}

impl AuthState {
    /// Returns a new [`AuthStateBuilder`], which can be used to build a [`State`]
    #[must_use]
    pub(crate) fn builder() -> AuthStateBuilder {
        AuthStateBuilder::default()
    }
}

impl TokenState {
    /// Returns a new [`TokenStateBuilder`], which can be used to build a [`TokenState`]
    #[must_use]
    pub(crate) fn builder() -> TokenStateBuilder {
        TokenStateBuilder::default()
    }
}
