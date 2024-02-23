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
    #[builder( default)]
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
                    err!(Err::InvalidRequest, "State has expired");
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

/// `AuthState` is used to store authorization state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct AuthState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) redirect_uri: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) code_challenge: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) code_challenge_method: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) scope: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) user_code: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) authorization_details: Option<Vec<TokenAuthorizationDetail>>,
}

/// `TokenState` is used to store token state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct TokenState {
    /// The access token.
    pub(crate) access_token: String,

    /// The type of token issued (should be "Bearer")
    pub(crate) token_type: String,

    /// The refresh token, issued
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) refresh_token: Option<String>,

    /// The nonce to be used by the Wallet when creating a proof of possession of
    /// the key proof.
    pub(crate) c_nonce: String,

    /// Number denoting the lifetime in seconds of the c_nonce.
    pub(crate) c_nonce_expires_at: DateTime<Utc>,
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
        AuthStateBuilder::new()
    }
}

/// [`AuthStateBuilder`] is used to build a [`AuthState`]
#[derive(Clone, Default)]
pub(crate) struct AuthStateBuilder {
    pub(crate) state: AuthState,
}

impl AuthStateBuilder {
    /// Returns a new [`AuthStateBuilder`]
    #[must_use]
    pub(crate) fn new() -> Self {
        AuthStateBuilder::default()
    }

    /// The client's redirection endpoint if `redirect_uri` was included in the
    /// authorization request. Only used when `grant_type` is "`authorization_code`".
    ///
    /// REQUIRED if the `redirect_uri` parameter was included in the authorization
    /// request and values MUST be identical.
    #[must_use]
    pub(crate) fn redirect_uri(mut self, redirect_uri: String) -> Self {
        self.state.redirect_uri = Some(redirect_uri);
        self
    }

    /// Sets the `code_challenge` properties
    #[must_use]
    pub(crate) fn code_challenge(mut self, challenge: String, method: String) -> Self {
        self.state.code_challenge = Some(challenge);
        self.state.code_challenge_method = Some(method);
        self
    }

    /// Sets the `scope` property
    #[must_use]
    pub(crate) fn scope(mut self, scope: Option<String>) -> Self {
        self.state.scope = scope;
        self
    }

    /// Sets the `user_code` property
    #[must_use]
    pub(crate) fn user_code(mut self, user_code: Option<String>) -> Self {
        self.state.user_code = user_code;
        self
    }

    /// Turns this builder into a [`AuthState`]
    pub(crate) fn build(self) -> AuthState {
        self.state
    }
}

impl TokenState {
    /// Returns a new [`TokenStateBuilder`], which can be used to build a [`TokenState`]
    #[must_use]
    pub(crate) fn builder() -> TokenStateBuilder {
        TokenStateBuilder::new()
    }
}

/// [`TokenStateBuilder`] is used to build a [`TokenState`]
#[derive(Clone, Default)]
pub(crate) struct TokenStateBuilder {
    state: TokenState,
}

impl TokenStateBuilder {
    /// Returns a new [`TokenStateBuilder`]
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            state: TokenState {
                token_type: "Bearer".to_string(),
                c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
                ..Default::default()
            },
        }
    }

    /// Sets the `access_token` property
    #[must_use]
    pub(crate) fn access_token(mut self, access_token: String) -> Self {
        self.state.access_token = access_token;
        self
    }

    /// Sets the `nonce` property
    #[must_use]
    pub(crate) fn c_nonce(mut self, c_nonce: String) -> Self {
        self.state.c_nonce = c_nonce;
        self
    }

    /// Turns this builder into a [`TokenState`]
    pub(crate) fn build(self) -> TokenState {
        self.state
    }
}
