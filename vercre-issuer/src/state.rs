//! State is used by the library to persist request information between steps
//! in the issuance process.

use std::collections::HashMap;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use vercre_openid::issuer::{
    AuthorizationDetail, CodeChallengeMethod, CredentialOffer, CredentialRequest, RequestObject,
};
use vercre_w3c_vc::model::VerifiableCredential;

type CredentialIdentifier = String;

/// State is used to persist request information between issuance steps in the
/// Credential issuance process.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct State {
    /// Identifies the (previously authenticated) Holder in order that Issuer
    /// can authorize credential issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,

    /// Stage holds data relevant to the current state of the issuance process.
    /// This data is used by subsequent step(s) to verify Wallet interactions,
    /// including credential issuance.
    pub stage: Stage,

    /// Time state should expire.
    pub expires_at: DateTime<Utc>,
}

impl State {
    /// Determines whether state has expired or not.
    pub fn is_expired(&self) -> bool {
        self.expires_at.signed_duration_since(Utc::now()).num_seconds() < 0
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum Stage {
    /// Unauthorized state.
    #[default]
    Unauthorized,

    /// Holds a Credential Offer awaiting retrieval by the Wallet. The Wallet
    /// has been sent a unique URL it can use to retrieve the offer.
    Pending(CredentialOffer),

    /// Holds pre-authorized offer data as presented to the Wallet. This data is
    /// used when validating the Wallet's request for an access token.
    Offered(Offer),

    /// Holds a Pushed Authorization Request awaiting retrieval by the Wallet.
    PushedAuthorization(PushedAuthorization),

    /// Holds authorization data in cases where the Wallet requests and is
    /// granted authorization to request credential issuance. As with
    /// `PreAuthorized` state, this data is used when validating the
    /// Wallet's request for an access token.
    Authorized(Authorization),

    /// Holds information about the access token and corresponding credentials
    /// the Wallet is authorized to request.
    Validated(Token),

    /// Issued Credential state.
    Issued(Credential),

    /// Deferred issuance state.
    Deferred(Deferrance),
}

/// Pre-authorization state from the `create_offer` endpoint.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Offer {
    /// A list of `authorization_details` entries referencing credentials the
    /// Wallet is authorized to request.
    pub items: Option<Vec<AuthorizedItem>>,

    /// Transaction code sent to the holder to use (if present)when requesting
    /// an access token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<String>,
}

/// Holds data used during the issuance of a credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Authorized {
    /// Identifies the dataset associated with the credential to be issued.
    /// Dataset is unique by issuer not by subject.
    ///
    /// For example, the `credential_configuration_id` is `UniversityDegree_JWT`
    /// and the `credential_identifier` is `EngineeringDegree2023`.
    pub credential_identifier: String,

    /// Credential's `credential_configuration_id` connecting it with supported
    /// credential metadata.
    pub credential_configuration_id: String,

    /// Identifies a subset of claims to use when issuing the associated
    /// credential. This subset is used in cases where the Wallet has
    /// requested (and has been authorized for) issuance of a credential
    /// containing subset of claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_ids: Option<Vec<String>>,
}

/// Authorization state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
pub struct Authorization {
    /// The `client_id` of the Wallet requesting issuance.
    pub client_id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    /// PKCE code challenge from the Authorization Request.
    pub code_challenge: String,

    /// PKCE code challenge method from the Authorization Request.
    pub code_challenge_method: CodeChallengeMethod,

    /// A list of authorized `scope` or `authorization_details` entries along
    /// with credential metadata and dataset identifiers.
    pub items: Vec<AuthorizedItem>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PushedAuthorization {
    /// The Authorization Request pushed to the PAR endpoint.
    pub request: RequestObject,

    /// The time the request URI should expire at.
    pub expires_at: DateTime<Utc>,
}

/// Authorized `authorization_detail` or `scope` item along with
/// `credential_configuration_id` and `credential_identifier`s.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuthorizedItem {
    /// Authorized item.
    #[serde(flatten)]
    pub item: ItemType,

    /// Credential configuration metadata for the item.
    pub credential_configuration_id: String,

    /// Authorized credential datasets for the item.
    pub credential_identifiers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum ItemType {
    /// Authorized item is of type `authorization_detail`
    AuthorizationDetail(AuthorizationDetail),

    /// Authorized item is of type `scope`
    Scope(String),
}

impl Default for ItemType {
    fn default() -> Self {
        Self::AuthorizationDetail(AuthorizationDetail::default())
    }
}

/// Token state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Token {
    /// The access token.
    #[allow(clippy::struct_field_names)]
    pub access_token: String,

    /// The nonce to be used by the Wallet when creating a proof of possession
    /// of the key proof.
    pub c_nonce: String,

    /// Number denoting the lifetime in seconds of the `c_nonce`.
    pub c_nonce_expires_at: DateTime<Utc>,

    /// Credentials (configuration id and identifier) validated for issuance
    /// using the accompanying access token.
    pub credentials: HashMap<CredentialIdentifier, Authorized>,
}

impl Token {
    pub fn c_nonce_expires_in(&self) -> i64 {
        self.c_nonce_expires_at.signed_duration_since(Utc::now()).num_seconds()
    }

    pub fn c_nonce_expired(&self) -> bool {
        self.c_nonce_expires_in() < 0
    }
}

/// Issued Credential state (for Notification endpoint).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Credential {
    pub credential: VerifiableCredential,
}

/// Deferred issuance state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Deferrance {
    /// Used to identify a Deferred Issuance transaction. Is used as the
    /// state persistence key.
    pub transaction_id: String,

    /// Save the Credential request when issuance is deferred.
    pub credential_request: CredentialRequest,
}

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
