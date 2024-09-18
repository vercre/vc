//! State is used by the library to persist request information between steps
//! in the issuance process.

use std::collections::HashMap;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use vercre_openid::issuer::{AuthorizationDetail, CredentialOffer, CredentialRequest};

type CredentialIdentifier = String;

/// State is used to persist request information between issuance steps in the Credential
/// issuance process.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct State {
    /// Identifies the (previously authenticated) Holder in order that Issuer can
    /// authorize credential issuance.
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

    /// Holds a Credential Offer awaiting retrieval by the Wallet. The Wallet has
    /// been sent a unique URL it can use to retrieve the offer.
    Offered(Offer),

    /// Holds pre-authorized offer data as presented to the Wallet. This data is
    /// used when validating the Wallet's request for an access token.
    PreAuthorized(PreAuthorization),

    /// Holds authorization data in cases where the Wallet requests and is granted
    /// authorization to request credential issuance. As with `PreAuthorized` state,
    /// this data is used when validating the Wallet's request for an access token.
    Authorized(Authorization),

    /// Holds information about the access token and corresponding credentials
    /// the Wallet is authorized to request.
    Validated(Token),

    /// Issued Credential state.
    Issued(),

    /// Deferred issuance state.
    Deferred(Deferrance),
}

/// Holds data used during the issuance of a credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuthorizedCredential {
    /// Identifies the dataset associated with the credential to be issued.
    /// Dataset is unique by issuer not by subject.
    ///
    /// For example, the `credential_configuration_id` is `UniversityDegree_JWT`
    /// and the `credential_identifier` is `EngineeringDegree2023`.
    pub credential_identifier: String,

    /// Credential's `credential_configuration_id` connecting it with supported
    /// credential metadata.
    pub credential_configuration_id: String,

    /// Identifies a subset of claims to use when issuing the associated credential.
    /// This subset is used in cases where the Wallet has requested (and has been
    /// authorized for) issuance of a credential containing subset of claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_ids: Option<Vec<String>>,
}

/// Pre-authorization state from the `create_offer` endpoint.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
pub struct Offer {
    /// Credential Offer, ready for the client to retrieve.
    pub credential_offer: CredentialOffer,

    /// Credentials (configuration id and identifier) authorized for issuance.
    pub credentials: HashMap<CredentialIdentifier, AuthorizedCredential>,

    /// Transaction code for pre-authorized offers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<String>,
}

/// Pre-authorization state from the `create_offer` endpoint.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PreAuthorization {
    /// Authorized credentials (configuration id and identifier).
    pub credentials: HashMap<CredentialIdentifier, AuthorizedCredential>,

    /// Transaction code sent to the holder to use (if present)when requesting
    /// an access token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<String>,
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
    pub code_challenge_method: String,

    /// Lists credentials (as `authorization_details` entries) that the Wallet is
    /// authorized to request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<DetailItem>>,

    /// Lists credentials (as scope items) that the Wallet is authorized to request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Vec<ScopeItem>>,
}

/// Stores authorized `authorization_detail` item and attendant
/// `credential_configuration_id`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DetailItem {
    /// Authorized `authorization_detail`
    pub authorization_detail: AuthorizationDetail,

    /// Corresponding `credential_configuration_id` for the detail item.
    pub credential_configuration_id: String,

    /// Authorized credential datasets for the scope item.
    pub credential_identifiers: Vec<String>,
}

/// Stores authorized scope items with attendant `credential_configuration_id`
/// and `credential_identifier`s.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScopeItem {
    /// Authorized scope
    pub item: String,

    /// Authorized `credential_configuration_id` for the scope item.
    pub credential_configuration_id: String,

    /// Authorized credential datasets for the scope item.
    pub credential_identifiers: Vec<String>,
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

    /// Credentials (configuration id and identifier) validated for issuance using
    /// the accompanying access token.
    pub credentials: HashMap<CredentialIdentifier, AuthorizedCredential>,
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
