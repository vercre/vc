//! State is used by the library to persist request information between steps
//! in the issuance process.

use chrono::{DateTime, TimeDelta, Utc};
use derive_builder::Builder;
use openid4vc::error::Err;
use openid4vc::presentation::RequestObject;
use openid4vc::Result;
use serde::{Deserialize, Serialize};

pub enum Expire {
    Request,
    // Nonce,
}

impl Expire {
    pub fn duration(&self) -> TimeDelta {
        match self {
            Self::Request => TimeDelta::try_minutes(5).unwrap_or_default(),
        }
    }
}

#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize)]
pub struct State {
    /// The time this state item should expire.
    #[builder(default = "Utc::now() + Expire::Request.duration()")]
    pub expires_at: DateTime<Utc>,

    /// The Verifier's Request Object. Saved for use by the `request_uri` endpoint
    /// and in comparing the Presentation Definition to the Presentation Submission.
    pub request_object: RequestObject,

    // The callback ID for the current request.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub callback_id: Option<String>,
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

    pub fn from_slice(value: &[u8]) -> Result<Self> {
        match serde_json::from_slice::<Self>(value) {
            Ok(res) => {
                if res.expired() {
                    return Err(Err::InvalidRequest("state has expired".into()));
                }
                Ok(res)
            }
            Err(e) => Err(Err::ServerError(format!("Failed to deserialize state: {e}"))),
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
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for State {
    type Error = openid4vc::error::Err;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        Self::try_from(value.as_slice())
    }
}
