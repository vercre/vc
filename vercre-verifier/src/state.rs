//! State is used by the library to persist request information between steps
//! in the issuance process.

use chrono::{DateTime, TimeDelta, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use vercre_openid::verifier::RequestObject;

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
    pub expires_at: DateTime<Utc>,

    /// The Verifier's Request Object. Saved for use by the `request_uri` endpoint
    /// and in comparing the Presentation Definition to the Presentation Submission.
    pub request_object: RequestObject,
}

impl State {
    /// Determines whether state has expired or not.
    pub fn expired(&self) -> bool {
        self.expires_at.signed_duration_since(Utc::now()).num_seconds() < 0
    }
}
