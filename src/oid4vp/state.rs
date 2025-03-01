//! State is used by the library to persist request information between steps
//! in the issuance process.

use chrono::{DateTime, TimeDelta, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use crate::oid4vp::verifier::RequestObject;

/// The duration for which a state item is valid.
pub enum Expire {
    /// The state item expires after the request is created.
    Request,
}

impl Expire {
    /// Returns the duration for which the state item is valid.
    #[must_use]
    pub fn duration(&self) -> TimeDelta {
        match self {
            Self::Request => TimeDelta::try_minutes(5).unwrap_or_default(),
        }
    }
}

/// State is used by the library to persist request information between steps.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize)]
pub struct State {
    /// The time this state item should expire.
    pub expires_at: DateTime<Utc>,

    /// The Verifier's Request Object. Saved for use by the `request_uri`
    /// endpoint and in comparing the Presentation Definition to the
    /// Presentation Submission.
    pub request_object: RequestObject,
}
