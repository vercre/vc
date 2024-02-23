//! State is used by the library to persist request information between steps
//! in the issuance process.
use chrono::{DateTime, Duration, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use vercre_core::error::Err;
use vercre_core::vp::RequestObject;
use vercre_core::{err, Result};

pub(crate) enum Expire {
    Request,
    // Nonce,
}

impl Expire {
    pub(crate) fn duration(&self) -> Duration {
        match self {
            Expire::Request => Duration::minutes(5),
        }
    }
}

#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct State {
    /// The time this state item should expire.
    #[builder(default = "Utc::now() + Expire::Request.duration()")]
    pub(crate) expires_at: DateTime<Utc>,

    /// The Verifier's Request Object. Saved for use by the 'request_uri' endpoint
    /// and in comparing the Presentation Definition to the Presentation Submission.
    pub(crate) request_object: RequestObject,

    // The callback ID for the current request.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub(crate) callback_id: Option<String>,
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

    pub(crate) fn from_slice(value: &[u8]) -> Result<Self> {
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

    /// Determines whether state has expired or not.
    pub(crate) fn expired(&self) -> bool {
        self.expires_at.signed_duration_since(Utc::now()).num_seconds() < 0
    }
}

impl TryFrom<&[u8]> for State {
    type Error = vercre_core::error::Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        State::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for State {
    type Error = vercre_core::error::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        State::try_from(value.as_slice())
    }
}

// /// [`StateBuilder`] is used to build a [State]
// #[derive(Clone, Default)]
// #[allow(clippy::module_name_repetitions)]
// pub struct StateBuilder {
//     pub(crate) state: State,
// }

// /// [`StateBuilder`] is used to build a [`State`] item.
// #[allow(dead_code)]
// impl StateBuilder {
//     /// Returns a new [`StateBuilder`]
//     #[must_use]
//     pub(crate) fn new() -> Self {
//         Self {
//             state: State {
//                 expires_at: Utc::now() + Expire::Request.duration(),
//                 ..Default::default()
//             },
//         }
//     }

//     /// Sets the `expires_at` property
//     #[must_use]
//     pub(crate) fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
//         self.state.expires_at = expires_at;
//         self
//     }

//     /// Sets the `request_object` property
//     #[must_use]
//     pub(crate) fn request_object(mut self, obj: &RequestObject) -> Self {
//         self.state.request_object = obj.clone();
//         self
//     }

//     /// Turns this builder into a [`State`]
//     pub(crate) fn build(self) -> State {
//         self.state
//     }
// }
