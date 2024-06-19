//! # Presentation
//!
//! The Presentation endpoints implement the vercre-holder's credential presentation flow.

mod authorize;
mod present;
mod request;

use std::fmt::Debug;

use anyhow::anyhow;
pub use openid4vc::presentation::{
    RequestObject, RequestObjectResponse, ResponseRequest, ResponseResponse,
};
use serde::{Deserialize, Serialize};
use vercre_exch::{Constraints, PresentationSubmission};

use crate::credential::Credential;

/// `Presentation` maintains app state across steps of the presentation flow.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Presentation {
    /// The unique identifier for the presentation flow. Not used internally but passed to providers
    /// so that wallet clients can track interactions with specific flows.
    pub id: String,

    /// The current status of the presentation flow.
    pub status: Status,

    /// The request object received from the verifier.
    pub request: RequestObject,

    /// The list of credentials matching the verifier's request (Presentation
    /// Definition).
    pub credentials: Vec<Credential>,

    /// The `JSONPath` query used to match credentials to the verifier's request.
    pub filter: Constraints,

    /// The presentation submission token.
    pub submission: PresentationSubmission,
}

/// Presentation Status values.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename = "PresentationStatus")]
pub enum Status {
    /// No authorization request is being processed.
    #[default]
    Inactive,

    /// A new authorization request has been received.
    Requested,

    /// The authorization request has been authorized.
    Authorized,

    /// The authorization request has failed, with an error message.
    Failed(String),
}

/// Get a string representation of the `Status`.
impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inactive => write!(f, "Inactive"),
            Self::Requested => write!(f, "Requested"),
            Self::Authorized => write!(f, "Authorized"),
            Self::Failed(e) => write!(f, "Failed: {e}"),
        }
    }
}

/// Parse a `Status` from a string.
impl std::str::FromStr for Status {
    // TODO: strongly typed error
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        if s.starts_with("Failed") {
            return Ok(Self::Failed(s[8..].to_string()));
        }
        match s {
            "Inactive" => Ok(Self::Inactive),
            "Requested" => Ok(Self::Requested),
            "Authorized" => Ok(Self::Authorized),
            _ => Err(anyhow!("Invalid status: {s}")),
        }
    }
}
