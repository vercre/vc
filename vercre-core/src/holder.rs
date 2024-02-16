//! User defines traits the library requires to be implemented for dynamically
//! provided user information.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The user information returned by the Holder trait.
#[derive(Clone, Deserialize, Serialize)]
pub struct Claims {
    /// The credential subject populated for the user.
    pub claims: HashMap<String, Value>,

    /// Specifies whether user information required for the credential subject
    /// is pending.
    pub pending: bool,
}
