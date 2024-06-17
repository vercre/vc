#![allow(missing_docs)]

pub mod issuance;
mod logic;
pub mod presentation;
pub mod wallet;

use logic::{callback, client, issuer, server, state, subject};

pub const NORMAL_USER: &str = "normal_user";
pub const PENDING_USER: &str = "pending_user";

pub const CREDENTIAL_ISSUER: &str = "http://vercre.io";
pub const VERIFY_KEY_ID: &str = "publicKeyModel1Id";

#[derive(Default, Clone, Debug)]
pub struct Provider {
    client: client::Store,
    issuer: issuer::Store,
    server: server::Store,
    subject: subject::Store,
    state: state::Store,
    callback: callback::Hook,
}

impl Provider {
    #[must_use]
    fn new() -> Self {
        Self {
            client: client::Store::new(),
            issuer: issuer::Store::new(),
            server: server::Store::new(),
            subject: subject::Store::new(),
            state: state::Store::new(),
            callback: callback::Hook::new(),
        }
    }
}
