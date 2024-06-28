pub mod callback;
pub mod client;
pub mod issuer;
pub mod proof;
pub mod server;
pub mod state;
pub mod subject;

pub const NORMAL_USER: &str = "normal_user";
pub const PENDING_USER: &str = "pending_user";
pub const CREDENTIAL_ISSUER: &str = "http://vercre.io";
pub const VERIFY_KEY_ID: &str = "publicKeyModel1Id";
pub const CLIENT_ID: &str = "96bfb9cb-0513-7d64-5532-bed74c48f9ab";
pub const VERIFIER_ID: &str = "http://vercre.io";

#[derive(Default, Clone, Debug)]
pub struct Issuance {
    pub client: client::Store,
    pub issuer: issuer::Store,
    pub server: server::Store,
    pub subject: subject::Store,
    pub state: state::Store,
    pub callback: callback::Hook,
}

impl Issuance {
    #[must_use]
    pub fn new() -> Self {
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

#[derive(Default, Clone, Debug)]
pub struct Presentation {
    pub client: client::Store,
    pub state: state::Store,
    pub callback: callback::Hook,
}

impl Presentation {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: client::Store::new(),
            state: state::Store::new(),
            callback: callback::Hook::new(),
        }
    }
}