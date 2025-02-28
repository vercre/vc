pub mod keystore;
pub mod resolver;
pub mod state;
pub mod store;

use chrono::{DateTime, Utc};
use credibil_did::{DidResolver, Document};
use credibil_infosec::{Algorithm, Signer};
use credibil_vc::openid::issuer::{Client, Dataset, Issuer, Metadata, Provider, Server, Subject};
use credibil_vc::openid::provider::{Result, StateStore};
use credibil_vc::status::issuer::Status;
pub use keystore::Keystore;
use serde::Serialize;
use serde::de::DeserializeOwned;

pub const CREDENTIAL_ISSUER: &str = "http://credibil.io";
pub const CLIENT_ID: &str = "96bfb9cb-0513-7d64-5532-bed74c48f9ab";
pub const NORMAL_USER: &str = "normal_user";
pub const PENDING_USER: &str = "pending_user";
pub const REDIRECT_URI: &str = "http://localhost:3000/callback";

#[derive(Default, Clone, Debug)]
pub struct ProviderImpl {
    pub client: store::ClientStore,
    pub issuer: store::IssuerStore,
    pub server: store::ServerStore,
    pub subject: store::DatasetStore,
    pub state: state::Store,
}

impl ProviderImpl {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: store::ClientStore::new(),
            issuer: store::IssuerStore::new(),
            server: store::ServerStore::new(),
            subject: store::DatasetStore::new(),
            state: state::Store::new(),
        }
    }
}

impl Provider for ProviderImpl {}

impl Metadata for ProviderImpl {
    async fn client(&self, client_id: &str) -> Result<Client> {
        self.client.get(client_id)
    }

    async fn register(&self, client: &Client) -> Result<Client> {
        self.client.add(client)
    }

    async fn issuer(&self, issuer_id: &str) -> Result<Issuer> {
        self.issuer.get(issuer_id)
    }

    async fn server(&self, server_id: &str, _issuer_id: Option<&str>) -> Result<Server> {
        self.server.get(server_id)
    }
}

impl Subject for ProviderImpl {
    /// Authorize issuance of the specified credential for the holder.
    async fn authorize(
        &self, subject_id: &str, credential_configuration_id: &str,
    ) -> Result<Vec<String>> {
        self.subject.authorize(subject_id, credential_configuration_id)
    }

    async fn dataset(&self, subject_id: &str, credential_identifier: &str) -> Result<Dataset> {
        self.subject.dataset(subject_id, credential_identifier)
    }
}

impl StateStore for ProviderImpl {
    async fn put(&self, key: &str, state: impl Serialize, dt: DateTime<Utc>) -> Result<()> {
        self.state.put(key, state, dt)
    }

    async fn get<T: DeserializeOwned>(&self, key: &str) -> Result<T> {
        self.state.get(key)
    }

    async fn purge(&self, key: &str) -> Result<()> {
        self.state.purge(key)
    }
}

impl DidResolver for ProviderImpl {
    async fn resolve(&self, url: &str) -> anyhow::Result<Document> {
        resolver::resolve_did(url).await
    }
}

impl Signer for ProviderImpl {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Keystore::try_sign(msg)
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        Keystore::public_key()
    }

    fn algorithm(&self) -> Algorithm {
        Keystore::algorithm()
    }

    async fn verification_method(&self) -> Result<String> {
        Ok(Keystore::verification_method())
    }
}

impl Status for ProviderImpl {}
