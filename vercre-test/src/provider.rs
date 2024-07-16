use std::ops::Deref;

use chrono::{DateTime, Utc};
use openid::endpoint::{
    self, Callback, Claims, ClientMetadata, IssuerMetadata, Payload, ServerMetadata, StateManager,
    Subject,
};
use openid::issuance::Issuer;
use openid::{Client, Server};
use proof::jose::jwk::PublicKeyJwk;
use proof::signature::{Algorithm, Signer, Verifier};
use test_utils::proof::Enclave;
use test_utils::providers::Issuance;

use crate::IssuerProvider;

#[derive(Clone, Debug)]
pub struct TestProvider(Issuance);
impl TestProvider {
    #[must_use]
    pub fn new() -> Self {
        Self(Issuance::new())
    }
}

impl IssuerProvider for TestProvider {}

impl Default for TestProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for TestProvider {
    type Target = Issuance;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ClientMetadata for TestProvider {
    async fn metadata(&self, client_id: &str) -> endpoint::Result<Client> {
        self.client.get(client_id)
    }

    async fn register(&self, client: &Client) -> endpoint::Result<Client> {
        self.client.add(client)
    }
}

impl IssuerMetadata for TestProvider {
    async fn metadata(&self, issuer_id: &str) -> endpoint::Result<Issuer> {
        self.issuer.get(issuer_id)
    }
}

impl ServerMetadata for TestProvider {
    async fn metadata(&self, server_id: &str) -> endpoint::Result<Server> {
        self.server.get(server_id)
    }
}

impl Subject for TestProvider {
    /// Authorize issuance of the specified credential for the holder.
    async fn authorize(
        &self, holder_subject: &str, credential_identifier: &str,
    ) -> endpoint::Result<bool> {
        self.subject.authorize(holder_subject, credential_identifier)
    }

    async fn claims(
        &self, holder_subject: &str, credential_identifier: &str,
    ) -> endpoint::Result<Claims> {
        self.subject.claims(holder_subject, credential_identifier)
    }
}

impl StateManager for TestProvider {
    async fn put(&self, key: &str, state: Vec<u8>, dt: DateTime<Utc>) -> endpoint::Result<()> {
        self.state.put(key, state, dt)
    }

    async fn get(&self, key: &str) -> endpoint::Result<Vec<u8>> {
        self.state.get(key)
    }

    async fn purge(&self, key: &str) -> endpoint::Result<()> {
        self.state.purge(key)
    }
}

impl Signer for TestProvider {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256K
    }

    fn verification_method(&self) -> String {
        //format!("{ISSUER_DID}#{VERIFY_KEY_ID}")
        Enclave::verification_method()
    }

    async fn try_sign(&self, msg: &[u8]) -> endpoint::Result<Vec<u8>> {
        Enclave::try_sign(msg)
    }
}

impl Verifier for TestProvider {
    async fn deref_jwk(&self, did_url: &str) -> endpoint::Result<PublicKeyJwk> {
        Enclave::deref_jwk(did_url)
    }
}

impl Callback for TestProvider {
    async fn callback(&self, pl: &Payload) -> endpoint::Result<()> {
        self.callback.callback(pl)
    }
}
