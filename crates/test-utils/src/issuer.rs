#![allow(missing_docs)]

use std::collections::HashMap;
use std::ops::Deref;

use chrono::{DateTime, Utc};
use openid4vc::issuance::{ClaimDefinition, Issuer};
use openid4vc::{Client, Server};
use endpoint::{
    Algorithm, Callback, Claims, ClientMetadata, IssuerMetadata, Jwk, Payload, Result,
    ServerMetadata, Signer, StateManager, Subject, Verifier,
};

use crate::proof::Enclave;
pub use crate::providers::{Issuance, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER, PENDING_USER};

#[derive(Clone, Debug)]
pub struct Provider(Issuance);
impl Provider {
    #[must_use]
    pub fn new() -> Self {
        Self(Issuance::new())
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for Provider {
    type Target = Issuance;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ClientMetadata for Provider {
    async fn metadata(&self, client_id: &str) -> Result<Client> {
        self.client.get(client_id)
    }

    async fn register(&self, client: &Client) -> Result<Client> {
        self.client.add(client)
    }
}

impl IssuerMetadata for Provider {
    async fn metadata(&self, issuer_id: &str) -> Result<Issuer> {
        self.issuer.get(issuer_id)
    }
}

impl ServerMetadata for Provider {
    async fn metadata(&self, server_id: &str) -> Result<Server> {
        self.server.get(server_id)
    }
}

impl Subject for Provider {
    /// Authorize issuance of the specified credential for the holder.
    async fn authorize(&self, holder_subject: &str, credential_identifier: &str) -> Result<bool> {
        self.subject.authorize(holder_subject, credential_identifier)
    }

    async fn claims(
        &self, holder_subject: &str, credential_identifier: &str,
        credential_subject: Option<HashMap<String, ClaimDefinition>>,
    ) -> Result<Claims> {
        self.subject.claims(holder_subject, credential_identifier, credential_subject)
    }
}

impl StateManager for Provider {
    async fn put(&self, key: &str, state: Vec<u8>, dt: DateTime<Utc>) -> Result<()> {
        self.state.put(key, state, dt)
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        self.state.get(key)
    }

    async fn purge(&self, key: &str) -> Result<()> {
        self.state.purge(key)
    }
}

impl Signer for Provider {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256K
    }

    fn verification_method(&self) -> String {
        //format!("{ISSUER_DID}#{VERIFY_KEY_ID}")
        Enclave::verification_method()
    }

    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Enclave::try_sign(msg)
    }
}

impl Verifier for Provider {
    async fn deref_jwk(&self, did_url: &str) -> Result<Jwk> {
        Enclave::deref_jwk(did_url)
    }
}

impl Callback for Provider {
    async fn callback(&self, pl: &Payload) -> Result<()> {
        self.callback.callback(pl)
    }
}
