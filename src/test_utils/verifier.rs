use chrono::{DateTime, Utc};
use credibil_did::{DidResolver, Document};
use credibil_infosec::{self, Algorithm, PublicKey, Receiver, SharedSecret, Signer};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::store::keystore::VerifierKeystore;
use super::store::{presentation, resolver, state};
use crate::openid::provider::{Result, StateStore};
use crate::openid::verifier::{Metadata, Verifier, Wallet};

pub const VERIFIER_ID: &str = "http://localhost:8080";

#[derive(Default, Clone, Debug)]
pub struct Provider {
    pub verifier: presentation::Store,
    pub state: state::Store,
}

impl Provider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            verifier: presentation::Store::new(),
            state: state::Store::new(),
        }
    }
}

impl crate::openid::verifier::Provider for Provider {}

impl Metadata for Provider {
    async fn verifier(&self, verifier_id: &str) -> Result<Verifier> {
        self.verifier.get(verifier_id)
    }

    async fn register(&self, verifier: &Verifier) -> Result<Verifier> {
        self.verifier.add(verifier)
    }

    async fn wallet(&self, _wallet_id: &str) -> Result<Wallet> {
        unimplemented!("WalletMetadata")
    }
}

impl StateStore for Provider {
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

impl DidResolver for Provider {
    async fn resolve(&self, url: &str) -> anyhow::Result<Document> {
        resolver::resolve_did(url).await
    }
}

impl Signer for Provider {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        VerifierKeystore::try_sign(msg)
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        VerifierKeystore::public_key()
    }

    fn algorithm(&self) -> Algorithm {
        VerifierKeystore::algorithm()
    }

    async fn verification_method(&self) -> Result<String> {
        Ok(VerifierKeystore::verification_method())
    }
}

impl Receiver for Provider {
    fn key_id(&self) -> String {
        todo!()
    }

    async fn shared_secret(&self, _sender_public: PublicKey) -> Result<SharedSecret> {
        todo!()
    }
}
