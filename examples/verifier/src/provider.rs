use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::Serialize;
use test_utils::store::keystore::VerifierKeystore;
use test_utils::store::{presentation, resolver, state};
use vercre_verifier::provider::{
    Algorithm, Cipher, DidResolver, Document, KeyOps, Metadata, Result, Signer, StateStore,
    Verifier, Wallet,
};

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

impl vercre_verifier::provider::Provider for Provider {}

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
    async fn put(&self, key: &str, state: impl Serialize + Send, dt: DateTime<Utc>) -> Result<()> {
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

struct VerifierSec(VerifierKeystore);

impl KeyOps for Provider {
    fn signer(&self, _identifier: &str) -> anyhow::Result<impl Signer> {
        Ok(VerifierSec(VerifierKeystore {}))
    }

    fn cipher(&self, _identifier: &str) -> anyhow::Result<impl Cipher> {
        Ok(VerifierSec(VerifierKeystore {}))
    }
}

impl Signer for VerifierSec {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        VerifierKeystore::try_sign(msg)
    }

    async fn public_key(&self) -> Result<Vec<u8>> {
        VerifierKeystore::public_key()
    }

    fn algorithm(&self) -> Algorithm {
        VerifierKeystore::algorithm()
    }

    async fn verification_method(&self) -> Result<String> {
        Ok(VerifierKeystore::verification_method())
    }
}

impl Cipher for VerifierSec {
    async fn encrypt(&self, _plaintext: &[u8], _recipient_public_key: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }

    fn ephemeral_public_key(&self) -> Vec<u8> {
        todo!()
    }

    async fn decrypt(&self, _ciphertext: &[u8], _sender_public_key: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }
}
