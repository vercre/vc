use chrono::{DateTime, Utc};
use vercre_datasec::{
    self, Algorithm, DataSec, Decryptor, DidResolver, Document, Encryptor, Signer,
};
use vercre_openid::verifier::{
    Result, StateManager, Verifier, VerifierMetadata, Wallet, WalletMetadata,
};

use crate::store::keystore::VerifierKeystore;
use crate::store::{presentation, state};

pub const VERIFIER_ID: &str = "http://vercre.io";

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

impl vercre_openid::verifier::Provider for Provider {}

impl VerifierMetadata for Provider {
    async fn metadata(&self, verifier_id: &str) -> Result<Verifier> {
        self.verifier.get(verifier_id)
    }

    async fn register(&self, verifier: &Verifier) -> Result<Verifier> {
        self.verifier.add(verifier)
    }
}

impl WalletMetadata for Provider {
    async fn metadata(&self, _wallet_id: &str) -> Result<Wallet> {
        unimplemented!("WalletMetadata")
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

struct VerifierSec(VerifierKeystore);

impl DataSec for Provider {
    fn signer(&self, _identifier: &str) -> anyhow::Result<impl Signer> {
        Ok(VerifierSec(VerifierKeystore {}))
    }

    fn resolver(&self, _identifier: &str) -> anyhow::Result<impl DidResolver> {
        Ok(VerifierSec(VerifierKeystore {}))
    }

    fn encryptor(&self, _identifier: &str) -> anyhow::Result<impl Encryptor> {
        Ok(VerifierSec(VerifierKeystore {}))
    }

    fn decryptor(&self, _identifier: &str) -> anyhow::Result<impl Decryptor> {
        Ok(VerifierSec(VerifierKeystore {}))
    }
}

impl Signer for VerifierSec {
    fn algorithm(&self) -> Algorithm {
        self.0.algorithm()
    }

    fn verification_method(&self) -> String {
        self.0.verification_method()
    }

    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.0.try_sign(msg)
    }
}

impl DidResolver for VerifierSec {
    async fn resolve(&self, did_url: &str) -> Result<Document> {
        crate::store::keystore::get_did(did_url).await
    }
}

impl Encryptor for VerifierSec {
    async fn encrypt(&self, _plaintext: &[u8], _recipient_public_key: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }

    fn public_key(&self) -> Vec<u8> {
        todo!()
    }
}

impl Decryptor for VerifierSec {
    async fn decrypt(&self, _ciphertext: &[u8], _sender_public_key: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }
}
