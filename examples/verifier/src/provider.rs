use chrono::{DateTime, Utc};
use test_utils::store::keystore::{self, VerifierKeystore};
use test_utils::store::{presentation, state};
use vercre_verifier::provider::{
    Algorithm, Decryptor, Encryptor, PublicKeyJwk, Result, Security, SignatureVerifier, Signer,
    StateManager, Verifier, VerifierMetadata, Wallet, WalletMetadata,
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

impl Security for Provider {
    fn signer(&self, _identifier: &str) -> impl Signer {
        self.clone()
    }

    fn verifier(&self, _identifier: &str) -> impl SignatureVerifier {
        self.clone()
    }

    fn encryptor(&self, _identifier: &str) -> impl Encryptor {
        self.clone()
    }

    fn decryptor(&self, _identifier: &str) -> impl Decryptor {
        self.clone()
    }
}

impl Signer for Provider {
    fn algorithm(&self) -> Algorithm {
        VerifierKeystore::algorithm()
    }

    fn verification_method(&self) -> String {
        VerifierKeystore::verification_method()
    }

    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        VerifierKeystore::try_sign(msg)
    }
}

impl SignatureVerifier for Provider {
    async fn deref_jwk(&self, did_url: &str) -> Result<PublicKeyJwk> {
        keystore::deref_jwk(did_url).await
    }
}

impl Encryptor for Provider {
    async fn encrypt(&self, _plaintext: &[u8], _recipient_public_key: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }

    fn public_key(&self) -> Vec<u8> {
        todo!()
    }
}

impl Decryptor for Provider {
    async fn decrypt(&self, _ciphertext: &[u8], _sender_public_key: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }
}
