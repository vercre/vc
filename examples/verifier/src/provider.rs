use chrono::{DateTime, Utc};
use test_utils::store::proof::Keystore;
use test_utils::store::{presentation, state};
use vercre_verifier::provider::{
    Algorithm, PublicKeyJwk, Result, SignatureVerifier, Signer, StateManager, Verifier,
    VerifierMetadata, Wallet, WalletMetadata,
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

impl Signer for Provider {
    fn algorithm(&self) -> Algorithm {
        Keystore::algorithm()
    }

    fn verification_method(&self) -> String {
        Keystore::verification_method()
    }

    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Keystore::try_sign(msg)
    }
}

impl SignatureVerifier for Provider {
    async fn deref_jwk(&self, did_url: &str) -> Result<PublicKeyJwk> {
        Keystore::deref_jwk(did_url).await
    }
}
