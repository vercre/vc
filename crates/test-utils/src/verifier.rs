#![allow(missing_docs)]

use std::ops::Deref;

use chrono::{DateTime, Utc};
use openid::verifier::{
    self, Result, StateManager, Verifier, VerifierMetadata, Wallet,
    WalletMetadata,
};
use proof::jose::jwk::PublicKeyJwk;
use proof::signature::{self, Algorithm, Signer};

use crate::proof::Enclave;
pub use crate::providers::{Presentation, VERIFIER_DID, VERIFIER_ID, VERIFY_KEY_ID};

#[derive(Clone, Debug)]
pub struct Provider(Presentation);
impl Provider {
    #[must_use]
    pub fn new() -> Self {
        Self(Presentation::new())
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for Provider {
    type Target = Presentation;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl verifier::Provider for Provider {}

impl VerifierMetadata for Provider {
    async fn metadata(&self, verifier_id: &str) -> Result<Verifier> {
        self.verifier.get(verifier_id)
    }

    async fn register(&self, client: &Verifier) -> Result<Verifier> {
        self.verifier.add(client)
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
        Algorithm::ES256K
    }

    fn verification_method(&self) -> String {
        format!("{VERIFIER_DID}#{VERIFY_KEY_ID}")
        // Enclave::verification_method()
    }

    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        // let decoded = Base64UrlUnpadded::decode_vec(SERVER_JWK_D)?;
        // let signing_key: SigningKey<Secp256k1> = SigningKey::from_slice(&decoded)?;
        // let signature: Signature<Secp256k1> = signing_key.sign(msg);
        // Ok(signature.to_vec())
        Enclave::try_sign(msg)
    }
}

impl signature::Verifier for Provider {
    async fn deref_jwk(&self, did_url: &str) -> Result<PublicKeyJwk> {
        Enclave::deref_jwk(did_url)
    }
}
