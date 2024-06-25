use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use rand::rngs::OsRng;
// use ed25519_dalek::SigningKey;
use signature::{Keypair, Signer, Verifier};

use super::Keyring;

pub struct Ed25519Ring {
    keys: Arc<Mutex<HashMap<String, ed25519_dalek::SigningKey>>>,
}

impl Ed25519Ring {
    fn new() -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Keyring for Ed25519Ring {
    type VerifyingKey = ed25519_dalek::VerifyingKey;

    fn generate(&self, name: &str) -> anyhow::Result<Self::VerifyingKey> {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);

        let mut lock = self.keys.lock().map_err(|e| anyhow!("could not lock Keyring: {e}"))?;
        lock.insert(name.to_string(), signing_key.clone());

        Ok(signing_key.verifying_key())
    }

    fn sign(&self, name: &str, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let lock = self.keys.lock().map_err(|e| anyhow!("could not lock Keyring: {e}"))?;
        let Some(signing_key) = lock.get(name) else {
            return Err(anyhow!("key not found"));
        };

        let signature: ed25519_dalek::Signature = signing_key.try_sign(data)?;

        Ok(signature.to_vec())
    }

    fn verifying_key(&self, name: &str) -> anyhow::Result<Self::VerifyingKey> {
        let lock = self.keys.lock().map_err(|e| anyhow!("could not lock Keyring: {e}"))?;
        let Some(signing_key) = lock.get(name) else {
            return Err(anyhow!("key not found"));
        };

        return Ok(signing_key.verifying_key());
    }

    fn verify(&self, name: &str, data: &[u8], signature: &[u8]) -> anyhow::Result<()> {
        let sig_bytes: &[u8; 64] = signature.try_into()?;
        let sig = ed25519_dalek::Signature::from_bytes(sig_bytes);

        let verifying_key = self.verifying_key(name)?;
        verifying_key.verify(data, &sig).map_err(|_| anyhow!("signature verification failed"))
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn keyring() {
        let keyring = Ed25519Ring::new();

        // compare verification keys
        let key1 = keyring.generate("key-1").unwrap();
        let key2 = keyring.verifying_key("key-1").unwrap();
        assert_eq!(key1, key2);

        // sign and verify
        let sig = keyring.sign("key-1", b"test data").expect("should sign");
        let sig_bytes: [u8; 64] = sig.try_into().expect("should convert");
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        key1.verify(b"test data", &sig).expect("should verify");
    }
}
