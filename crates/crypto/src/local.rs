use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use rand::rngs::OsRng;
use signature::Signer;

// use ed25519_dalek::SigningKey;
// use signature::{Keypair, Signer, Verifier};
use super::Keyring;

pub struct Ed25519Keyring {
    keys: Arc<Mutex<HashMap<String, ed25519_dalek::SigningKey>>>,
}

// #[derive(Clone)]
// pub struct MyKeypair {
//     signing_key: ed25519_dalek::SigningKey,
// }

// impl Keypair for MyKeypair {
//     type VerifyingKey = ed25519_dalek::VerifyingKey;

//     fn verifying_key(&self) -> Self::VerifyingKey {
//         self.signing_key.verifying_key()
//     }
// }

impl Keyring for Ed25519Keyring {
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

    // fn verify(&self, name: &str, data: &[u8], signature: &[u8]) -> anyhow::Result<()> {
    //     let lock = self.keypairs.lock().map_err(|e| anyhow!("could not lock Keyring: {e}"))?;
    //     let Some(kp) = lock.get(name) else {
    //         return Err(anyhow!("key not found"));
    //     };

    //     let sig_bytes: &[u8; 64] = signature.try_into()?;
    //     let sig = ed25519_dalek::Signature::from_bytes(sig_bytes);

    //     kp.verifying_key().verify(data, &sig).map_err(|_| anyhow!("signature verification failed"))
    // }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn keyring() {
        let keyring = Ed25519Keyring {
            keys: Arc::new(Mutex::new(HashMap::new())),
        };

        let verifying_key1 = keyring.generate("test").unwrap();
        let verifying_key2 = keyring.verifying_key("test").unwrap();

        assert_eq!(verifying_key1, verifying_key2);
    }
}
