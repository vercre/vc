use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
// use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use signature::{Keypair, Signer, Verifier};

use super::{Algorithm, Keyring};

pub struct KeyStore {
    keypairs: Arc<Mutex<HashMap<String, MyKeypair>>>,
}

#[derive(Clone)]
pub struct MyKeypair {
    signing_key: ed25519_dalek::SigningKey,
}

impl Keypair for MyKeypair {
    type VerifyingKey = ed25519_dalek::VerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl Keyring for KeyStore {
    fn generate(&self, name: &str, alg: &Algorithm) -> anyhow::Result<impl Keypair> {
        let keypair = MyKeypair {
            signing_key: ed25519_dalek::SigningKey::generate(&mut OsRng),
        };

        let mut lock = self.keypairs.lock().map_err(|e| anyhow!("could not lock Keyring: {e}"))?;
        lock.insert(name.to_string(), keypair.clone());

        Ok(keypair)
    }

    fn keypair(&self, name: &str) -> anyhow::Result<impl Keypair> {
        let lock = self.keypairs.lock().map_err(|e| anyhow!("could not lock Keyring: {e}"))?;
        let Some(kp) = lock.get(name) else {
            return Err(anyhow!("key not found"));
        };

        return Ok(kp.clone());
    }

    fn sign(&self, name: &str, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        // let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);

        let lock = self.keypairs.lock().map_err(|e| anyhow!("could not lock Keyring: {e}"))?;
        let Some(kp) = lock.get(name) else {
            return Err(anyhow!("key not found"));
        };

        let signature: ed25519_dalek::Signature = kp.signing_key.try_sign(data)?;
        Ok(signature.to_vec())
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
        let keyring = KeyStore {
            keypairs: Arc::new(Mutex::new(HashMap::new())),
        };

        let keypair = keyring.generate("test", &Algorithm::Ed25519).unwrap();
        let keypair2 = keyring.keypair("test").unwrap();

        // assert_eq!(keypair.verifying_key(), keypair2.verifying_key());
    }
}
