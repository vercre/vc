#![allow(missing_docs)]
#![allow(dead_code)]
#![allow(clippy::missing_errors_doc)]

//! # Cryptographic Support
//!
//! This module provides cryptographic support.

// use signature::Keypair;

/// A `Keyring` contains a set of related keys
pub trait Keyring: Signer + Encryptor {}

pub trait Signer {
    type VerifyingKey;

    fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>>;

    fn verifying_key(&self) -> anyhow::Result<Self::VerifyingKey>;
}

pub trait Verifier {
    type VerifyingKey;

    fn verify(
        &self, data: &[u8], signature: &[u8], verifying_key: &Self::VerifyingKey,
    ) -> anyhow::Result<()>;
}

pub trait Encryptor {
    type PublicKey;

    fn encrypt(
        &self, msg: &[u8], nonce: &[u8; 24], public_key: &Self::PublicKey,
    ) -> anyhow::Result<Vec<u8>>;

    fn public_key(&self) -> Self::PublicKey;
}

pub trait Decryptor {
    type PublicKey;

    fn decrypt(&self, encrypted: &[u8], nonce: &[u8; 24]) -> anyhow::Result<Vec<u8>>;
}

#[cfg(test)]
mod test {
    use anyhow::anyhow;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use rand::rngs::OsRng;
    use signature::{Signer as _, Verifier as _}; // Keypair,
    use x25519_dalek::StaticSecret;

    use super::{Decryptor, Encryptor, Keyring, Signer, Verifier};

    pub struct Curve25519 {
        // keys: Arc<Mutex<HashMap<String, SigningKey>>>,
        signing_key: SigningKey,
        encryption_key: StaticSecret,
    }

    impl Curve25519 {
        fn new() -> Self {
            Self {
                signing_key: SigningKey::generate(&mut OsRng),
                encryption_key: StaticSecret::random_from_rng(&mut OsRng),
            }
        }

        fn from_bytes(
            signing_key_bytes: [u8; 32], encryption_key_bytes: [u8; 32],
        ) -> anyhow::Result<Self> {
            let signing_key = SigningKey::from(signing_key_bytes);
            let encryption_key = StaticSecret::from(encryption_key_bytes);
            Ok(Self {
                signing_key,
                encryption_key,
            })
        }
    }

    impl Keyring for Curve25519 {}

    impl Signer for Curve25519 {
        type VerifyingKey = VerifyingKey;

        fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
            let signature: ed25519_dalek::Signature = self.signing_key.try_sign(data)?;
            Ok(signature.to_vec())
        }

        fn verifying_key(&self) -> anyhow::Result<Self::VerifyingKey> {
            Ok(self.signing_key.verifying_key())
        }
    }

    impl Verifier for Curve25519 {
        type VerifyingKey = VerifyingKey;

        fn verify(
            &self, data: &[u8], signature: &[u8], verifying_key: &Self::VerifyingKey,
        ) -> anyhow::Result<()> {
            let sig_bytes: &[u8; 64] = signature.try_into()?;
            let sig = ed25519_dalek::Signature::from_bytes(sig_bytes);
            verifying_key.verify(data, &sig).map_err(|_| anyhow!("signature verification failed"))
        }
    }

    impl Encryptor for Curve25519 {
        type PublicKey = x25519_dalek::PublicKey;

        fn encrypt(
            &self, msg: &[u8], nonce: &[u8; 24], public_key: &Self::PublicKey,
        ) -> anyhow::Result<Vec<u8>> {
            todo!()
        }

        fn public_key(&self) -> Self::PublicKey {
            todo!()
        }
    }

    impl Decryptor for Curve25519 {
        type PublicKey = x25519_dalek::PublicKey;

        fn decrypt(&self, _ciphertext: &[u8], _nonce: &[u8; 24]) -> anyhow::Result<Vec<u8>> {
            // let secret_key = EphemeralSecret::random_from_rng(&mut OsRng);
            // let shared_secret = secret_key.diffie_hellman(&public_key);
            todo!()
        }
    }

    #[test]
    fn keyring() {
        let keyring = Curve25519::new();

        let verifying_key = keyring.verifying_key().unwrap();

        // sign and verify
        let sig = keyring.sign(b"test data").expect("should sign");
        let sig_bytes: [u8; 64] = sig.try_into().expect("should convert");
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        verifying_key.verify(b"test data", &sig).expect("should verify");
    }
}
