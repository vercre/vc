#![allow(missing_docs)]

// use std::sync::LazyLock;

use anyhow::anyhow;
use ed25519_dalek::{SigningKey, VerifyingKey};
use proof::{Decryptor, Encryptor, Keyring, Signer, Verifier};
use rand::rngs::OsRng;
use signature::{Signer as _, Verifier as _};

// static KEYPAIR: LazyLock<KeyPair> = LazyLock::new(|| KeyPair::gen());

fn main() {
    // let keyring = Curve25519::new();

    // let verifying_key = keyring.verifying_key().unwrap();

    // // sign and verify
    // let sig = keyring.sign(b"test data").expect("should sign");
    // let sig_bytes: [u8; 64] = sig.try_into().expect("should convert");
    // let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    // verifying_key.verify(b"test data", &sig).expect("should verify");

    // // encrypt and decrypt
    // let public_key = KEYPAIR.public_key.as_array();
    // let recipient_key = x25519_dalek::PublicKey::from(*public_key);

    // let ciphertext = keyring.encrypt(b"test data", &recipient_key).expect("should encrypt");
    // let plaintext = keyring.decrypt(&ciphertext).expect("should decrypt");

    // assert_eq!(b"test data", plaintext.as_slice());
}

pub struct Curve25519 {
    signing_key: SigningKey,
}

impl Curve25519 {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    #[allow(dead_code)]
    fn from_bytes(signing_key_bytes: [u8; 32]) -> anyhow::Result<Self> {
        let signing_key = SigningKey::from(signing_key_bytes);

        Ok(Self { signing_key })
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

    fn encrypt(&self, _plaintext: &[u8], _recipient_public_key: &[u8]) -> anyhow::Result<Vec<u8>> {
        todo!()
    }

    fn public_key(&self) -> Vec<u8> {
        // x25519_dalek::PublicKey::from(&self.secret_key)
        todo!()
    }
}

impl Decryptor for Curve25519 {
    type PublicKey = x25519_dalek::PublicKey;

    fn decrypt(&self, _ciphertext: &[u8], _sender_public_key: &[u8]) -> anyhow::Result<Vec<u8>> {
        todo!()
    }
}
