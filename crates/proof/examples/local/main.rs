#![allow(missing_docs)]

use std::sync::LazyLock;

use anyhow::anyhow;
use dryoc::dryocbox::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use proof::{Decryptor, Encryptor, Keyring, Signer, Verifier};
use rand::rngs::OsRng;
use signature::{Signer as _, Verifier as _};
use x25519_dalek::StaticSecret;

static KEYPAIR: LazyLock<KeyPair> = LazyLock::new(|| KeyPair::gen());

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

    with_biscuit();
}

fn with_biscuit() {
    use std::str;

    use biscuit::jwa::{ContentEncryptionAlgorithm, EncryptionOptions, KeyManagementAlgorithm};
    use biscuit::jwk::JWK;
    use biscuit::{jwe, Empty};

    let payload = "The true sign of intelligence is not knowledge but imagination.";

    let secret_key = StaticSecret::random_from_rng(&mut OsRng);
    let key: JWK<Empty> = JWK::new_octet_key(secret_key.as_bytes(), Default::default());

    let jwe = jwe::Compact::new_decrypted(
        From::from(jwe::RegisteredHeader {
            cek_algorithm: KeyManagementAlgorithm::ECDH_ES,
            enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
            ..Default::default()
        }),
        payload.as_bytes().to_vec(),
    );

    // we need a nonce for AES GCM encryption
    let nonce = num_bigint::BigUint::from_bytes_le(&vec![0; 96 / 8]);
    let mut nonce_bytes = nonce.to_bytes_le();
    nonce_bytes.resize(96 / 8, 0);
    // nonce = nonce + 1u8;

    // encrypt
    let options = EncryptionOptions::AES_GCM { nonce: nonce_bytes };
    let encrypted_jwe = match jwe.encrypt(&key, &options) {
        Ok(jwe) => jwe,
        Err(e) => panic!("error encrypting: {}", e),
    };

    let serialized = serde_json::to_string(&encrypted_jwe).unwrap();
    println!("serialized: {}", serialized);

    // decrypt
    let decrypted_jwe = encrypted_jwe
        .decrypt(&key, KeyManagementAlgorithm::A256GCMKW, ContentEncryptionAlgorithm::A256GCM)
        .unwrap();

    let decrypted_payload: &Vec<u8> = decrypted_jwe.payload().unwrap();
    let decrypted_str = str::from_utf8(&*decrypted_payload).unwrap();
    assert_eq!(decrypted_str, payload);
}

pub struct Curve25519 {
    signing_key: SigningKey,
    secret_key: StaticSecret,
}

impl Curve25519 {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
            secret_key: StaticSecret::random_from_rng(&mut OsRng),
        }
    }

    #[allow(dead_code)]
    fn from_bytes(signing_key_bytes: [u8; 32], secret_key_bytes: [u8; 32]) -> anyhow::Result<Self> {
        let signing_key = SigningKey::from(signing_key_bytes);
        let secret_key = StaticSecret::from(secret_key_bytes);

        Ok(Self {
            signing_key,
            secret_key,
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

    // fn encrypt(
    //     &self, msg: &[u8], nonce: &[u8; 24], public_key: &Self::PublicKey,
    // ) -> anyhow::Result<Vec<u8>> {
    //     let mut db_nonce = StackByteArray::new();
    //     db_nonce.copy_from_slice(nonce.as_slice());

    //     let mut db_public_key = StackByteArray::new();
    //     db_public_key.copy_from_slice(&public_key.to_bytes());

    //     let mut db_secret_key = StackByteArray::new(); // ByteArray
    //     db_secret_key.copy_from_slice(&self.secret_key.to_bytes());

    //     let dryocbox = DryocBox::encrypt_to_vecbox(msg, &db_nonce, &db_public_key, &db_secret_key)?;
    //     Ok(dryocbox.to_vec())
    // }

    fn encrypt(&self, msg: &[u8], public_key: &Self::PublicKey) -> anyhow::Result<Vec<u8>> {
        let mut recipient_public_key = StackByteArray::new();
        recipient_public_key.copy_from_slice(&public_key.to_bytes());
        let dryocbox = DryocBox::seal_to_vecbox(msg, &recipient_public_key)?;
        Ok(dryocbox.to_vec())
    }

    fn public_key(&self) -> Self::PublicKey {
        x25519_dalek::PublicKey::from(&self.secret_key)
    }
}

impl Decryptor for Curve25519 {
    type PublicKey = x25519_dalek::PublicKey;

    // fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 24]) -> anyhow::Result<Vec<u8>> {
    //     let dryocbox = DryocBox::from_bytes(ciphertext)?;

    //     let mut db_nonce = StackByteArray::new();
    //     db_nonce.copy_from_slice(nonce.as_slice());

    //     let mut db_public_key = StackByteArray::new();
    //     db_public_key.copy_from_slice(&self.public_key().to_bytes());

    //     Ok(dryocbox.decrypt_to_vec(&db_nonce, &db_public_key, &KEYPAIR.secret_key)?)

    //     // simple alternative to above
    //     Ok(dryocbox.unseal_to_vec(&KEYPAIR)?)
    // }

    fn decrypt(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let dryocbox = DryocBox::from_sealed_bytes(ciphertext)?;
        Ok(dryocbox.unseal_to_vec(&KEYPAIR)?)
    }
}
