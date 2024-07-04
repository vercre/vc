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

    // ECDH-ES, RSA
    fn encrypt(&self, msg: &[u8], public_key: &Self::PublicKey) -> anyhow::Result<Vec<u8>>;

    fn public_key(&self) -> Self::PublicKey;
}

pub trait Decryptor {
    type PublicKey;

    fn decrypt(&self, encrypted: &[u8]) -> anyhow::Result<Vec<u8>>;
}

// https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
// https://www.rfc-editor.org/rfc/rfc7518.html (JSON Web Algorithms (JWA))

// "alg_values_supported" : [
// 	"ECDH-ES" // <- Diffie-Hellman Ephemeral Static key agreement using Concat KDF
// ],
// "enc_values_supported" : [
// 	"A128GCM" // <- 128-bit AES-GCM
// ],

// https://www.rfc-editor.org/rfc/rfc7518#appendix-C:

// {
// 	"alg":"ECDH-ES",
// 	"enc":"A128GCM",
// 	"apu":"QWxpY2U",
// 	"apv":"Qm9i",
// 	"epk": {
// 		"kty":"EC",
//         "crv":"P-256",
//         "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
//         "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
// 	}
// }
