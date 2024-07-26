#![allow(missing_docs)]
#![allow(dead_code)]
#![allow(clippy::missing_errors_doc)]

//! # JSON Object Signing and Encryption (JOSE) Proofs
//!
//! [JOSE] proofs are enveloping proofs for Credentials based on JWT [RFC7519],
//! JWS [RFC7515], and JWK [RFC7517].
//!
//! The Securing Verifiable Credentials using JOSE and COSE [VC-JOSE-COSE]
//! recommendation defines a "bridge" between these and the Verifiable Credentials Data
//! Model v2.0, specifying the suitable header claims, media types, etc.
//!
//! In the case of JOSE, the Credential is the "payload". This is preceded by a suitable
//! header whose details are specified by Securing Verifiable Credentials using JOSE and
//! COSE for the usage of JWT. These are encoded, concatenated, and signed, to be
//! transferred in a compact form by one entity to an other (e.g., sent by the holder to
//! the verifier). All the intricate details on signatures, encryption keys, etc., are
//! defined by the IETF specifications; see Example 6 for a specific case.
//!
//! ## Note
//!
//! If the JWT is only a JWE, iss, exp and aud MUST be omitted in the JWT Claims
//! Set of the JWE, and the processing rules as per JARM Section 2.4 related to
//! these claims do not apply. [OpenID4VP] JWT - JWE
//!
//! ```json
//! {
//!   "vp_token": "eyJI...",
//!   "presentation_submission": {...}
//! }
//! ```
//!
//! [JOSE]: https://datatracker.ietf.org/wg/jose/about
//! [RFC7515]: https://www.rfc-editor.org/rfc/rfc7515
//! [RFC7517]: https://www.rfc-editor.org/rfc/rfc7517
//! [RFC7519]: https://www.rfc-editor.org/rfc/rfc7519
//! [VC-JOSE-COSE]: https://w3c.github.io/vc-jose-cose
//! [OpenID4VP]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

// pub mod jwa;
// mod jwe;
// pub mod jwk;
// pub mod jws;
// mod jwt;
pub mod jose;
pub mod signature;

// use signature::Keypair;

/// A `Keyring` contains a set of related keys
pub trait Keyring: Signer + Encryptor {}

// pub trait Signature {
//     type VerifyingKey;

//     fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>>;

//     fn verifying_key(&self) -> anyhow::Result<Self::VerifyingKey>;

//     fn verify(
//         &self, data: &[u8], signature: &[u8], verifying_key: &Self::VerifyingKey,
//     ) -> anyhow::Result<()>;
// }

// pub trait Encryption {
//     fn encrypt(&self, plaintext: &[u8], recipient_public_key: &[u8]) -> anyhow::Result<Vec<u8>>;

//     fn public_key(&self) -> Vec<u8>;

//     fn decrypt(&self, ciphertext: &[u8], sender_public_key: &[u8]) -> anyhow::Result<Vec<u8>>;
// }

pub trait Signer {
    type VerifyingKey;

    fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>>;

    fn verifying_key(&self) -> anyhow::Result<Self::VerifyingKey>;
}

// pub trait Verifier {
//     type VerifyingKey;

//     fn verify(
//         &self, data: &[u8], signature: &[u8], verifying_key: &Self::VerifyingKey,
//     ) -> anyhow::Result<()>;
// }

pub trait Encryptor {
    fn encrypt(&self, plaintext: &[u8], recipient_public_key: &[u8]) -> anyhow::Result<Vec<u8>>;

    fn public_key(&self) -> Vec<u8>;
}

pub trait Decryptor {
    fn decrypt(&self, ciphertext: &[u8], sender_public_key: &[u8]) -> anyhow::Result<Vec<u8>>;
}
