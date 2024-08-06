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

pub mod jose;

use std::future::{Future, IntoFuture};

pub use crate::jose::jwa::Algorithm;
use crate::jose::jwk::PublicKeyJwk;

/// The `DataSec` trait is used to provide methods needed for signing, encrypting,
/// verifying, and decrypting data. Implementers of this trait are expected to
/// provide the necessary cryptographic functionality to support Verifiable
/// Credential issuance and Verifiable Presentation submissions.
pub trait DataSec: Send + Sync {
    /// Signer provides digital signing-related funtionality.
    /// The `identifier` parameter is one of `credential_issuer` or `verifier_id`.
    fn signer(&self, identifier: &str) -> anyhow::Result<impl Signer>;

    /// Verifier provides digital signature verification functionality.
    fn verifier(&self, identifier: &str) -> anyhow::Result<impl Verifier>;

    /// Encryptor provides data encryption functionality.
    fn encryptor(&self, identifier: &str) -> anyhow::Result<impl Encryptor>;

    /// Decryptor provides data decryption functionality.
    fn decryptor(&self, identifier: &str) -> anyhow::Result<impl Decryptor>;
}

/// Signer is used by implementers to provide signing functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
pub trait Signer: Send + Sync {
    /// Algorithm returns the algorithm used by the signer.
    fn algorithm(&self) -> Algorithm;

    /// The verification method the verifier should use to verify the signer's
    /// signature. This is typically a DID URL + # + verification key ID.
    fn verification_method(&self) -> String;

    /// Sign is a convenience method for infallible Signer implementations.
    fn sign(&self, msg: &[u8]) -> impl Future<Output = Vec<u8>> + Send {
        let v = async { self.try_sign(msg).await.expect("should sign") };
        v.into_future()
    }

    /// `TrySign` is the fallible version of Sign.
    fn try_sign(&self, msg: &[u8]) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;
}

/// Verifier is used by implementers to provide verification functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
pub trait Verifier: Send + Sync {
    /// Dereference DID URL to the public key JWK specified in the URL fragment.
    ///
    /// # Errors
    ///
    /// Returns an error if the DID URL cannot be dereferenced to a JWK
    fn deref_jwk(&self, did_url: &str)
        -> impl Future<Output = anyhow::Result<PublicKeyJwk>> + Send;
}

/// Encryptor is used by implementers to provide encryption functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
pub trait Encryptor: Send + Sync {
    fn encrypt(
        &self, plaintext: &[u8], recipient_public_key: &[u8],
    ) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;

    fn public_key(&self) -> Vec<u8>;
}

/// Decryptor is used by implementers to provide decryption functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
pub trait Decryptor: Send + Sync {
    fn decrypt(
        &self, ciphertext: &[u8], sender_public_key: &[u8],
    ) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;
}
