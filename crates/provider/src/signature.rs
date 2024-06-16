//! # Signature
//!
//! The `signature` module provides `Signer` and `Verifier` traits for Vercre.

use std::fmt::{Debug, Display};
use std::future::{Future, IntoFuture};

use serde::{Deserialize, Serialize};

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
    /// Verify the provided signature for a given message.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    fn verify(&self, msg: &[u8], signature: &[u8]) -> anyhow::Result<()>;
}

/// Algorithm is used to specify the signing algorithm used by the signer.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Algorithm {
    /// Algorithm for the secp256k1 curve
    #[serde(rename = "ES256K")]
    ES256K,

    /// Algorithm for the Ed25519 curve
    #[default]
    #[serde(rename = "EdDSA")]
    EdDSA,
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
