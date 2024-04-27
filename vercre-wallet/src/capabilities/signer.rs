//! # Signer
//!
//! The `Signer` capability is used to sign requests and responses using the wallet's
//! signing key.
//!
//! Signing operations occur during:
//!
//! 1. Credential issuance — the wallet signs a Proof (JWT or CWT) as proof of possesion
//!    of key material. That is, proof that the wallet controls the private key for the
//!    DID the issued credential will be bound to.
//!
//! 2. Credential presentation — the wallet signs a Proof eincluded in the presentation
//!    response as proof of possession of key material. That is, proof that the wallet
//!    controls the private key for the DID the presentation response is bound to.

use std::fmt::Display;

use base64ct::{Base64UrlUnpadded, Encoding};
use crux_core::capability::{CapabilityContext, Operation};
use crux_core::macros::Capability;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vercre_core::jwt::Jwt;

/// Errors that can be returned by the Signer capability.
#[derive(Clone, Debug, Deserialize, Error, PartialEq, Eq)]
pub enum Error {
    /// The request was invalid.
    #[error("invalid signing request {0}")]
    InvalidRequest(String),
}

// manually implement serde::Serialize
impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::InvalidRequest(err.to_string())
    }
}

/// Result type for the `Signer` capability.
pub type Result<T> = std::result::Result<T, Error>;

/// Operations supported (by the `Signer` capability).
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[allow(clippy::module_name_repetitions)]
pub enum SignerRequest {
    /// Sign the provided message
    Sign(Vec<u8>),

    /// Verification information
    Verification,
}

/// `SignerResponse` represents the output expected from any implementer of the
/// Signer capability.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[allow(clippy::module_name_repetitions)]
pub enum SignerResponse {
    /// The signing operation returned the signature without issue.
    Signature(Vec<u8>),

    /// Signer's verification information.
    Verification {
        /// The algorithm used for signing.
        alg: String,

        /// The key identifier.
        kid: String,
    },

    /// The signing operation returned with the specified error.
    Err(String),
}

/// Operation provides a Crux wrapper for the `SignerRequest` consumed by the
/// Shell.
///
/// The Output type allows us to specify the expected response type from the
/// Shell.
impl Operation for SignerRequest {
    type Output = SignerResponse;
}

/// The Signer type used to implement the capability.
#[derive(Capability)]
pub struct Signer<Ev> {
    context: CapabilityContext<SignerRequest, Ev>,
}

impl<Ev> Signer<Ev>
where
    Ev: 'static,
{
    /// Create a new Signer capability context.
    #[must_use]
    pub const fn new(context: CapabilityContext<SignerRequest, Ev>) -> Self {
        Self { context }
    }

    /// Sign provided message using the vercre-wallet's signing key. Returns the signed output.
    ///
    /// Dispatches the 'callback' event specified in the capability request.
    ///
    /// # Panics
    ///
    /// Panics if the response is an `Err` variant.
    pub fn sign<T, F>(&self, jwt: &Jwt<T>, make_event: F)
    where
        T: Serialize + Clone,
        Jwt<T>: Display,
        F: Fn(Result<String>) -> Ev + Send + Sync + 'static,
    {
        self.context.spawn({
            let ctx = self.context.clone();
            let msg = jwt.to_string();

            async move {
                let request = SignerRequest::Sign(msg.clone().into_bytes());

                match ctx.request_from_shell(request).await {
                    SignerResponse::Signature(sig) => {
                        let sig_enc = Base64UrlUnpadded::encode_string(&sig);
                        let signed = format!("{msg}.{sig_enc}");
                        ctx.update_app(make_event(Ok(signed)));
                    }
                    SignerResponse::Err(err) => {
                        ctx.update_app(make_event(Err(Error::InvalidRequest(err))));
                    }
                    SignerResponse::Verification { .. } => {
                        panic!("Verification is not a valid response");
                    }
                }
            }
        });
    }

    /// Get the signer's verification information.
    ///
    /// Dispatches the 'callback' event specified in the capability request.
    ///
    /// # Panics
    ///
    /// Panics if the response is a `Signature` variant.
    pub fn verification<F>(&self, make_event: F)
    where
        F: Fn(Result<(String, String)>) -> Ev + Send + Sync + 'static,
    {
        self.context.spawn({
            let ctx = self.context.clone();

            async move {
                let request = SignerRequest::Verification;

                match ctx.request_from_shell(request).await {
                    SignerResponse::Verification { alg, kid } => {
                        ctx.update_app(make_event(Ok((alg, kid))));
                    }
                    SignerResponse::Err(err) => {
                        ctx.update_app(make_event(Err(Error::InvalidRequest(err))));
                    }
                    SignerResponse::Signature(_) => panic!("Signature is not a valid response"),
                }
            }
        });
    }
}
