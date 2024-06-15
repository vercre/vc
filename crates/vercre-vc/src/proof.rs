//! Securing Credentials
//!
//! Verifiable Credentials can be secured using two different mechanisms: enveloping
//! proofs or embedded proofs. In both cases, a proof cryptographically secures a
//! Credential (for example, using digital signatures). In the enveloping case,
//! the proof wraps around the Credential, whereas embedded proofs are included in the
//! serialization, alongside the Credential itself.
//!
//! ## Envelooping Proofs
//!
//! A family of enveloping proofs is defined in the [Securing Verifiable Credentials
//! using JOSE and COSE] document, relying on technologies defined by
//! the IETF. Other types of enveloping proofs may be specified by the community.
//!
//! ## Embedded Proofs
//!
//! The general structure for embedded proofs is defined in a separate [Verifiable
//! Credential Data Integrity 1.0] specification. Furthermore, some instances of this
//! general structure are specified in the form of the "cryptosuites": Data Integrity
//! [EdDSA Cryptosuites v1.0], Data Integrity [ECDSA Cryptosuites v1.0], and Data
//! Integrity [BBS Cryptosuites v1.0].
//!
//! [Securing Verifiable Credentials using JOSE and COSE]: https://w3c.github.io/vc-jose-cose
//! [Verifiable Credential Data Integrity 1.0]: https://www.w3.org/TR/vc-data-integrity
//! [EdDSA Cryptosuites v1.0]: https://www.w3.org/TR/vc-di-eddsa
//! [ECDSA Cryptosuites v1.0]: https://www.w3.org/TR/vc-di-ecdsa
//! [BBS Cryptosuites v1.0]: https://w3c.github.io/vc-di-bbs

mod controller;
pub mod integrity;
mod jose;

use serde::{Deserialize, Serialize};
use vercre_core::jws;
pub use vercre_core::provider::{Algorithm, Signer};

use crate::model::{VerifiableCredential, VerifiablePresentation};

/// `Type` is used to identify the type of proof to be created.
#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions, clippy::large_enum_variant)]
pub enum Payload {
    /// A Verifiable Credential proof encoded as a JWT.
    Vc(VerifiableCredential),

    /// A Verifiable Presentation proof encoded as a JWT.
    Vp {
        /// The Presentation to create a proof for.
        vp: VerifiablePresentation,

        /// The Verifier's OpenID `client_id` (from Presentation request).
        client_id: String,

        /// The Verifier's `nonce` (from Presentation request).
        nonce: String,
    },
}

/// Create a proof from a proof provider.
///
/// # Errors
/// TODO: Add errors
pub async fn create(payload: Payload, signer: impl Signer) -> anyhow::Result<String> {
    let jwt = match payload {
        Payload::Vc(vc) => {
            let claims: jose::VcClaims = vc.into();
            jws::encode(jws::Payload::Credential, &claims, signer).await?

            // TODO: add data integrity proof payload
            // let proof = Proof {
            //     id: Some(format!("urn:uuid:{}", Uuid::new_v4())),
            //     type_: Signer::algorithm(provider).proof_type(),
            //     verification_method: Signer::verification_method(provider),
            //     created: Some(Utc::now()),
            //     expires: Utc::now().checked_add_signed(TimeDelta::try_hours(1).unwrap_or_default()),
            //     ..Proof::default()
            // };
        }
        Payload::Vp { vp, client_id, nonce } => {
            let mut claims = jose::VpClaims::from(vp);
            claims.aud.clone_from(&client_id);
            claims.nonce.clone_from(&nonce);
            vercre_core::jws::encode(vercre_core::jws::Payload::Presentation, &claims, signer)
                .await?
        }
    };

    // Ok(serde_json::to_value(jwt)?)
    Ok(jwt)
}

/// Data type to verify.
pub enum Verify {
    /// A Verifiable Credential proof encoded as a JWT.
    Vc,

    /// A Verifiable Presentation proof encoded as a JWT.
    Vp,
}

/// Verify a proof.
///
/// # Errors
/// TODO: Add errors
#[allow(clippy::unused_async)]
pub async fn verify(token: &str, payload: Verify) -> anyhow::Result<Payload> {
    match payload {
        Verify::Vc => {
            let jwt = jws::decode::<jose::VcClaims>(token)?;
            Ok(Payload::Vc(jwt.claims.vc))
        }
        Verify::Vp => {
            let jwt = jws::decode::<jose::VpClaims>(token)?;
            Ok(Payload::Vp {
                vp: jwt.claims.vp,
                client_id: jwt.claims.aud,
                nonce: jwt.claims.nonce,
            })
        }
    }
}
