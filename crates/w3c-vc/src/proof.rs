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

use anyhow::bail;
use serde::{Deserialize, Serialize};
use vercre_core::{Kind, Quota};
use vercre_datasec::jose::{jws, jwt};
use vercre_datasec::Signer;
use vercre_did::DidResolver;

use crate::model::{VerifiableCredential, VerifiablePresentation};
use crate::verify_key;

/// Credential format options for the resulting proof.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Format {
    /// VC signed as a JWT, not using JSON-LD
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson,

    /// VC signed as a JWT, using JSON-LD
    #[serde(rename = "jwt_vc_json-ld")]
    JwtVcJsonLd,

    /// VC secured using Data Integrity, using JSON-LD, with a proof suite requiring
    /// Linked Data canonicalization.
    #[serde(rename = "ldp_vc")]
    DataIntegrityJsonLd,

    /// SD-JWT-based Verifiable Credentials
    /// [SD-JWT VC](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-01)
    #[serde(rename = "vc+sd-jwt")]
    VcSdJwt,

    /// ISO-compliant driving licence
    /// [ISO.18013-5](https://www.iso.org/standard/69084.html).
    #[serde(rename = "mso_mdoc")]
    IsoMDl,
}

/// `Payload` is used to identify the type of proof to be created.
#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
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
/// TODO: document errors
pub async fn create(
    format: Format, payload: Payload, signer: impl Signer,
) -> anyhow::Result<String> {
    if format != Format::JwtVcJson && format != Format::JwtVcJsonLd {
        return Err(anyhow::anyhow!("Unsupported proof format"));
    }

    let jwt = match payload {
        Payload::Vc(vc) => {
            let claims: jose::VcClaims = vc.into();
            jws::encode(jws::Type::Credential, &claims, signer).await?
        }
        Payload::Vp { vp, client_id, nonce } => {
            let mut claims = jose::VpClaims::from(vp);
            claims.aud.clone_from(&client_id);
            claims.nonce.clone_from(&nonce);
            jws::encode(jws::Type::Presentation, &claims, signer).await?
        }
    };

    // TODO: add data integrity proof payload
    // let proof = Proof {
    //     id: Some(format!("urn:uuid:{}", Uuid::new_v4())),
    //     type_: Signer::algorithm(provider).proof_type(),
    //     verification_method: Signer::verification_method(provider),
    //     created: Some(Utc::now()),
    //     expires: Utc::now().checked_add_signed(TimeDelta::try_hours(1).unwrap_or_default()),
    //     ..Proof::default()
    // };

    // Ok(serde_json::to_value(jwt)?)
    Ok(jwt)
}

/// Data type to verify.
pub enum Verify<'a> {
    /// A Verifiable Credential proof either encoded as a JWT or with an
    /// embedded a Data Integrity Proof.
    Vc(&'a Kind<VerifiableCredential>),

    /// A Verifiable Presentation proof either encoded as a JWT or with an
    /// embedded a Data Integrity Proof.
    Vp(&'a Kind<VerifiablePresentation>),
}

/// Verify a proof.
///
/// # Errors
/// TODO: document errors
#[allow(clippy::unused_async)]
pub async fn verify(proof: Verify<'_>, resolver: &impl DidResolver) -> anyhow::Result<Payload> {
    match proof {
        Verify::Vc(value) => {
            let Kind::String(token) = value else {
                bail!("VerifiableCredential is not a JWT");
            };
            let jwt: jwt::Jwt<jose::VcClaims> = jws::decode(token, verify_key!(resolver)).await?;
            Ok(Payload::Vc(jwt.claims.vc))
        }
        Verify::Vp(value) => {
            match value {
                Kind::String(token) => {
                    let jwt: jwt::Jwt<jose::VpClaims> =
                        jws::decode(token, verify_key!(resolver)).await?;
                    Ok(Payload::Vp {
                        vp: jwt.claims.vp,
                        client_id: jwt.claims.aud,
                        nonce: jwt.claims.nonce,
                    })
                }
                Kind::Object(vp) => {
                    // TODO: Implement embedded proof verification
                    let Some(Quota::One(proof)) = &vp.proof else {
                        bail!("invalid VerifiablePresentation proof")
                    };
                    let challenge = proof.challenge.clone().unwrap_or_default();

                    Ok(Payload::Vp {
                        vp: vp.clone(),
                        nonce: challenge,
                        client_id: String::new(),
                    })
                }
            }
        }
    }
}
