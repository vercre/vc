//! # `OpenID` for Verifiable Credentials Types
//!
//! Types and logic used in the `OpenID4VC` specifications and consumed by
//! `vercre-issuer`,`vercre-verifier`, and `vercre-holder` crates.
//!
//! The crate is for internal use within Vercre project and is not intended to be used
//! directly by the end users. Any public types are re-exported through the respective
//! top-level `vercre-xxx` crates.

mod error;
pub mod issuer;
pub mod oauth;
pub mod provider;
pub mod verifier;

use std::fmt::Display;

use serde::{Deserialize, Serialize};

pub use self::error::Error;

/// Result type for `OpenID` for Verifiable Credential Issuance and Verifiable
/// Presentations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The `OpenID4VCI` specification defines commonly used [Credential Format Profiles]
/// to support.  The profiles define Credential format specific parameters or claims
/// used to support a particular format.
///
///
/// [Credential Format Profiles]: (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-format-profiles)
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub enum CredentialFormat {
    /// A W3C Verifiable Credential.
    ///
    /// When this format is specified, Credential Offer, Authorization Details,
    /// Credential Request, and Credential Issuer metadata, including
    /// `credential_definition` object, MUST NOT be processed using JSON-LD rules.
    #[default]
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson,

    /// A W3C Verifiable Credential.
    ///
    /// When using this format, data MUST NOT be processed using JSON-LD rules.
    ///
    /// N.B. The `@context` value in the `credential_definition` object can be used by
    /// the Wallet to check whether it supports a certain VC. If necessary, the Wallet
    /// could apply JSON-LD processing to the Credential issued.
    #[serde(rename = "ldp-vc")]
    LdpVc,

    /// A W3C Verifiable Credential.
    ///
    /// When using this format, data MUST NOT be processed using JSON-LD rules.
    ///
    /// N.B. The `@context` value in the `credential_definition` object can be used by
    /// the Wallet to check whether it supports a certain VC. If necessary, the Wallet
    /// could apply JSON-LD processing to the Credential issued.
    #[serde(rename = "jwt_vc_json-ld")]
    JwtVcJsonLd,

    /// ISO mDL.
    ///
    /// A Credential Format Profile for Credentials complying with [ISO.18013-5] —
    /// ISO-compliant driving licence specification.
    ///
    /// [ISO.18013-5]: (https://www.iso.org/standard/69084.html)
    #[serde(rename = "mso_mdoc")]
    MsoDoc,

    /// IETF SD-JWT VC.
    ///
    /// A Credential Format Profile for Credentials complying with
    /// [I-D.ietf-oauth-sd-jwt-vc] — SD-JWT-based Verifiable Credentials for
    /// selective disclosure.
    ///
    /// [I-D.ietf-oauth-sd-jwt-vc]: (https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-01)
    #[serde(rename = "vc+sd-jwt")]
    VcSdJwt,

    /// W3C Verifiable Credential.
    #[serde(rename = "jwt_vp_json")]
    JwtVpJson,
}

impl Display for CredentialFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialFormat::JwtVcJson => write!(f, "jwt_vc_json"),
            CredentialFormat::LdpVc => write!(f, "ldp_vc"),
            CredentialFormat::JwtVcJsonLd => write!(f, "jwt_vc_json-ld"),
            CredentialFormat::MsoDoc => write!(f, "mso_mdoc"),
            CredentialFormat::VcSdJwt => write!(f, "vc+sd-jwt"),
            CredentialFormat::JwtVpJson => write!(f, "jwt_vp_json"),
        }
    }
}
