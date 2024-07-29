//! # JSON Web Algorithms (JWA)
//!
//! JWA [RFC7518] defines a set of cryptographic algorithms for use with
//! JWS ([RFC7515]), JWE ([RFC7516]), and JWK ([RFC7517]).
//!
//! See associated [IANA] registries for more information
//!
//! [RFC7515]: https://www.rfc-editor.org/rfc/rfc7515
//! [RFC7516]: https://www.rfc-editor.org/rfc/rfc7516
//! [RFC7517]: https://www.rfc-editor.org/rfc/rfc7517
//! [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
//! [IANA]: https://www.iana.org/assignments/jose/jose.xhtml

use std::fmt::{Debug, Display};

use serde::{Deserialize, Serialize};

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
