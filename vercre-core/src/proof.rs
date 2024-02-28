//! Proof

use std::fmt::Display;
use std::str::{self, FromStr};

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use ecdsa::signature::Verifier;
use serde::{Deserialize, Serialize};

use crate::{err, error, Result};

/// Simplified JSON Web Key (JWK) key structure.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Jwk {
    /// Key type. For example, "EC" for elliptic curve or "OKP" for octet
    /// key pair (Edwards curve).
    pub kty: String,

    /// Cryptographic curve type. For example, "ES256K" for secp256k1 and
    /// "X25519" for ed25519.
    pub crv: String,

    /// X coordinate.
    pub x: String,

    /// Y coordinate. Not required for `EdDSA` verification keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    /// Use of the key. For example, "sig" for signing or "enc" for
    /// encryption.
    #[serde(rename = "use")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
}

impl Jwk {
    /// Verify the signature of the provided message using the JWK.
    ///
    /// # Errors
    /// TODO: Add error descriptions
    pub fn verify(&self, msg: &str, sig: &[u8]) -> Result<()> {
        match self.crv.as_str() {
            "ES256K" | "secp256k1" => self.verify_es256k(msg, sig), // kty: "EC"
            "X25519" => self.verify_eddsa(msg, sig),                // kty: "OKP"
            _ => err!("Unsupported JWT signature algorithm"),
        }
    }

    // Verify the signature of the provided message using the ES256K algorithm.
    fn verify_es256k(&self, msg: &str, sig: &[u8]) -> Result<()> {
        use ecdsa::{Signature, VerifyingKey};
        use k256::Secp256k1;

        // build verifying key
        let Some(y) = &self.y else {
            err!("Proof JWT 'y' is invalid");
        };
        let mut sec1 = vec![0x04]; // uncompressed format
        sec1.append(&mut Base64UrlUnpadded::decode_vec(&self.x)?);
        sec1.append(&mut Base64UrlUnpadded::decode_vec(y)?);

        let verifying_key = VerifyingKey::<Secp256k1>::from_sec1_bytes(&sec1)?;
        let signature: Signature<Secp256k1> = Signature::from_slice(sig)?;

        Ok(verifying_key.verify(msg.as_bytes(), &signature)?)
    }

    // Verify the signature of the provided message using the EdDSA algorithm.
    fn verify_eddsa(&self, msg: &str, sig_bytes: &[u8]) -> Result<()> {
        use ed25519_dalek::{Signature, VerifyingKey};

        // build verifying key
        let x_bytes = Base64UrlUnpadded::decode_vec(&self.x)?;
        let Ok(bytes) = &x_bytes.try_into() else {
            err!("Invalid public key length");
        };

        let verifying_key = VerifyingKey::from_bytes(bytes)?;
        let signature = Signature::from_slice(sig_bytes)?;

        verifying_key.verify(msg.as_bytes(), &signature)?;

        Ok(())
    }
}

impl Display for Jwk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let jwk_str = serde_json::to_string(self).map_err(|_| std::fmt::Error)?;
        write!(f, "{jwk_str}")
    }
}

impl FromStr for Jwk {
    type Err = error::Error;

    fn from_str(kid: &str) -> Result<Self, Self::Err> {
        const DID_JWK: &str = "did:jwk:";
        const DID_ION: &str = "did:ion:";

        let jwk = if kid.starts_with(DID_JWK) {
            let jwk_b64 = kid.trim_start_matches(DID_JWK).trim_end_matches("#0");
            let jwk_vec = Base64UrlUnpadded::decode_vec(jwk_b64)?;
            let Ok(jwk_str) = str::from_utf8(&jwk_vec) else {
                err!("Issue converting JWK bytes to string");
            };
            serde_json::from_str(jwk_str)?
        } else if kid.starts_with(DID_ION) {
            verification_key(kid)?
        } else {
            err!("Proof JWT 'kid' is invalid");
        };

        Ok(jwk)
    }
}

/// Get the verification key for the specified DID.
///
/// # Errors
///
/// This function will return an `Err::ServerError` error if a verification key
/// cannot be found for the provided DID.
///
/// # Panics
///
/// This function will panic if a `PublicKeyJwk` cannot be found in the DID Document.
pub fn verification_key(did: &str) -> Result<Jwk> {
    let Some(did) = did.split('#').next() else {
        err!("Unable to parse DID");
    };

    // if have long-form DID then try to extract key from metadata
    let did_parts: Vec<&str> = did.split(':').collect();
    if did_parts.len() != 4 {
        err!("Short-form DID's are not supported");
    }

    let dec = match Base64UrlUnpadded::decode_vec(did_parts[3]) {
        Ok(dec) => dec,
        Err(e) => {
            err!("Unable to decode DID: {e}");
        }
    };

    // let ion_op = serde_json::from_slice::<IonOperation>(&dec)?;
    let ion_op = serde_json::from_slice::<serde_json::Value>(&dec)?;
    let pk_val = ion_op
        .get("delta")
        .unwrap()
        .get("patches")
        .unwrap()
        .get(0)
        .unwrap()
        .get("document")
        .unwrap()
        .get("publicKeys")
        .unwrap()
        .get(0)
        .unwrap()
        .get("publicKeyJwk")
        .unwrap();

    Ok(serde_json::from_value(pk_val.clone())?)
}
