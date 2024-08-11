//! # JSON Web Signature (JWS)
//!
//! JWS ([RFC7515]) represents content secured with digital signatures using JSON-based data
//! structures. Cryptographic algorithms and identifiers for use with this
//! specification are described in the JWA ([RFC7518]) specification.
//!
//! [RFC7515]: https://www.rfc-editor.org/rfc/rfc7515
//! [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518

use anyhow::{anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
use ecdsa::signature::Verifier as _;
use futures::Future;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::jose::jwk::{Curve, PublicKeyJwk};
pub use crate::jose::jwt::{Header, Jwt, KeyType, Type};
use crate::{Algorithm, Signer};

/// Encode the provided header and claims and sign, returning a JWT in compact JWS form.
///
/// # Errors
/// TODO: add error docs
pub async fn encode<T>(typ: Type, claims: &T, signer: impl Signer) -> anyhow::Result<String>
where
    T: Serialize + Send + Sync,
{
    tracing::debug!("encode");

    // header
    let header = Header {
        alg: signer.algorithm(),
        typ,
        key: KeyType::KeyId(signer.verification_method()),
        ..Header::default()
    };

    // payload
    let header = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header)?);
    let claims = Base64UrlUnpadded::encode_string(&serde_json::to_vec(claims)?);
    let payload = format!("{header}.{claims}");

    // sign
    let sig = signer.try_sign(payload.as_bytes()).await?;
    let sig_enc = Base64UrlUnpadded::encode_string(&sig);

    Ok(format!("{payload}.{sig_enc}"))
}

// TODO: allow passing verifier into this method
/// Decode the JWT token and return the claims.
///
/// # Errors
/// TODO: Add errors
pub async fn decode<F, Fut, T>(token: &str, pk_cb: F) -> anyhow::Result<Jwt<T>>
where
    T: DeserializeOwned + Send,
    F: FnOnce(String) -> Fut + Send + Sync,
    Fut: Future<Output = anyhow::Result<PublicKeyJwk>> + Send + Sync,
{
    // TODO: cater for different key types
    let parts = token.split('.').collect::<Vec<&str>>();
    if parts.len() != 3 {
        bail!("invalid Compact JWS format");
    }

    // deserialize header, claims, and signature
    let decoded = Base64UrlUnpadded::decode_vec(parts[0])
        .map_err(|e| anyhow!("issue decoding header: {e}"))?;
    let header: Header =
        serde_json::from_slice(&decoded).map_err(|e| anyhow!("issue deserializing header: {e}"))?;
    let decoded = Base64UrlUnpadded::decode_vec(parts[1])
        .map_err(|e| anyhow!("issue decoding claims: {e}"))?;
    let claims =
        serde_json::from_slice(&decoded).map_err(|e| anyhow!("issue deserializing claims:{e}"))?;
    let sig = Base64UrlUnpadded::decode_vec(parts[2])
        .map_err(|e| anyhow!("issue decoding signature: {e}"))?;

    // check algorithm
    if !(header.alg == Algorithm::ES256K || header.alg == Algorithm::EdDSA) {
        bail!("'alg' is not recognised");
    }

    // verify signature
    let KeyType::KeyId(kid) = header.key.clone() else {
        bail!("'kid' is not set");
    };

    // resolve 'kid' to Jwk (hint: kid will contain a DID URL for now)
    let jwk = pk_cb(kid).await?;
    verify(&jwk, &format!("{}.{}", parts[0], parts[1]), &sig)?;

    Ok(Jwt { header, claims })
}

/// Verify the signature of the provided message using the JWK.
///
/// # Errors
///
/// Will return an error if the signature is invalid, the JWK is invalid, or the
/// algorithm is unsupported.
pub fn verify(jwk: &PublicKeyJwk, msg: &str, sig: &[u8]) -> anyhow::Result<()> {
    match jwk.crv {
        Curve::Es256K => verify_es256k(jwk, msg, sig),
        Curve::Ed25519 => verify_eddsa(jwk, msg, sig),
    }
}

// Verify the signature of the provided message using the ES256K algorithm.
fn verify_es256k(jwk: &PublicKeyJwk, msg: &str, sig: &[u8]) -> anyhow::Result<()> {
    use ecdsa::{Signature, VerifyingKey};
    use k256::Secp256k1;

    // build verifying key
    let y = jwk.y.as_ref().ok_or_else(|| anyhow!("Proof JWT 'y' is invalid"))?;
    let mut sec1 = vec![0x04]; // uncompressed format
    sec1.append(&mut Base64UrlUnpadded::decode_vec(&jwk.x)?);
    sec1.append(&mut Base64UrlUnpadded::decode_vec(y)?);

    let verifying_key = VerifyingKey::<Secp256k1>::from_sec1_bytes(&sec1)?;
    let signature: Signature<Secp256k1> = Signature::from_slice(sig)?;
    let normalised = signature.normalize_s().unwrap_or(signature);

    Ok(verifying_key.verify(msg.as_bytes(), &normalised)?)
}

// Verify the signature of the provided message using the EdDSA algorithm.
fn verify_eddsa(jwk: &PublicKeyJwk, msg: &str, sig_bytes: &[u8]) -> anyhow::Result<()> {
    use ed25519_dalek::{Signature, VerifyingKey};

    // build verifying key
    let x_bytes = Base64UrlUnpadded::decode_vec(&jwk.x)
        .map_err(|e| anyhow!("unable to base64 decode proof JWK 'x': {e}"))?;
    let bytes = &x_bytes.try_into().map_err(|_| anyhow!("invalid public key length"))?;
    let verifying_key = VerifyingKey::from_bytes(bytes)
        .map_err(|e| anyhow!("unable to build verifying key: {e}"))?;
    let signature =
        Signature::from_slice(sig_bytes).map_err(|e| anyhow!("unable to build signature: {e}"))?;

    verifying_key
        .verify(msg.as_bytes(), &signature)
        .map_err(|e| anyhow!("unable to verify signature: {e}"))
}

// /// In the JWS JSON Serialization, one or both of the JWS Protected Header and
// /// JWS Unprotected Header MUST be present.  In this case, the members of the
// /// JOSE Header are the union of the members of the JWS Protected Header and
// /// the JWS Unprotected Header values that are present.
// #[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
// pub struct Jwe {
//     /// JWE protected header.
//     protected: Header,

//     /// Shared unprotected header as a JSON object.
//     #[serde(skip_serializing_if = "Option::is_none")]
//     unprotected: Option<Value>,

//     /// Encrypted key, as a base64Url encoded string.
//     payload: String,

//     /// AAD value, base64url encoded. Not used for JWE Compact Serialization.
//     signature: String,
// }
