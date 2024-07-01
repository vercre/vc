//! # JOSE Proofs
//!
//! JSON Object Signing and Encryption ([JOSE]) proofs are a form of enveloping proofs
//! of Credentials based on JWT [RFC7519], JWS [RFC7515], and JWK [RFC7517].
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
//! [RFC7519]: https://www.rfc-editor.org/rfc/rfc7519
//! [RFC7517]: https://www.rfc-editor.org/rfc/rfc7517
//! [VC-JOSE-COSE]: https://w3c.github.io/vc-jose-cose
//! [OpenID4VP]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

use std::fmt::{Debug, Display};

use anyhow::{anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
use ecdsa::signature::Verifier as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::endpoint::{Algorithm, Jwk, Signer, Verifier};

/// The JWT `typ` claim.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Type {
    /// JWT `typ` for Verifiable Credential.
    #[default]
    #[serde(rename = "jwt")]
    Credential,

    /// JWT `typ` for Verifiable Presentation.
    #[serde(rename = "jwt")]
    Presentation,

    /// JWT `typ` for Authorization Request Object.
    #[serde(rename = "oauth-authz-req+jwt")]
    Request,

    /// JWT `typ` for Wallet's Proof of possession of key material.
    #[serde(rename = "openid4vci-proof+jwt")]
    Proof,
}

impl Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

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
        kid: Some(signer.verification_method()),
        ..Header::default()
    };

    // payload
    let header_raw = serde_json::to_vec(&header)?;
    let header_enc = Base64UrlUnpadded::encode_string(&header_raw);
    let claims_raw = serde_json::to_vec(claims)?;
    let claims_enc = Base64UrlUnpadded::encode_string(&claims_raw);
    let payload = format!("{header_enc}.{claims_enc}");

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
pub async fn decode<T>(token: &str, verifier: &impl Verifier) -> anyhow::Result<Jwt<T>>
where
    T: DeserializeOwned + Send,
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
    let jwk = verifier.deref_jwk(&header.kid.clone().unwrap_or_default()).await?;
    verify(&jwk, &format!("{}.{}", parts[0], parts[1]), &sig)?;

    Ok(Jwt { header, claims })
}

/// Verify the signature of the provided message using the JWK.
///
/// # Errors
///
/// Will return an error if the signature is invalid, the JWK is invalid, or the
/// algorithm is unsupported.
pub fn verify(jwk: &Jwk, msg: &str, sig: &[u8]) -> anyhow::Result<()> {
    match jwk.crv.as_str() {
        "ES256K" | "secp256k1" => verify_es256k(jwk, msg, sig), // kty: "EC"
        "X25519" => verify_eddsa(jwk, msg, sig),                // kty: "OKP"
        _ => bail!("Unsupported JWT signature algorithm"),
    }
}

// Verify the signature of the provided message using the ES256K algorithm.
fn verify_es256k(jwk: &Jwk, msg: &str, sig: &[u8]) -> anyhow::Result<()> {
    use ecdsa::{Signature, VerifyingKey};
    use k256::Secp256k1;

    // build verifying key
    let y = jwk.y.as_ref().ok_or_else(|| anyhow!("Proof JWT 'y' is invalid"))?;
    let mut sec1 = vec![0x04]; // uncompressed format
    sec1.append(&mut Base64UrlUnpadded::decode_vec(&jwk.x)?);
    sec1.append(&mut Base64UrlUnpadded::decode_vec(y)?);

    let verifying_key = VerifyingKey::<Secp256k1>::from_sec1_bytes(&sec1)?;
    let signature: Signature<Secp256k1> = Signature::from_slice(sig)?;

    Ok(verifying_key.verify(msg.as_bytes(), &signature)?)
}

// Verify the signature of the provided message using the EdDSA algorithm.
fn verify_eddsa(jwk: &Jwk, msg: &str, sig_bytes: &[u8]) -> anyhow::Result<()> {
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

/// Represents a JWT as used for proof and credential presentation.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Jwt<T> {
    /// The JWT header.
    pub header: Header,

    /// The JWT claims.
    pub claims: T,
}

/// Represents the JWT header.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Header {
    /// Digital signature algorithm identifier as per IANA "JSON Web Signature
    /// and Encryption Algorithms" registry.
    pub alg: Algorithm,

    /// Used to declare the media type [IANA.MediaTypes](http://www.iana.org/assignments/media-types)
    /// of the JWS.
    pub typ: Type,

    /// Contains the key ID. If the Credential is bound to a DID, the kid refers to a
    /// DID URL which identifies a particular key in the DID Document that the
    /// Credential should bound to. Alternatively, may refer to  a key inside a JWKS.
    ///
    /// MUST NOT be set if `jwk` property is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Contains the key material the new Credential shall be bound to.
    ///
    /// MUST NOT be set if `kid` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,

    /// Contains a certificate (or certificate chain) corresponding to the key used to
    /// sign the JWT. This element MAY be used to convey a key attestation. In such a
    /// case, the actual key certificate will contain attributes related to the key
    /// properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<String>,

    /// Contains an OpenID.Federation Trust Chain. This element MAY be used to convey
    /// key attestation, metadata, metadata policies, federation Trust Marks and any
    /// other information related to a specific federation, if available in the chain.
    ///
    /// When used for signature verification, `kid` MUST be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_chain: Option<String>,
}
