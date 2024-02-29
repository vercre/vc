//! # JWT support
//!
//! ## Note
//! If the JWT is only a JWE, iss, exp and aud MUST be omitted in the JWT Claims
//! Set of the JWE, and the processing rules as per JARM Section 2.4 related to
//! these claims do not apply. [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
//! JWT - JWE
//!
//! ```json
//! {
//!   "vp_token": "eyJI...",
//!   "presentation_submission": {...}
//! }
//! ```

// TODO: replace this with `jsonwebtoken` library or similar.

use std::fmt::Display;
use std::marker::PhantomData;
use std::str::FromStr;
use std::{fmt, str};

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::de::{self, DeserializeOwned, Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use tracing::{instrument, trace};

use crate::error::{self, Err};
use crate::provider::Signer;
use crate::{err, proof, Result};

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
    pub alg: String,

    /// MAY be used if there are multiple keys associated with the issuer of the
    /// JWT. For example, kid can refer to a key in a DID document or a key
    /// inside a JWKS.
    pub kid: String,

    /// Wallet proof: "vercre-vci-proof+jwt"
    /// Credential: "jwt"
    /// Request Object: "oauth-authz-req+jwt"
    /// Presentation: ???
    pub typ: String,
}

impl<T> Jwt<T>
where
    T: Serialize + Default + Send + fmt::Debug,
{
    /// Signs the JWT using the provided Signer
    #[instrument]
    pub async fn sign(&mut self, signer: impl Signer) -> Result<String> {
        trace!("Jwt::sign");

        // set header fields
        if self.header.typ.is_empty() {
            self.header.typ = String::from("JWT");
        }
        if self.header.kid.is_empty() {
            self.header.kid = signer.verification_method();
        }
        if self.header.alg.is_empty() {
            self.header.alg = signer.algorithm().to_string();
        }

        // serialize
        let msg = self.to_string();

        // sign
        let sig = signer.try_sign(msg.as_bytes()).await?;
        let sig_enc = Base64UrlUnpadded::encode_string(&sig);

        Ok(format!("{msg}.{sig_enc}"))
    }
}

impl<T> Display for Jwt<T>
where
    T: Serialize + Default + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_raw = serde_json::to_vec(&self.header).map_err(|_| std::fmt::Error)?;
        let header_enc = Base64UrlUnpadded::encode_string(&header_raw);
        let claims_raw = serde_json::to_vec(&self.claims).map_err(|_| std::fmt::Error)?;
        let claims_enc = Base64UrlUnpadded::encode_string(&claims_raw);

        write!(f, "{header_enc}.{claims_enc}")
    }
}

impl<T> FromStr for Jwt<T>
where
    T: DeserializeOwned,
{
    type Err = error::Error;

    #[instrument]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        trace!("Jwt::from_str");

        // verify signature
        // TODO: cater for different key types
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            err!(Err::InvalidRequest, "invalid proof JWT format");
        }

        let jwt = Self {
            header: serde_json::from_slice(&Base64UrlUnpadded::decode_vec(parts[0])?)?,
            claims: serde_json::from_slice(&Base64UrlUnpadded::decode_vec(parts[1])?)?,
        };

        let msg = format!("{}.{}", parts[0], parts[1]);
        let sig = Base64UrlUnpadded::decode_vec(parts[2])?;
        let jwk = proof::Jwk::from_str(&jwt.header.kid)?;

        jwk.verify(&msg, &sig).map(|()| jwt)
    }
}

struct VisitorImpl<T>(PhantomData<fn() -> Jwt<T>>);

impl<'de, T> Deserialize<'de> for Jwt<T>
where
    T: DeserializeOwned + Default,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(VisitorImpl(PhantomData))
    }
}

impl<'de, T> Visitor<'de> for VisitorImpl<T>
where
    T: DeserializeOwned + Default,
{
    type Value = Jwt<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Jwt<T>")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Jwt::from_str(value).map_or_else(
            |_| Err(de::Error::invalid_value(de::Unexpected::Str(value), &self)),
            |jwt| Ok(jwt),
        )
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut jwt = Jwt::<T>::default();

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "header" => jwt.header = map.next_value()?,
                "claims" => jwt.claims = map.next_value::<T>()?,
                _ => return Err(de::Error::unknown_field(&key, &["header", "claims"])),
            }
        }

        Ok(jwt)
    }
}
