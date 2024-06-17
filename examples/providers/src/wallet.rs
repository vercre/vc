use std::str;

use anyhow::bail;
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey};
use vercre_holder::provider::{self, Algorithm, Jwk};

pub const CLIENT_ID: &str = "96bfb9cb-0513-7d64-5532-bed74c48f9ab";

const JWK_D: &str = "Y1KNbzOcX112pXI3v6sFvcr8uBLw4Pc2ciZTWdZx-As";
const JWK_X: &str = "3Lg9yviAmTDCuVOyLXI3lq9S2pHm73yr3wwAkjwCAhw";

pub struct Provider;

impl Provider {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}

impl provider::Signer for Provider {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }

    fn verification_method(&self) -> String {
        format!("{}#0", holder_did())
    }

    async fn try_sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(JWK_D)?;
        let bytes: [u8; 32] = decoded.as_slice().try_into().expect("should convert ");
        let signing_key = SigningKey::from_bytes(&bytes);
        let sig: Signature = signing_key.sign(msg);
        Ok(sig.to_vec())
    }
}

//-----------------------------------------------------------------------------
// Verifier
//-----------------------------------------------------------------------------
impl provider::Verifier for Provider {
    fn deref_jwk(&self, did_url: impl AsRef<str>) -> anyhow::Result<Jwk> {
        let Some(did) = did_url.as_ref().split('#').next() else {
            bail!("Unable to parse DID");
        };

        // if have long-form DID then try to extract key from metadata
        let did_parts: Vec<&str> = did.split(':').collect();
        if did_parts.len() != 4 {
            bail!("Short-form DID's are not supported");
        }

        let dec = match Base64UrlUnpadded::decode_vec(did_parts[3]) {
            Ok(dec) => dec,
            Err(e) => {
                bail!("Unable to decode DID: {e}");
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
}

#[must_use]
pub fn holder_did() -> String {
    let jwk = serde_json::json!({
        "kty": "OKP",
        "crv": "X25519",
        "use": "enc",
        "x": JWK_X,
    });
    let jwk_str = jwk.to_string();
    let jwk_b64 = Base64UrlUnpadded::encode_string(jwk_str.as_bytes());

    format!("did:jwk:{jwk_b64}")
}
