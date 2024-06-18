//! Sample Signer implementation. This is a hard-coded signer for example purposes only. Real
//! implementations should use a secure key store and secure signing methods.

use anyhow::{anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use vercre_holder::provider::{Algorithm, Jwk, Result, Signer, Verifier};

use super::Provider;

const JWK_D: &str = "Y1KNbzOcX112pXI3v6sFvcr8uBLw4Pc2ciZTWdZx-As";
const JWK_X: &str = "3Lg9yviAmTDCuVOyLXI3lq9S2pHm73yr3wwAkjwCAhw";

impl Signer for Provider {
    /// Algorithm returns the algorithm used by the signer.
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }

    /// The verification method the verifier should use to verify the signer's
    /// signature. This is typically a DID URL + # + verification key ID.
    fn verification_method(&self) -> String {
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "use": "enc",
            "x": JWK_X,
        });
        let jwk_str = jwk.to_string();
        let jwk_b64 = Base64UrlUnpadded::encode_string(jwk_str.as_bytes());

        let holder_did = format!("did:jwk:{jwk_b64}");
        format!("{holder_did}#0")
    }

    /// Sign the payload.
    async fn try_sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(JWK_D)?;
        let bytes: [u8; 32] = decoded.as_slice().try_into().expect("should convert ");
        let signing_key = SigningKey::from_bytes(&bytes);
        let sig: Signature = signing_key.sign(msg);
        Ok(sig.to_vec())
    }
}

impl Verifier for Provider {
    async fn deref_jwk(&self, did_url: &str) -> Result<Jwk> {
        let did = did_url.split('#').next().ok_or_else(|| anyhow!("Unable to parse DID"))?;

        // if have long-form DID then try to extract key from metadata
        let did_parts = did.split(':').collect::<Vec<&str>>();

        // if DID is a JWK then return it
        if did.starts_with("did:jwk:") {
            let decoded = Base64UrlUnpadded::decode_vec(did_parts[2])
                .map_err(|e| anyhow!("Unable to decode DID: {e}"))?;
            return serde_json::from_slice::<Jwk>(&decoded).map_err(anyhow::Error::from);
        }

        // DID should be long-form ION
        if did_parts.len() != 4 {
            bail!("Short-form DID's are not supported");
        }

        let decoded = Base64UrlUnpadded::decode_vec(did_parts[3])
            .map_err(|e| anyhow!("Unable to decode DID: {e}"))?;
        let ion_op = serde_json::from_slice::<serde_json::Value>(&decoded)?;

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
