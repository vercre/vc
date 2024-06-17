use anyhow::{anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
use ecdsa::signature::Signer as _;
use ecdsa::{Signature, SigningKey};
use k256::Secp256k1;
use vercre_issuer::provider::{Jwk, Result};

// Issuer & Verifier private key
const JWK_D: &str = "0Md3MhPaKEpnKAyKE498EdDFerD5NLeKJ5Rb-vC16Gs";

#[derive(Default, Clone, Debug)]
pub struct Enclave;

impl Enclave {
    pub fn try_sign(msg: &[u8]) -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(JWK_D)?;
        let signing_key: SigningKey<Secp256k1> = SigningKey::from_slice(&decoded)?;
        let sig: Signature<Secp256k1> = signing_key.sign(msg);
        Ok(sig.to_vec())
    }

    pub fn deref_jwk(did_url: impl AsRef<str>) -> anyhow::Result<Jwk> {
        let did =
            did_url.as_ref().split('#').next().ok_or_else(|| anyhow!("Unable to parse DID"))?;

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
