use anyhow::{anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
// use ecdsa::{Signature, Signer as _, SigningKey};
use ed25519_dalek::Signer;
use ed25519_dalek::{SecretKey, SigningKey};
// use k256::Secp256k1;
use openid::provider::Result;
use datasec::jose::jwa::Algorithm;
use datasec::jose::jwk::PublicKeyJwk;

// Mock DID client
struct Client {}
impl did::DidClient for Client {
    async fn get(&self, _url: &str) -> anyhow::Result<Vec<u8>> {
        // reqwest::get(url).await?.bytes().await.map_err(|e| anyhow!("{e}")).map(|b| b.to_vec())
        Ok(include_bytes!("did.json").to_vec())
    }
}

#[derive(Default, Clone, Debug)]
pub struct IssuerKeystore;

const ISSUER_DID: &str = "did:web:demo.credibil.io";
const ISSUER_VERIFY_KEY: &str = "key-0";
const ISSUER_SECRET: &str = "cCxmHfFfIJvP74oNKjAuRC3zYoDMo0pFsAs19yKMowY";

impl IssuerKeystore {
    pub fn algorithm() -> Algorithm {
        Algorithm::EdDSA
    }

    pub fn verification_method() -> String {
        format!("{ISSUER_DID}#{ISSUER_VERIFY_KEY}")
    }

    pub fn try_sign(msg: &[u8]) -> Result<Vec<u8>> {
        // let decoded = Base64UrlUnpadded::decode_vec(SECRET_KEY)?;
        // let signing_key: SigningKey<Secp256k1> = SigningKey::from_slice(&decoded)?;
        // Ok(signing_key.sign(msg).to_vec())

        let decoded = Base64UrlUnpadded::decode_vec(ISSUER_SECRET)?;
        let secret_key: SecretKey =
            decoded.try_into().map_err(|_| anyhow!("Invalid secret key"))?;
        let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);
        Ok(signing_key.sign(msg).to_bytes().to_vec())
    }
}

#[derive(Default, Clone, Debug)]
pub struct VerifierKeystore;

const VERIFIER_DID: &str = "did:web:demo.credibil.io";
const VERIFIER_VERIFY_KEY: &str = "key-0";
const VERIFIER_SECRET: &str = "cCxmHfFfIJvP74oNKjAuRC3zYoDMo0pFsAs19yKMowY";

impl VerifierKeystore {
    pub fn algorithm() -> Algorithm {
        Algorithm::EdDSA
    }

    pub fn verification_method() -> String {
        format!("{VERIFIER_DID}#{VERIFIER_VERIFY_KEY}")
    }

    pub fn try_sign(msg: &[u8]) -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(VERIFIER_SECRET)?;
        let secret_key: SecretKey =
            decoded.try_into().map_err(|_| anyhow!("Invalid secret key"))?;
        let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);
        Ok(signing_key.sign(msg).to_bytes().to_vec())
    }
}

const HOLDER_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
const HOLDER_VERIFY_KEY: &str = "z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
const HOLDER_SECRET: &str = "8rmFFiUcTjjrL5mgBzWykaH39D64VD0mbDHwILvsu30";

#[derive(Default, Clone, Debug)]
pub struct HolderKeystore;

impl HolderKeystore {
    pub fn algorithm() -> Algorithm {
        Algorithm::EdDSA
    }

    pub fn verification_method() -> String {
        format!("{HOLDER_DID}#{HOLDER_VERIFY_KEY}")
    }

    pub fn try_sign(msg: &[u8]) -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(HOLDER_SECRET)?;
        let bytes: [u8; 32] = decoded.as_slice().try_into().expect("should convert ");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let signature: ed25519_dalek::Signature = signing_key.sign(msg);
        Ok(signature.to_vec())
    }
}

/// Dereference DID URL to public key. For example,  did:web:demo.credibil.io#key-0.
///
/// did:web:demo.credibil.io -> did:web:demo.credibil.io/.well-known/did.json
/// did:web:demo.credibil.io:entity:supplier -> did:web:demo.credibil.io/entity/supplier/did.json
pub async fn deref_jwk(did_url: &str) -> Result<PublicKeyJwk> {
    let resp = did::dereference(did_url, None, Client {}).await?;

    // get public key specified by the url fragment
    let Some(did::Resource::VerificationMethod(vm)) = resp.content_stream else {
        bail!("Verification method not found");
    };

    Ok(vm.public_key.jwk()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_deref_jwk() {
        let did_url = "did:web:demo.credibil.io#key-0";
        let jwk = deref_jwk(did_url).await.unwrap();
        println!("{:?}", jwk);
        // assert_eq!(jwk.kty, "OKP");
        // assert_eq!(jwk.crv, "Ed25519");
        // assert_eq!(jwk.x, "cCxmHfFfIJvP74oNKjAuRC3zYoDMo0pFsAs19yKMowY");
    }
}
