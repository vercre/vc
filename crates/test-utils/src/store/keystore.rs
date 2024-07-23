use anyhow::{anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
// use ecdsa::signature::Signer as _;
// use ecdsa::{Signature, SigningKey};
use ed25519_dalek::Signer;
use ed25519_dalek::{SecretKey, SigningKey};
// use k256::Secp256k1;
use openid::provider::Result;
use proof::jose::jwa::Algorithm;
use proof::jose::jwk::PublicKeyJwk;

struct Client {}
impl did::DidClient for Client {
    async fn get(&self, _url: &str) -> anyhow::Result<Vec<u8>> {
        // reqwest::get(url).await?.bytes().await.map_err(|e| anyhow!("{e}")).map(|b| b.to_vec())
        let doc = serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/data-integrity/v1"
            ],
            "id": "did:web:demo.credibil.io",
            "verificationMethod": [{
                "id": "did:web:demo.credibil.io#key-0",
                "type": "Multikey",
                "controller": "did:web:demo.credibil.io",
                "publicKeyMultibase": "z6Mkr1NtupNezZtcUAMxJ79HPex6ZTR9RnGh8xfV257ZQdss"
            }],
            "authentication": [
                "did:web:demo.credibil.io#key-0"
            ],
            "assertionMethod": [
                "did:web:demo.credibil.io#key-0"
            ],
            "capabilityInvocation": [
                "did:web:demo.credibil.io#key-0"
            ],
            "capabilityDelegation": [
                "did:web:demo.credibil.io#key-0"
            ],
            "keyAgreement": [{
                "id": "did:web:demo.credibil.io#key-1",
                "type": "Multikey",
                "controller": "did:web:demo.credibil.io",
                "publicKeyMultibase": "z6LSo1jPr1g7qoR9UsYWoJs66FiaoHGAK5cJzBGSvQpuVEQv"
            }]
        });

        Ok(serde_json::to_vec(&doc)?)
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

// TODO: move this back into did crate
pub async fn deref_jwk(did_url: &str) -> Result<PublicKeyJwk> {
    // TODO: use did crate dereference to resolve DID URL
    let did = did_url.split('#').next().ok_or_else(|| anyhow!("Unable to parse DID"))?;

    let client = Client {};
    let resp = did::resolve(did, None, client).await?;

    let Some(document) = resp.document else {
        bail!("Unable to resolve DID document");
    };
    let Some(verifcation_methods) = document.verification_method else {
        bail!("Unable to find verification method in DID document");
    };

    let vm = &verifcation_methods[0];
    Ok(vm.public_key.to_jwk()?)
}
