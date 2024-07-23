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
    async fn get(&self, url: &str) -> anyhow::Result<Vec<u8>> {
        reqwest::get(url).await?.bytes().await.map_err(|e| anyhow!("{e}")).map(|b| b.to_vec())
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

const JWK_X: &str = "3Lg9yviAmTDCuVOyLXI3lq9S2pHm73yr3wwAkjwCAhw";
const HOLDER_SECRET: &str = "Y1KNbzOcX112pXI3v6sFvcr8uBLw4Pc2ciZTWdZx-As";

#[derive(Default, Clone, Debug)]
pub struct HolderKeystore;

impl HolderKeystore {
    pub fn algorithm() -> Algorithm {
        Algorithm::EdDSA
    }

    pub fn verification_method() -> String {
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "x": JWK_X,
        });
        let jwk_str = jwk.to_string();
        let jwk_b64 = Base64UrlUnpadded::encode_string(jwk_str.as_bytes());

        let did = format!("did:jwk:{jwk_b64}");
        format!("{}#0", did)
    }

    pub fn try_sign(msg: &[u8]) -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(HOLDER_SECRET)?;
        let bytes: [u8; 32] = decoded.as_slice().try_into().expect("should convert ");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let signature: ed25519_dalek::Signature = signing_key.sign(msg);
        Ok(signature.to_vec())
    }
}

// TODO: rename this to try_verify()
pub async fn deref_jwk(did_url: &str) -> Result<PublicKeyJwk> {
    let did = did_url.split('#').next().ok_or_else(|| anyhow!("Unable to parse DID"))?;

    if did.starts_with("did:web") || did.starts_with("did:key") {
        let client = Client {};
        let resp = did::resolve(did, None, client).await?;

        let Some(document) = resp.document else {
            bail!("Unable to resolve DID document");
        };
        let Some(verifcation_methods) = document.verification_method else {
            bail!("Unable to find verification method in DID document");
        };

        let vm = &verifcation_methods[0];
        return vm.public_key.to_jwk().map_err(|e| anyhow!("{e}"));
    }

    // if have long-form DID then try to extract key from metadata
    let did_parts = did.split(':').collect::<Vec<&str>>();

    // if DID is a JWK then return it
    if did.starts_with("did:jwk:") {
        let decoded = Base64UrlUnpadded::decode_vec(did_parts[2])
            .map_err(|e| anyhow!("Unable to decode DID: {e}"))?;
        return serde_json::from_slice::<PublicKeyJwk>(&decoded).map_err(anyhow::Error::from);
    }

    // HACK: for now, assume DID is long-form with delta operation containing public key
    // TODO: use vercre-did crate to dereference DID URL

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

    serde_json::from_value(pk_val.clone()).map_err(anyhow::Error::from)
}
