//! # DID Web Operations
//!
//! Implements Create, Read, Update, Delete (CRUD) operations for DID Key.
//!
//! See <https://w3c-ccg.github.io/did-method-web>

use base64ct::{Base64UrlUnpadded, Encoding};
use curve25519_dalek::edwards::CompressedEdwardsY;
// use ecdsa::signature::Signer as _;
use ed25519_dalek::SigningKey;
// use k256::Secp256k1;
use multibase::Base;
use rand::rngs::OsRng;
use url::Url;
use vercre_core_utils::Kind;

use super::DidWeb;
use crate::did;
use crate::did::document::{
    CreateOptions, Document, MethodType, PublicKeyFormat, VerificationMethod,
};
use crate::did::error::Error;

#[allow(dead_code)]
const ED25519_CODEC: [u8; 2] = [0xed, 0x01];
#[allow(dead_code)]
const X25519_CODEC: [u8; 2] = [0xec, 0x01];

impl DidWeb {
    // HACK: generate a key pair
    #[allow(dead_code)]
    pub fn generate() -> Vec<u8> {
        // TODO: pass in public key
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        let secret = Base64UrlUnpadded::encode_string(signing_key.as_bytes());
        println!("signing: {secret}");

        signing_key.verifying_key().to_bytes().to_vec()
    }

    #[allow(dead_code)]
    pub fn create(
        url: &str, verifying_key: &[u8], options: CreateOptions,
    ) -> did::Result<Document> {
        // create identifier from url
        let url =
            Url::parse(url).map_err(|e| Error::InvalidDid(format!("issue parsing url: {e}")))?;
        let host = url.host_str().ok_or(Error::InvalidDid("no host in url".into()))?;
        let mut did = format!("did:web:{host}");
        if let Some(path) = url.path().strip_prefix('/')
            && !path.is_empty()
        {
            did = format!("{did}:{}", path.replace('/', ":"));
        }

        // multibase encode the public key
        let mut multi_bytes = vec![];
        multi_bytes.extend_from_slice(&ED25519_CODEC);
        multi_bytes.extend_from_slice(verifying_key);
        let multikey = multibase::encode(Base::Base58Btc, &multi_bytes);

        let context = Kind::String("https://w3id.org/security/data-integrity/v1".into());
        // let multikey = PublicKey::Multibase(multi_key);

        // key agreement
        // <https://w3c-ccg.github.io/did-method-key/#encryption-method-creation-algorithm>
        let key_agreement = if options.enable_encryption_key_derivation {
            // derive an X25519 public encryption key from the Ed25519 key
            let edwards_y = CompressedEdwardsY::from_slice(verifying_key).map_err(|e| {
                Error::InvalidPublicKey(format!("public key is not Edwards Y: {e}"))
            })?;
            let Some(edwards_pt) = edwards_y.decompress() else {
                return Err(Error::InvalidPublicKey(
                    "Edwards Y cannot be decompressed to point".into(),
                ));
            };
            let x25519_bytes = edwards_pt.to_montgomery().to_bytes();

            // base58B encode the raw key
            let mut multi_bytes = vec![];
            multi_bytes.extend_from_slice(&X25519_CODEC);
            multi_bytes.extend_from_slice(&x25519_bytes);
            let multikey = multibase::encode(Base::Base58Btc, &multi_bytes);

            let method_type = match options.public_key_format {
                PublicKeyFormat::Multikey => MethodType::Multikey {
                    public_key_multibase: multikey,
                },
                _ => return Err(Error::InvalidPublicKey("Unsupported public key format".into())),
            };

            Some(vec![Kind::Object(VerificationMethod {
                id: format!("{did}#key-1"),
                controller: did.clone(),
                method_type,
                ..VerificationMethod::default()
            })])
        } else {
            None
        };

        let kid = format!("{did}#key-0");
        let method_type = match options.public_key_format {
            PublicKeyFormat::Multikey => MethodType::Multikey {
                public_key_multibase: multikey,
            },
            _ => return Err(Error::InvalidPublicKey("Unsupported public key format".into())),
        };

        Ok(Document {
            context: vec![Kind::String(options.default_context), context],
            id: did.clone(),
            verification_method: Some(vec![VerificationMethod {
                id: kid.clone(),
                controller: did,
                method_type,
                ..VerificationMethod::default()
            }]),
            authentication: Some(vec![Kind::String(kid.clone())]),
            assertion_method: Some(vec![Kind::String(kid.clone())]),
            capability_invocation: Some(vec![Kind::String(kid.clone())]),
            capability_delegation: Some(vec![Kind::String(kid)]),
            key_agreement,
            ..Document::default()
        })
    }

    #[allow(dead_code)]
    pub fn read(_did: &str, _: CreateOptions) -> did::Result<Document> {
        // self.create(did, options)
        unimplemented!("read")
    }

    #[allow(dead_code)]
    pub fn update(_did: &str, _: CreateOptions) -> did::Result<Document> {
        unimplemented!("This DID Method does not support updating the DID Document")
    }

    #[allow(dead_code)]
    pub fn deactivate(_did: &str, _: CreateOptions) -> did::Result<()> {
        unimplemented!("This DID Method does not support deactivating the DID Document")
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn create() {
        let url = "https://demo.credibil.io/entity/funder";
        let mut options = CreateOptions::default();
        options.enable_encryption_key_derivation = true;

        let verifying_key = DidWeb::generate();
        let res = DidWeb::create(url, &verifying_key, options).expect("should create");

        let json = serde_json::to_string_pretty(&res).expect("should serialize");
        println!("{json}");
    }

    #[test]
    fn create_2() {
        let url = "https://demo.credibil.io/entity/funder";
        let mut options = CreateOptions::default();
        options.enable_encryption_key_derivation = true;

        let verifying_key = DidWeb::generate();
        let res = DidWeb::create(url, &verifying_key, options).expect("should create");

        let json = serde_json::to_string_pretty(&res).expect("should serialize");
        println!("{json}");
    }
}
