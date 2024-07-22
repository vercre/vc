//! # DID Web Operations
//!
//! Implements Create, Read, Update, Delete (CRUD) operations for DID Key.
//!
//! See <https://w3c-ccg.github.io/did-method-web>

use base64ct::{Base64UrlUnpadded, Encoding};
use core_utils::Kind;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::SigningKey;
use multibase::Base;
use rand::rngs::OsRng;
use url::Url;

use super::DidWeb;
use crate::did::{self, Error};
use crate::document::{CreateOptions, Document, PublicKey, VerificationMethod};

const ED25519_CODEC: [u8; 2] = [0xed, 0x01];
const X25519_CODEC: [u8; 2] = [0xec, 0x01];

impl DidWeb {
    pub fn new() -> Self {
        Self
    }

    pub fn create(&self, url: &str, options: CreateOptions) -> did::Result<Document> {
        // create identifier from url
        let url =
            Url::parse(url).map_err(|e| Error::InvalidDid(format!("issue parsing url: {e}")))?;
        let host = url.host_str().ok_or(Error::InvalidDid("no host in url".into()))?;
        let mut did = format!("did:web:{host}");
        if let Some(path) = url.path().strip_prefix('/')
            && !path.is_empty()
        {
            did = format!("{did}{}", path.replace('/', ":"));
        }

        // generate a key pair
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);

        let secret = Base64UrlUnpadded::encode_string(signing_key.as_bytes());
        println!("signing: {secret}");

        // multibase encode the public key
        let mut multi_bytes = vec![];
        multi_bytes.extend_from_slice(&ED25519_CODEC);
        multi_bytes.extend_from_slice(signing_key.verifying_key().as_bytes());
        let multi_key = multibase::encode(Base::Base58Btc, &multi_bytes);

        let context = Kind::String("https://w3id.org/security/data-integrity/v1".into());
        let public_key = PublicKey::Multibase(multi_key.into());

        // key agreement
        // <https://w3c-ccg.github.io/did-method-key/#encryption-method-creation-algorithm>
        let key_agreement = if options.enable_encryption_key_derivation {
            let key_bytes = signing_key.verifying_key().to_bytes();

            // derive an X25519 public encryption key from the Ed25519 key
            let edwards_y = CompressedEdwardsY::from_slice(&key_bytes).map_err(|e| {
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
            let ek_multibase = multibase::encode(Base::Base58Btc, &multi_bytes);

            Some(vec![Kind::Object(VerificationMethod {
                id: format!("{did}#{ek_multibase}"),
                type_: options.public_key_format.clone(),
                controller: did.clone().into(),
                public_key: PublicKey::Multibase(ek_multibase),
                ..VerificationMethod::default()
            })])
        } else {
            None
        };

        let kid = format!("{did}#key-0");

        Ok(Document {
            context: vec![Kind::String(options.default_context), context],
            id: did.clone(),
            verification_method: Some(vec![VerificationMethod {
                id: kid.clone(),
                type_: options.public_key_format,
                controller: did,
                public_key,
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

    pub fn read(&self, did: &str, options: CreateOptions) -> did::Result<Document> {
        self.create(did, options)
    }

    pub fn update(&self, _did: &str, _: CreateOptions) -> did::Result<Document> {
        unimplemented!("This DID Method does not support updating the DID Document")
    }

    pub fn deactivate(&self, _did: &str, _: CreateOptions) -> did::Result<()> {
        unimplemented!("This DID Method does not support deactivating the DID Document")
    }
}

#[cfg(test)]
mod test {
    // use std::sync::LazyLock;

    // use serde_json::{json, Value};

    use super::*;

    #[test]
    fn create() {
        let url = "https://demo.credibil.io";
        let mut options = CreateOptions::default();
        options.enable_encryption_key_derivation = true;

        let res = DidWeb::new().create(url, options).expect("should create");

        let json = serde_json::to_string(&res).expect("should serialize");
        println!("{json}");
    }
}
