//! # DID Key Operations
//!
//! Implements Create, Read, Update, Delete (CRUD) operations for DID Key.
//!
//! See <https://w3c-ccg.github.io/did-method-key>

use base64ct::{Base64UrlUnpadded, Encoding};
use core_utils::Kind;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::SigningKey;
use jose::jwk::{Curve, KeyType, PublicKeyJwk};
use multibase::Base;
use rand::rngs::OsRng;
use serde_json::json;

use super::DidKey;
use crate::document::{CreateOptions, Document, PublicKey, PublicKeyFormat, VerificationMethod};
use crate::error::Error;

const ED25519_CODEC: [u8; 2] = [0xed, 0x01];
const X25519_CODEC: [u8; 2] = [0xec, 0x01];

impl DidKey {
    // HACK: generate a key pair
    pub fn generate() -> Vec<u8> {
        // TODO: pass in public key
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        let secret = Base64UrlUnpadded::encode_string(signing_key.as_bytes());
        println!("signing: {secret}");

        signing_key.verifying_key().to_bytes().to_vec()
    }

    pub fn create(verifying_key: &[u8], options: CreateOptions) -> crate::Result<Document> {
        let mut multi_bytes = vec![];
        multi_bytes.extend_from_slice(&ED25519_CODEC);
        multi_bytes.extend_from_slice(verifying_key);
        let multikey = multibase::encode(Base::Base58Btc, &multi_bytes);

        let did = format!("did:key:{multikey}");

        let (context, public_key) = if options.public_key_format == PublicKeyFormat::Multikey
            || options.public_key_format == PublicKeyFormat::Ed25519VerificationKey2020
        {
            (
                Kind::String("https://w3id.org/security/data-integrity/v1".into()),
                PublicKey::Multibase(multikey.clone()),
            )
        } else {
            let verif_type = &options.public_key_format;
            (
                Kind::Object(json!({
                    "publicKeyJwk": {
                        "@id": "https://w3id.org/security#publicKeyJwk",
                        "@type": "@json"
                    },
                    verif_type.to_string(): format!("https://w3id.org/security#{verif_type}"),
                })),
                PublicKey::Jwk(PublicKeyJwk {
                    kty: KeyType::Okp,
                    crv: Curve::Ed25519,
                    x: Base64UrlUnpadded::encode_string(verifying_key),
                    ..PublicKeyJwk::default()
                }),
            )
        };

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

            Some(vec![Kind::Object(VerificationMethod {
                id: format!("{did}#{multikey}"),
                type_: options.public_key_format.clone(),
                controller: did.clone(),
                public_key: PublicKey::Multibase(multikey),
                ..VerificationMethod::default()
            })])
        } else {
            None
        };

        let kid = format!("{did}#{multikey}");

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

    pub fn read(_did: &str, _: CreateOptions) -> crate::Result<Document> {
        // self.resolve(did, options)
        unimplemented!("read")
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn create() {
        let mut options = CreateOptions::default();
        options.enable_encryption_key_derivation = true;

        let verifying_key = DidKey::generate();
        let res = DidKey::create(&verifying_key, options).expect("should create");

        let json = serde_json::to_string(&res).expect("should serialize");
        println!("{json}");
    }
}
