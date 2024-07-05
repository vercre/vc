//! # DID Key Operations
//!
//! Implements Create, Read, Update, Delete (CRUD) operations for DID Key.
//!
//! See <https://w3c-ccg.github.io/did-method-key>

use std::sync::LazyLock;

use base64ct::{Base64UrlUnpadded, Encoding};
use core_utils::Kind;
use curve25519_dalek::edwards::CompressedEdwardsY;
use multibase::Base::Base58Btc;
use regex::Regex;
use serde_json::json;

use super::DidKey;
use crate::did::{self, Error};
use crate::document::{
    CreateOptions, Document, Operator, PublicKey, PublicKeyFormat, VerificationMethod,
};
use proof::jose::jwk::{Curve, KeyType, PublicKeyJwk};

const ED25519_CODEC: [u8; 2] = [0xed, 0x01];
const X25519_CODEC: [u8; 2] = [0xec, 0x01];

static DID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^did:key:(?<key>z[a-km-zA-HJ-NP-Z1-9]+)$").expect("should compile")
});

impl Operator for DidKey {
    fn create(&self, did: &str, options: CreateOptions) -> did::Result<Document> {
        // check DID is valid AND extract key
        let Some(caps) = DID_REGEX.captures(did) else {
            return Err(Error::InvalidDid("DID is not a valid did:key".into()));
        };
        let multi_key = &caps["key"];

        // decode the the DID key
        let (_, key_bytes) = multibase::decode(multi_key)
            .map_err(|e| Error::InvalidDid(format!("issue decoding key: {e}")))?;
        if key_bytes.len() - 2 != 32 {
            return Err(Error::InvalidDid("invalid key length".into()));
        }
        if key_bytes[0..2] != ED25519_CODEC {
            return Err(Error::InvalidDid("unsupported signature".into()));
        }

        let (context, public_key) = if options.public_key_format == PublicKeyFormat::Multikey
            || options.public_key_format == PublicKeyFormat::Ed25519VerificationKey2020
        {
            (
                Kind::Simple("https://w3id.org/security/data-integrity/v1".into()),
                PublicKey::Multibase(multi_key.into()),
            )
        } else {
            let verif_type = &options.public_key_format;
            (
                Kind::Rich(json!({
                    "publicKeyJwk": {
                        "@id": "https://w3id.org/security#publicKeyJwk",
                        "@type": "@json"
                    },
                    verif_type.to_string(): format!("https://w3id.org/security#{verif_type}"),
                })),
                PublicKey::Jwk(PublicKeyJwk {
                    kty: KeyType::OKP,
                    crv: Curve::Ed25519,
                    x: Base64UrlUnpadded::encode_string(&key_bytes[2..]),
                    ..PublicKeyJwk::default()
                }),
            )
        };

        // key agreement
        // <https://w3c-ccg.github.io/did-method-key/#encryption-method-creation-algorithm>
        let key_agreement = if options.enable_encryption_key_derivation {
            // derive an X25519 public encryption key from the Ed25519 key
            let edwards_y = CompressedEdwardsY::from_slice(&key_bytes[2..]).map_err(|e| {
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
            let ek_multibase = multibase::encode(Base58Btc, &multi_bytes);

            Some(vec![Kind::Rich(VerificationMethod {
                id: format!("{did}#{ek_multibase}"),
                type_: options.public_key_format.clone(),
                controller: did.into(),
                public_key: PublicKey::Multibase(ek_multibase),
                ..VerificationMethod::default()
            })])
        } else {
            None
        };

        let kid = format!("{did}#{multi_key}");

        Ok(Document {
            context: vec![Kind::Simple(options.default_context), context],
            id: did.into(),
            verification_method: Some(vec![VerificationMethod {
                id: kid.clone(),
                type_: options.public_key_format,
                controller: did.into(),
                public_key,
                ..VerificationMethod::default()
            }]),
            authentication: Some(vec![Kind::Simple(kid.clone())]),
            assertion_method: Some(vec![Kind::Simple(kid.clone())]),
            capability_invocation: Some(vec![Kind::Simple(kid.clone())]),
            capability_delegation: Some(vec![Kind::Simple(kid)]),
            key_agreement,
            ..Document::default()
        })
    }

    fn read(&self, did: &str, options: CreateOptions) -> did::Result<Document> {
        self.create(did, options)
    }

    fn update(&self, _did: &str, _: CreateOptions) -> did::Result<Document> {
        unimplemented!("This DID Method does not support updating the DID Document")
    }

    fn deactivate(&self, _did: &str, _: CreateOptions) -> did::Result<()> {
        unimplemented!("This DID Method does not support deactivating the DID Document")
    }
}

#[cfg(test)]
mod test {
    // use std::sync::LazyLock;

    // use serde_json::{json, Value};

    // use super::*;

    // #[test]
    // fn resolve() {
    //     let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    //     let resolved = DidKey.resolve(did, None).expect("should resolve");

    //     let document: Document =
    //         serde_json::from_value(DOCUMENT.to_owned()).expect("should deserialize");
    //     assert_eq!(resolved.document, Some(document));

    //     let metadata: Metadata =
    //         serde_json::from_value(METADATA.to_owned()).expect("should deserialize");
    //     assert_eq!(resolved.metadata, metadata);
    // }

    // static DID_URL: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    // static DOCUMENT: LazyLock<Value> = LazyLock::new(|| {
    //     json!({
    //         "@context": [
    //             "https://www.w3.org/ns/did/v1",
    //             {
    //                 "Ed25519VerificationKey2020": "https://w3id.org/security#Ed25519VerificationKey2020",
    //                 "publicKeyJwk": {
    //                     "@id": "https://w3id.org/security#publicKeyJwk",
    //                     "@type": "@json"
    //                 }
    //             }
    //         ],
    //         "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    //         "verificationMethod": [
    //             {
    //                 "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    //                 "type": "Ed25519VerificationKey2020",
    //                 "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    //                 "publicKeyJwk": {
    //                     "kty": "OKP",
    //                     "crv": "Ed25519",
    //                     "x": "Lm_M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY"
    //                 }
    //             }
    //         ],
    //         "authentication": [
    //             "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    //         ],
    //         "assertionMethod": [
    //             "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    //         ]
    //     })
    // });
    // static METADATA: LazyLock<Value> = LazyLock::new(|| {
    //     json!({
    //       "contentType": "application/did+ld+json",
    //       "pattern": "^did:key:z[a-km-zA-HJ-NP-Z1-9]+$",
    //       "did": {
    //         "didString": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    //         "methodSpecificId": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    //         "method": "key"
    //       }
    //     })
    // });
}
