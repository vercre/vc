//! # DID Key Resolver
//!
//! https://w3c-ccg.github.io/did-method-key/#create

use crate::document::{Context, DidDocument, StrMap, VerificationMethod};
use crate::{DidResolution, DidResolutionMetadata, DidResolver, ResolutionOptions};

pub struct DidJwk;

impl DidResolver for DidJwk {
    fn resolve(&self, did: &str, _opts: impl ResolutionOptions) -> anyhow::Result<DidResolution> {
        let doc = DidDocument {
            context: vec![Context::String("https://www.w3.org/ns/did/v1".into())],
            id: did.to_string(),
            verification_method: Some(vec![VerificationMethod {
                id: format!("{}#{}", did, did),
                type_: "Ed25519VerificationKey2020".to_string(),
                controller: did.to_string(),

                public_key_multibase: Some(did.to_string()),
                ..VerificationMethod::default()
            }]),
            authentication: Some(vec![StrMap::String(did.to_string())]),
            assertion_method: Some(vec![StrMap::String(did.to_string())]),

            ..DidDocument::default()
        };

        Ok(DidResolution {
            did_document: doc,
            did_resolution_metadata: DidResolutionMetadata::default(),
            did_document_metadata: Default::default(),
        })
    }

    fn resolve_representation(
        &self, _did: &str, _opts: impl ResolutionOptions,
    ) -> anyhow::Result<DidResolution> {
        unimplemented!()
    }
}

// {
//   "@context": [
//     "https://www.w3.org/ns/did/v1",
//     "https://w3id.org/security/suites/ed25519-2020/v1",
//     "https://w3id.org/security/suites/x25519-2020/v1"
//   ],
//   "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
//   "verificationMethod": [{
//     "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
//     "type": "Ed25519VerificationKey2020",
//     "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
//     "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
//   }],
//   "authentication": [
//     "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
//   ],
//   "assertionMethod": [
//     "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
//   ],
//   "capabilityDelegation": [
//     "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
//   ],
//   "capabilityInvocation": [
//     "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
//   ],
//   "keyAgreement": [{
//     "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p",
//     "type": "X25519KeyAgreementKey2020",
//     "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
//     "publicKeyMultibase": "z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p"
//   }]
// }
