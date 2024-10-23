//! # Verifiable Credentials
//!
//! This crate provides common utilities for the Vercre project and is not
//! intended to be used directly.
//!
//! This library encompasses the family of W3C Recommendations for Verifiable
//! Credentials, as outlined below.
//!
//! The recommendations provide a mechanism to express credentials on the Web in
//! a way that is cryptographically secure, privacy respecting, and
//! machine-verifiable.

mod mdoc;
mod mso;

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded as Base64, Encoding};
use ciborium::cbor;
use coset::{iana, CoseSign1Builder, HeaderBuilder};
use rand::{thread_rng, Rng};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use vercre_infosec::cose::{CoseKey, Tag24};
use vercre_infosec::{Algorithm, Curve, KeyType, Signer};

use crate::mdoc::{IssuerSigned, IssuerSignedItem};
use crate::mso::{DigestIdGenerator, MobileSecurityObject};

/// Convert a Credential Dataset to a base64url-encoded, CBOR-encoded, ISO mDL
/// `IssuerSigned` object.
///
/// # Errors
/// // TODO: add errors
pub async fn to_credential(
    dataset: Map<String, Value>, signer: impl Signer,
) -> anyhow::Result<String> {
    // populate mdoc and accompanying MSO
    let mut mdoc = IssuerSigned::new();
    let mut mso = MobileSecurityObject::new();

    for (key, value) in dataset {
        // namespace is a root-level claim
        let Some(name_space) = value.as_object() else {
            return Err(anyhow!("invalid dataset"));
        };

        let mut id_gen = DigestIdGenerator::new();

        // assemble `IssuerSignedItem`s for name space
        for (k, v) in name_space {
            let item = Tag24(IssuerSignedItem {
                digest_id: id_gen.gen(),
                random: thread_rng().gen::<[u8; 16]>().into(),
                element_identifier: k.clone(),
                element_value: cbor!(v)?,
            });

            // digest of `IssuerSignedItem` for MSO
            let digest = Sha256::digest(&item.to_vec()?).to_vec();
            mso.value_digests.entry(key.clone()).or_default().insert(item.digest_id, digest);

            // add item to IssuerSigned object
            mdoc.name_spaces.entry(key.clone()).or_default().push(item);
        }
    }

    // add public key to MSO
    mso.device_key_info.device_key = CoseKey {
        kty: KeyType::Okp,
        crv: Curve::Ed25519,
        x: signer.public_key().await?,
        y: None,
    };

    // sign
    let mso_bytes = Tag24(mso).to_vec()?;
    let signature = signer.sign(&mso_bytes).await;

    // build COSE_Sign1
    let algorithm = match signer.algorithm() {
        Algorithm::EdDSA => iana::Algorithm::EdDSA,
        Algorithm::ES256K => return Err(anyhow!("unsupported algorithm")),
    };

    let key_id = signer.verification_method().as_bytes().to_vec();

    let protected = HeaderBuilder::new().algorithm(algorithm).build();
    let unprotected = HeaderBuilder::new().key_id(key_id).build();
    let cose_sign_1 = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(mso_bytes)
        .signature(signature)
        .build();

    // add COSE_Sign1 to IssuerSigned object
    mdoc.issuer_auth = mso::IssuerAuth(cose_sign_1);

    // encode CBOR -> Base64Url -> return
    Ok(Base64::encode_string(&mdoc.to_vec()?))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use test_utils::issuer::{Provider, CREDENTIAL_ISSUER};
    use vercre_infosec::cose::cbor;
    use vercre_infosec::KeyOps;

    use super::*;
    use crate::mso::DigestAlgorithm;
    use crate::to_credential;

    #[tokio::test]
    async fn roundtrip() {
        let dataset = json!({
            "org.iso.18013.5.1.mDL": {
                "given_name": "Normal",
                "family_name": "Person",
                "email": "normal.user@example.com"
            }
        });

        // generate mdl credential
        let dataset = serde_json::from_value(dataset).unwrap();
        let provider = Provider::new();
        let signer = KeyOps::signer(&provider, CREDENTIAL_ISSUER).unwrap();
        let mdl = to_credential(dataset, signer).await.unwrap();
        // println!("{}", mdl);

        // check credential deserializes back into original mdoc/mso structures
        let mdoc_bytes = Base64::decode_vec(&mdl).expect("should decode");
        let mdoc: IssuerSigned = cbor::from_slice(&mdoc_bytes).expect("should deserialize");
        println!("{:?}", mdoc);

        let mso_bytes = mdoc.issuer_auth.0.payload.expect("should have payload");
        let mso: MobileSecurityObject = cbor::from_slice(&mso_bytes).expect("should deserialize");
        println!("{:?}", mso);

        assert_eq!(mso.digest_algorithm, DigestAlgorithm::Sha256);
        assert_eq!(mso.device_key_info.device_key.kty, KeyType::Okp);
    }
}
