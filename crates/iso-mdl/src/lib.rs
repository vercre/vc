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

mod cbor;
mod cose;
mod mdoc;
mod mso;
mod tag24;

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded as Base64, Encoding};
use coset::{iana, CoseSign1Builder, HeaderBuilder};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use vercre_datasec::{Algorithm, Signer};
use vercre_openid::issuer::Dataset;

use crate::cose::{CoseKey, OKPCurve, Tagged};
use crate::mdoc::{IssuerSigned, IssuerSignedItem};
use crate::mso::{DigestIdGenerator, MobileSecurityObject};
use crate::tag24::Tag24;

/// Convert a Credential Dataset to a base64url-encoded, CBOR-encoded, ISO mDL
/// `IssuerSigned` object.
///
/// # Errors
/// // TODO: add errors
pub async fn to_credential(dataset: Dataset, signer: impl Signer) -> anyhow::Result<String> {
    // populate mdoc and accompanying MSO
    let mut mdoc = IssuerSigned::new();
    let mut mso = MobileSecurityObject::new();

    for (key, value) in dataset.claims {
        // namespace is a root-level claim
        let Some(name_space) = value.as_object() else {
            return Err(anyhow!("invalid dataset"));
        };

        let mut id_gen = DigestIdGenerator::new();

        // assemble `IssuerSignedItem`s for name space
        for (k, v) in name_space {
            let item = Tag24::new(IssuerSignedItem {
                digest_id: id_gen.gen(),
                random: thread_rng().gen::<[u8; 16]>().into(),
                element_identifier: k.clone(),
                element_value: ciborium::cbor!(v)?,
            })?;

            // digest of `IssuerSignedItem` for MSO
            let digest = Sha256::digest(&item.inner_bytes).to_vec();
            mso.value_digests.entry(key.clone()).or_default().insert(item.inner.digest_id, digest);

            // add item to IssuerSigned object
            mdoc.name_spaces.entry(key.clone()).or_default().push(item);
        }
    }

    // add public key to MSO
    mso.device_key_info.device_key = CoseKey::OKP {
        crv: OKPCurve::Ed25519,
        x: signer.public_key().await?,
    };

    // sign
    let mso_bytes = cbor::to_vec(&Tag24::new(mso)?)?;
    let signature = signer.sign(&mso_bytes).await;

    let algorithm = match signer.algorithm() {
        Algorithm::EdDSA => iana::Algorithm::EdDSA,
        _ => iana::Algorithm::EdDSA,
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

    let serialized = cbor::to_vec(&Tagged::new(false, cose_sign_1))?;

    Ok(Base64::encode_string(&serialized))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use vercre_datasec::SecOps;
    use vercre_test_utils::issuer::{Provider, CREDENTIAL_ISSUER};

    use crate::to_credential;

    #[tokio::test]
    async fn issuer_signed() {
        let dataset = json!({
            "claims": {
                "org.iso.18013.5.1.mDL": {
                    "given_name": "Normal",
                    "family_name": "Person",
                    "email": "normal.user@example.com"
                }
            }
        });
        let dataset = serde_json::from_value(dataset).unwrap();

        let provider = Provider::new();
        let signer = SecOps::signer(&provider, CREDENTIAL_ISSUER).unwrap();

        to_credential(dataset, signer).await.unwrap();

        // let slice = include_bytes!("../data/mso_mdoc.cbor");
        // let value: Value = ciborium::from_reader(Cursor::new(&slice)).unwrap();

        // 1. Pass in CredentialConfiguration + Dataset
    }
}
