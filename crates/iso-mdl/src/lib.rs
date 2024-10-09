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
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use vercre_datasec::Signer;
use vercre_openid::issuer::Dataset;

use crate::mdoc::IssuerSignedItem;
use crate::tag24::Tag24;

/// Convert a Credential Dataset to a base64url-encoded CBOR-encoded ISO mDL
/// `IssuerSigned` object.
///
/// # Errors
/// // TODO: add errors
pub fn to_iso_mdl(dataset: Dataset, _signer: impl Signer) -> anyhow::Result<String> {
    // ValueDigests:
    // - create digest of each configured data element

    let mut mdoc = mdoc::IssuerSigned::new();
    let mut mso = mso::MobileSecurityObject::new();

    for (key, value) in dataset.claims {
        // namespace should be root level claim
        let Some(name_space) = value.as_object() else {
            return Err(anyhow!("invalid dataset"));
        };

        let mut id_gen = mso::DigestIdGenerator::new();

        // assemble `IssuerSignedItem`s for name space
        for (k, v) in name_space {
            let item = Tag24::new(IssuerSignedItem {
                digest_id: id_gen.gen(),
                random: thread_rng().gen::<[u8; 16]>().into(),
                element_identifier: k.clone(),
                element_value: ciborium::cbor!(v)?,
            })?;

            // digest of item for MSO
            let digest = Sha256::digest(&item.inner_bytes).to_vec();
            mso.value_digests.entry(key.clone()).or_default().insert(item.inner.digest_id, digest);

            // add item to IssuerSigned object
            mdoc.name_spaces.entry(key.clone()).or_default().push(item);
        }
    }

    // DeviceKeyInfo
    // - use Signer to provide Issuer public key

    // IssuerAuth
    // - assemble MSO and sign with Issuer key

    // IssuerSigned
    // - set `issuer_auth` param
    // - serialize to CBOR
    // - base64 encode

    println!("issuer_signed: {mdoc:?}");

    Ok(String::new())
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use vercre_datasec::SecOps;
    use vercre_test_utils::issuer::{Provider, CREDENTIAL_ISSUER};

    use crate::to_iso_mdl;

    #[test]
    fn issuer_signed() {
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

        to_iso_mdl(dataset, signer).unwrap();

        // let slice = include_bytes!("../data/mso_mdoc.cbor");
        // let value: Value = ciborium::from_reader(Cursor::new(&slice)).unwrap();

        // 1. Pass in CredentialConfiguration + Dataset
    }
}
