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

pub mod cose;
pub mod mdoc;
pub mod mso;
pub use anyhow::anyhow;
mod bytes;
mod cbor;
mod tag24;

use std::collections::HashSet;

use coset::{self, CoseError};
use rand::Rng;
use sha2::{Digest, Sha256};
use vercre_openid::issuer::{Dataset, ProfileIsoMdl};

pub type Result<T> = std::result::Result<T, anyhow::Error>;

/// Convert a Credential Dataset to a base64url-encoded CBOR-encoded ISO mDL
/// IssuerSigned object.
pub fn to_iso_mdl(dataset: Dataset, configuration: ProfileIsoMdl) -> Result<String> {
    // ValueDigests:
    // - create digest of each configured data element
    let mut value_digests = mso::ValueDigests::new();
    let mut gen = Generator::new();

    for (key, value) in dataset.claims {
        // generate digests for a namespace
        let mut digests_ids = mso::DigestIds::new();
        let Some(ns_claims) = value.as_object() else {
            continue;
        };

        for (k, v) in ns_claims {
            let rnd_id = gen.gen_id();

            let item = tag24::Tag24::new(mdoc::IssuerSignedItem {
                digest_id: rnd_id,
                random: rnd_id.to_string(),
                element_identifier: k.clone(),
                element_value: ciborium::Value::Null,
            })?;
            let bytes = to_vec(&item).map_err(|e| anyhow!("{e}"))?;

            let digest = Sha256::digest(&bytes).to_vec();
            digests_ids.insert(rnd_id, digest);
        }

        value_digests.insert(key, digests_ids);
    }

    // IssuerSignedItems
    // - create IssuerSignedItem for each item in Dataset, referencing
    // - index of item in ValueDigests array

    // DeviceKeyInfo
    // - use Signer to provide Issuer public key

    // IssuerAuth
    // - assemble MSO and sign with Issuer key

    // IssuerSigned
    // - set `issuer_auth` param
    // - serialize to CBOR
    // - base64 encode

    todo!()
}

pub fn to_vec<T>(value: &T) -> std::result::Result<Vec<u8>, CoseError>
where
    T: serde::Serialize,
{
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|_| CoseError::EncodeFailed)?;
    Ok(buf)
}

struct Generator {
    used_ids: HashSet<mso::DigestId>,
}

impl Generator {
    fn new() -> Self {
        Self {
            used_ids: HashSet::new(),
        }
    }

    fn gen_id(&mut self) -> mso::DigestId {
        let mut digest_id;
        loop {
            digest_id = rand::thread_rng().gen();
            if self.used_ids.insert(digest_id) {
                return digest_id;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use ciborium::Value;

    #[test]
    fn issuer_signed() {
        // let slice = include_bytes!("../data/mso_mdoc.cbor");
        // let value: Value = ciborium::from_reader(Cursor::new(&slice)).unwrap();

        // 1. Pass in CredentialConfiguration + Dataset
    }
}
