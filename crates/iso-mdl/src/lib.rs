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

use vercre_openid::issuer::{CredentialConfiguration, Dataset};

pub fn to_iso_mdl(configuration: CredentialConfiguration, dataset: Dataset) {

    // ValueDigests
    // - create digest of each configuration data element

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
