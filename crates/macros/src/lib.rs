#![feature(let_chains)]

//! # Core Vercre `proc_macros`
//!
//! This crate provides external `proc_macro`s for use by Vercre implementers. It 
//! not intended to be used directly as the macros are re-exported from one  of the
//! top-level crates (`vercre-issuer`, `vercre-verifier`, and `vercre-holder`).

mod authorization;
mod create_offer;
mod credential;
mod parse;

use parse::Json;
use proc_macro::TokenStream;
use syn::{parse_macro_input, Error};

/// Generate a `CreateOfferRequest` using a JSON-like format.
///
/// # Example
///
/// ```rust
/// use vercre_macros::create_offer_request;
/// use vercre_openid::issuer::SendType;
///
/// const CREDENTIAL_ISSUER: &str = "http://vercre.io";
/// let subject_id = "normal_user";
///
/// let request = create_offer_request!({
///     "credential_issuer": CREDENTIAL_ISSUER,
///     "credential_configuration_ids": ["EmployeeID_JWT"],
///     "subject_id": subject_id,
///     "pre-authorize": true,
///     "tx_code_required": true,
///     "send_type": SendType::ByVal
/// });
///
/// assert_eq!(request.credential_issuer, CREDENTIAL_ISSUER);
/// ```
#[proc_macro]
pub fn create_offer_request(input: TokenStream) -> TokenStream {
    create_offer::request(&parse_macro_input!(input as Json))
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// Generate an `AuthorizationRequest` using a JSON-like format.
///
/// # Example
///
/// ```rust
/// use base64ct::{Base64UrlUnpadded, Encoding};
/// use sha2::{Digest, Sha256};
/// use vercre_macros::authorization_request;
///
/// const CREDENTIAL_ISSUER: &str = "http://vercre.io";
/// const CLIENT_ID: &str = "96bfb9cb-0513-7d64-5532-bed74c48f9ab";
/// let subject_id = "normal_user";
///
/// let request = authorization_request!({
///     "credential_issuer": CREDENTIAL_ISSUER,
///     "response_type": "code",
///     "client_id": CLIENT_ID,
///     "redirect_uri": "http://localhost:3000/callback",
///     "state": "1234",
///     "code_challenge": Base64UrlUnpadded::encode_string(&Sha256::digest("ABCDEF12345")),
///     "code_challenge_method": "S256",
///     "authorization_details": [{
///         "type": "openid_credential",
///         "credential_configuration_id": "EmployeeID_JWT",
///     }],
///     "subject_id": subject_id,
///     "wallet_issuer": CREDENTIAL_ISSUER
// });
///
/// assert_eq!(request.credential_issuer, CREDENTIAL_ISSUER);
/// ```
#[proc_macro]
pub fn authorization_request(input: TokenStream) -> TokenStream {
    authorization::request(&parse_macro_input!(input as Json))
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// Generate an `AuthorizationRequest` using a JSON-like format.
///
/// # Example
///
/// ```rust
/// use base64ct::{Base64UrlUnpadded, Encoding};
/// use sha2::{Digest, Sha256};
/// use vercre_macros::credential_request;
///
/// const CREDENTIAL_ISSUER: &str = "http://vercre.io";
/// const CLIENT_ID: &str = "96bfb9cb-0513-7d64-5532-bed74c48f9ab";
/// let subject_id = "normal_user";
///
/// let request = credential_request!({
///     "credential_issuer": CREDENTIAL_ISSUER,
///     "response_type": "code",
///     "client_id": CLIENT_ID,
///     "redirect_uri": "http://localhost:3000/callback",
///     "state": "1234",
///     "code_challenge": Base64UrlUnpadded::encode_string(&Sha256::digest("ABCDEF12345")),
///     "code_challenge_method": "S256",
///     "authorization_details": [{
///         "type": "openid_credential",
///         "credential_configuration_id": "EmployeeID_JWT",
///     }],
///     "subject_id": subject_id,
///     "wallet_issuer": CREDENTIAL_ISSUER
// });
///
/// assert_eq!(request.credential_issuer, CREDENTIAL_ISSUER);
/// ```
#[proc_macro]
pub fn credential_request(input: TokenStream) -> TokenStream {
    credential::request(&parse_macro_input!(input as Json))
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
