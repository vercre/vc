//! # Core Utilities for Vercre
//!
//! This crate provides common utilities for the Vercre project and is not intended to be used
//! directly.

mod create_offer;

use create_offer::CreateOffer;
use proc_macro::TokenStream;
use syn::parse_macro_input;

/// Generate a `CreateOfferRequest` from JSON.
///
/// # Example
///
/// ```rust,ignore
/// let request = create_offer!({
///     "credential_issuer": "http://vercre.io",
///     "credential_configuration_ids": ["EmployeeID_JWT"],
///     "subject_id": "normal_user",
///     "pre-authorize": true,
///     "tx_code_required": true,
///     "send_type": SendType::ByVal
/// });
/// ```
#[proc_macro]
pub fn create_offer(input: TokenStream) -> TokenStream {
    create_offer::expand(&parse_macro_input!(input as CreateOffer)).into()
}
