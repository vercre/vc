//! # Core Utilities for Vercre
//!
//! This crate provides common utilities for the Vercre project and is not intended to be used
//! directly.

mod create_offer;

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
pub fn create_offer(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    create_offer::expand(&parse_macro_input!(input as create_offer::CreateOffer))
}
