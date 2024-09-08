use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::parse::{Error, Result};

use crate::parse::Data;

pub fn create_offer_request(input: &Data) -> Result<TokenStream> {
    // remove fields so we can error on any remaining
    let mut fields = input.fields.clone();
    let credential_issuer = fields.remove("credential_issuer").unwrap();
    let subject_id = fields.remove("subject_id").unwrap();
    let credential_configuration_ids = fields.remove("credential_configuration_ids").unwrap();
    let pre_authorize = fields.remove("pre-authorize").unwrap();
    let tx_code_required = fields.remove("tx_code_required").unwrap();
    let send_type = fields.remove("send_type").unwrap();

    // return error for any additional fields
    if !fields.is_empty() {
        let keys = fields.keys().map(|k| format!("`{k}`")).collect::<Vec<_>>().join(", ");
        return Err(Error::new(Span::call_site(), format!("unexpected field(s): {keys}")));
    }

    Ok(quote! {
        CreateOfferRequest {
            credential_issuer: #credential_issuer.to_string(),
            subject_id: Some(#subject_id.to_string()),
            credential_configuration_ids: #credential_configuration_ids.iter().map(|s| s.to_string()).collect(),
            pre_authorize: #pre_authorize,
            tx_code_required: #tx_code_required,
            send_type:  #send_type,
        }
    })
}
