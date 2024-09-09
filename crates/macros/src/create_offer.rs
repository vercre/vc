use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::parse::{Error, Result};

use crate::parse::{Json, Value};

// Create strongly typed `CreateOfferRequest` from JSON-like input,
// doing basic validation and setting sensible defaults.
pub fn request(input: &Json) -> Result<TokenStream> {
    // remove fields as we go so we can check for unexpected input
    let mut fields = input.fields.clone();
    let span = Span::call_site();

    // `credential_issuer` is required
    let Some(credential_issuer) = fields.remove("credential_issuer") else {
        return Err(Error::new(span, "`credential_issuer` is not set"));
    };

    // return `subject_id` as Option<_>
    let subject_id =
        fields.remove("subject_id").map_or_else(|| quote! {None}, |v| quote! {#v.into()});

    // one or more `credential_configuration_ids` are required
    let Some(credential_configuration_ids) = fields.remove("credential_configuration_ids") else {
        return Err(Error::new(span, "`credential_configuration_ids` is not set"));
    };
    let Value::Array(ids) = &credential_configuration_ids else {
        return Err(Error::new(span, "`credential_configuration_ids` must be an array"));
    };
    if ids.is_empty() {
        return Err(Error::new(span, "`credential_configuration_ids` cannot be empty"));
    }

    // use default values if not set
    let pre_authorize = fields.remove("pre-authorize").unwrap_or(Value::Bool(false));
    let tx_code_required = fields.remove("tx_code_required").unwrap_or(Value::Bool(false));
    let send_type =
        fields.remove("send_type").map_or_else(|| quote! {SendType::ByVal}, |v| quote! {#v.into()});

    // return error for any unexpected fields
    if !fields.is_empty() {
        let keys = fields.keys().map(|k| format!("`{k}`")).collect::<Vec<_>>().join(", ");
        return Err(Error::new(span, format!("unexpected field(s): {keys}")));
    }

    let path = quote! {vercre_openid::issuer};

    Ok(quote! {
        #path::CreateOfferRequest {
            credential_issuer: #credential_issuer,
            subject_id: #subject_id,
            credential_configuration_ids: #credential_configuration_ids,
            pre_authorize: #pre_authorize,
            tx_code_required: #tx_code_required,
            send_type:  #send_type,
        }
    })
}
