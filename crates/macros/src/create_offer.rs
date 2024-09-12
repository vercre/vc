use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::parse::{Error, Result};

use crate::parse::{Json, Value};

// Create strongly typed `CreateOfferRequest` from JSON-like input,
// doing basic validation and setting sensible defaults.
pub fn request(input: &Json) -> Result<TokenStream> {
    let span = Span::call_site();

    let mut input1 = input.clone();

    let credential_issuer = input1.expect("credential_issuer")?;
    let subject_id = input1.option("subject_id");

    // one or more `credential_configuration_ids` are required
    let Some(credential_configuration_ids) = input1.get("credential_configuration_ids") else {
        return Err(Error::new(span, "`credential_configuration_ids` is not set"));
    };
    let Some(ids) = &credential_configuration_ids.as_array() else {
        return Err(Error::new(span, "`credential_configuration_ids` must be an array"));
    };
    if ids.is_empty() {
        return Err(Error::new(span, "`credential_configuration_ids` cannot be empty"));
    }

    // use default values if not set
    let pre_authorize = input1.get("pre-authorize").unwrap_or(Value::Bool(false));
    let tx_code_required = input1.get("tx_code_required").unwrap_or(Value::Bool(false));
    let send_type =
        input1.get("send_type").map_or_else(|| quote! {SendType::ByVal}, |v| quote! {#v.into()});

    // return error for any unexpected fields
    input1.err_unconsumed()?;

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
