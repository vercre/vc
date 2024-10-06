use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::parse::{Error, Result};

use crate::parse::{Json, Value};

// Create strongly typed `CreateOfferRequest` from JSON-like input,
// doing basic validation and setting sensible defaults.
pub fn request(input: &Json) -> Result<TokenStream> {
    let span = Span::call_site();
    let path = quote! {vercre_issuer};

    let mut input = input.clone();

    let credential_issuer = input.expect("credential_issuer")?;
    let subject_id = input.option("subject_id");

    // one or more `credential_configuration_ids` are required
    let Some(credential_configuration_ids) = input.get("credential_configuration_ids") else {
        return Err(Error::new(span, "`credential_configuration_ids` is not set"));
    };
    let Some(ids) = &credential_configuration_ids.as_array() else {
        return Err(Error::new(span, "`credential_configuration_ids` must be an array"));
    };
    if ids.is_empty() {
        return Err(Error::new(span, "`credential_configuration_ids` cannot be empty"));
    }

    // use default values if not set
    let grant_types = grant_types(input.get("grant_types"))?;

    let tx_code_required = input.get("tx_code_required").unwrap_or(Value::Bool(false));
    let send_type =
        input.get("send_type").map_or_else(|| quote! {SendType::ByVal}, |v| quote! {#v.into()});

    // return error for any unexpected fields
    input.check_consumed()?;

    Ok(quote! {
        #path::CreateOfferRequest {
            credential_issuer: #credential_issuer,
            subject_id: #subject_id,
            credential_configuration_ids: #credential_configuration_ids,
            grant_types: #grant_types,
            tx_code_required: #tx_code_required,
            send_type:  #send_type,
        }
    })
}

fn grant_types(input: Option<Value>) -> Result<TokenStream> {
    let span = Span::call_site();
    let path = quote! {vercre_issuer};

    if let Some(gts) = input {
        let mut tokens = TokenStream::new();

        for gt in gts.as_array().unwrap() {
            match gt.as_str().unwrap() {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code" => {
                    tokens.extend(quote! {#path::GrantType::PreAuthorizedCode});
                }
                "authorization_code" => {
                    tokens.extend(quote! {#path::GrantType::AuthorizationCode});
                }
                _ => {
                    return Err(Error::new(
                        span,
                        format!("unsupported grant type: {}", gt.as_str().unwrap()),
                    ));
                }
            }
        }
        Ok(quote! {Some(vec![#tokens])})
    } else {
        Ok(quote! {None})
    }
}
