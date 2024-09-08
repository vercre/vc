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

pub fn authorization_request(input: &Data) -> Result<TokenStream> {
    // remove fields so we can error on any remaining
    let mut fields = input.fields.clone();
    let credential_issuer = fields.remove("credential_issuer").unwrap();
    let response_type = fields.remove("response_type").unwrap();
    let client_id = fields.remove("client_id").unwrap();
    let redirect_uri = fields.remove("redirect_uri").unwrap();
    let state = fields.remove("state").unwrap();
    //  let code_challenge = fields.remove("code_challenge").unwrap();
    let code_challenge_method = fields.remove("code_challenge_method").unwrap();

    // return error for any additional fields
    if !fields.is_empty() {
        let keys = fields.keys().map(|k| format!("`{k}`")).collect::<Vec<_>>().join(", ");
        return Err(Error::new(Span::call_site(), format!("unexpected field(s): {keys}")));
    }

    Ok(quote! {
        AuthorizationRequest {
            credential_issuer: #credential_issuer.to_string(),
            response_type: #response_type.to_string(),
            client_id: #client_id.to_string(),
            redirect_uri: Some(#redirect_uri.to_string()),
            state: Some(#state.to_string()),
            // code_challenge: #code_challenge.to_string(),
            code_challenge_method: #code_challenge_method.to_string(),

            // credential_configuration_ids: #credential_configuration_ids.iter().map(|s| s.to_string()).collect(),

            ..Default::default()
        }
    })
}
