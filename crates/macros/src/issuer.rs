use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::parse::{Error, Result};

use crate::parse::{Data, Value};

// Create strongly typed `CreateOfferRequest` from JSON-like input,
// doing basic validation and setting sensible defaults.
pub fn create_offer_request(input: &Data) -> Result<TokenStream> {
    // remove fields so we can error on any remaining
    let mut fields = input.fields.clone();
    let span = Span::call_site();

    // `credential_issuer` is required
    let Some(credential_issuer) = fields.remove("credential_issuer") else {
        return Err(Error::new(span, "`credential_issuer` is not set"));
    };

    // return `subject_id` as Option<subject_id>
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
    let send_type = fields
        .remove("send_type")
        .unwrap_or(Value::Enum(format_ident!("SendType"), format_ident!("ByVal")));

    // return error for any additional fields
    if !fields.is_empty() {
        let keys = fields.keys().map(|k| format!("`{k}`")).collect::<Vec<_>>().join(", ");
        return Err(Error::new(span, format!("unexpected field(s): {keys}")));
    }

    Ok(quote! {
        CreateOfferRequest {
            credential_issuer: #credential_issuer,
            subject_id: #subject_id,
            credential_configuration_ids: #credential_configuration_ids,
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
    // let authorization_details = fields.remove("authorization_details").unwrap();
    // let scope = fields.remove("scope").unwrap();
    // let resource = fields.remove("resource").unwrap();
    let subject_id = fields.remove("subject_id").unwrap();
    let wallet_issuer = fields.remove("wallet_issuer").unwrap();
    // let user_hint = fields.remove("user_hint").unwrap();
    // let issuer_state = fields.remove("issuer_state").unwrap();

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
            // scope: Some(#scope.to_string()),
            // resource: Some(#resource.to_string()),
            // authorization_details: #authorization_details.iter().map(|s| s.to_string()).collect(),
            subject_id: #subject_id.to_string(),
            wallet_issuer: Some(#wallet_issuer.to_string()),
            // user_hint: Some(#user_hint.to_string()),
            // issuer_state: Some(#issuer_state.to_string()),

            ..Default::default()
        }
    })
}
