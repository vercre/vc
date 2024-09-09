use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::parse::{Error, Result};

use crate::parse::{Json, Value};

pub fn request(input: &Json) -> Result<TokenStream> {
    // when returning an Option<_> token
    let none = || quote! {None};
    let some = |v: Value| quote! {#v.into()};
    let path = quote! {vercre_openid::issuer};

    let span = Span::call_site();

    // remove fields as we go so we can check for unexpected input
    let mut fields = input.fields.clone();

    // `credential_issuer` is required
    let Some(credential_issuer) = fields.remove("credential_issuer") else {
        return Err(Error::new(span, "`credential_issuer` is not set"));
    };
    let Some(response_type) = fields.remove("response_type") else {
        return Err(Error::new(span, "`response_type` is not set"));
    };
    let Some(client_id) = fields.remove("client_id") else {
        return Err(Error::new(span, "`client_id` is not set"));
    };

    let redirect_uri = fields.remove("redirect_uri").map_or_else(none, some);
    let state = fields.remove("state").map_or_else(none, some);

    let Some(code_challenge) = fields.remove("code_challenge") else {
        return Err(Error::new(span, "`code_challenge` is not set"));
    };
    let Some(code_challenge_method) = fields.remove("code_challenge_method") else {
        return Err(Error::new(span, "`code_challenge_method` is not set"));
    };

    let authorization_details = if let Some(details) = fields.remove("authorization_details") {
        let Value::Array(details) = details else {
            return Err(Error::new(span, "`authorization_details` must be an array"));
        };

        let mut tokens = TokenStream::new();

        for detail in details {
            let Value::Object(detail) = detail else {
                return Err(Error::new(span, "`authorization_details` must be an object"));
            };

            // check type is set and is `openid_credential`
            if let Some(type_) = detail.get("type") {
                if let Value::String(t) = type_
                    && t != "openid_credential"
                {
                    return Err(Error::new(span, "`type` must be `openid_credential`"));
                }
            } else {
                return Err(Error::new(span, "`type` is not set"));
            }

            let credential_configuration_id = &detail["credential_configuration_id"];

            tokens.extend(quote! {
                #path::AuthorizationDetail {
                    type_: #path::AuthorizationDetailType::OpenIdCredential,
                    specification: #path::AuthorizationSpec::ConfigurationId (
                        #path::ConfigurationId::Definition {
                            credential_configuration_id: #credential_configuration_id,
                            credential_definition: None,
                        }
                    ),
                    locations: None
                }
            });
        }

        quote! {Some(vec![#tokens])}
    } else {
        quote! {None}
    };

    let scope = fields.remove("scope").map_or_else(none, some);
    let resource = fields.remove("resource").map_or_else(none, some);
    let Some(subject_id) = fields.remove("subject_id") else {
        return Err(Error::new(span, "`subject_id` is not set"));
    };
    let wallet_issuer = fields.remove("wallet_issuer").map_or_else(none, some);
    let user_hint = fields.remove("user_hint").map_or_else(none, some);
    let issuer_state = fields.remove("issuer_state").map_or_else(none, some);

    // return error for any additional fields
    if !fields.is_empty() {
        let keys = fields.keys().map(|k| format!("`{k}`")).collect::<Vec<_>>().join(", ");
        return Err(Error::new(Span::call_site(), format!("unexpected field(s): {keys}")));
    }

    Ok(quote! {
        #path::AuthorizationRequest {
            credential_issuer: #credential_issuer,
            response_type: #response_type,
            client_id: #client_id,
            redirect_uri: #redirect_uri,
            state: #state,
            code_challenge: #code_challenge,
            code_challenge_method: #code_challenge_method,
            scope: #scope,
            resource: #resource,
            authorization_details: #authorization_details,
            subject_id: #subject_id,
            wallet_issuer: #wallet_issuer,
            user_hint: #user_hint,
            issuer_state: #issuer_state,

            ..Default::default()
        }
    })
}
