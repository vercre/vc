use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::parse::{Error, Result};

use crate::parse::{Data, Value};

// Create strongly typed `CreateOfferRequest` from JSON-like input,
// doing basic validation and setting sensible defaults.
pub fn create_offer_request(input: &Data) -> Result<TokenStream> {
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
    let send_type = fields
        .remove("send_type")
        .unwrap_or(Value::Enum(format_ident!("SendType"), format_ident!("ByVal")));

    // return error for any unexpected fields
    if !fields.is_empty() {
        let keys = fields.keys().map(|k| format!("`{k}`")).collect::<Vec<_>>().join(", ");
        return Err(Error::new(span, format!("unexpected field(s): {keys}")));
    }

    Ok(quote! {
        vercre_openid::issuer::CreateOfferRequest {
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
    // when returning an Option<_> token
    let none = || quote! {None};
    let some = |v: Value| quote! {#v.into()};
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

    //  let code_challenge = fields.remove("code_challenge").unwrap();
    let Some(code_challenge_method) = fields.remove("code_challenge_method") else {
        return Err(Error::new(span, "`code_challenge_method` is not set"));
    };

    let mut authorization_details = TokenStream::new();

    if let Some(details) = fields.remove("authorization_details") {
        let Value::Array(details) = details else {
            return Err(Error::new(span, "`authorization_details` must be an array"));
        };

        let mut tokens = TokenStream::new();

        for detail in details {
            let Value::Object(mut detail) = detail else {
                return Err(Error::new(span, "`authorization_details` must be an object"));
            };
            // let Some(type_) = detail.remove("type") else {
            //     return Err(Error::new(span, "`type` is not set"));
            // };
            let Some(credential_configuration_id) = detail.remove("credential_configuration_id")
            else {
                return Err(Error::new(span, "`credential_configuration_id` is not set"));
            };

            tokens.extend(quote! {
                vercre_openid::issuer::AuthorizationDetail {
                    type_: vercre_openid::issuer::AuthorizationDetailType::OpenIdCredential,
                    specification: vercre_openid::issuer::AuthorizationSpec::ConfigurationId(vercre_openid::issuer::ConfigurationId::Definition {
                        credential_configuration_id: #credential_configuration_id,
                        credential_definition: None,
                    }),
                    locations: None
                }
            });
        }

        authorization_details.extend(quote! {Some(vec![#tokens])});
    } else {
        authorization_details.extend(quote! {None});
    }

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
        vercre_openid::issuer::AuthorizationRequest {
            credential_issuer: #credential_issuer,
            response_type: #response_type,
            client_id: #client_id,
            redirect_uri: #redirect_uri,
            state: #state,
            // code_challenge: #code_challenge,
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
