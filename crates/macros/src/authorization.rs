use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::parse::{Error, Result};

use crate::parse::{Json, Value};

pub fn request(input: &Json) -> Result<TokenStream> {
    // we remove fields as we go so we can check for unexpected input
    let mut input1 = input.clone();

    // required fields — return error if not present
    let credential_issuer = input1.expect("credential_issuer")?;
    let response_type = input1.expect("response_type")?;
    let client_id = input1.expect("client_id")?;
    let code_challenge = input1.expect("code_challenge")?;
    let code_challenge_method = input1.expect("code_challenge_method")?;
    let subject_id = input1.expect("subject_id")?;

    // optional fields — return Some or None
    let redirect_uri = input1.either("redirect_uri");
    let state = input1.either("state");
    let scope = input1.either("scope");
    let resource = input1.either("resource");
    let wallet_issuer = input1.either("wallet_issuer");
    let user_hint = input1.either("user_hint");
    let issuer_state = input1.either("issuer_state");

    let authorization_details = if let Some(details) = input1.get("authorization_details") {
        let authorization_details = authorization_details(&details)?;
        quote! {Some(#authorization_details)}
    } else {
        quote! {None}
    };

    // return error for either additional fields
    if !input1.remaining().is_empty() {
        let keys =
            input1.remaining().iter().map(|k| format!("`{k}`")).collect::<Vec<_>>().join(", ");
        return Err(Error::new(Span::call_site(), format!("unexpected field(s): {keys}")));
    }

    let path = quote! {vercre_openid::issuer};

    Ok(quote! {
        #path::AuthorizationRequest {
            credential_issuer: #credential_issuer,
            response_type: #response_type,
            client_id: #client_id,
            redirect_uri: #redirect_uri,
            state: #state,
            code_challenge: #code_challenge,
            code_challenge_method: #code_challenge_method,
            authorization_details: #authorization_details,
            scope: #scope,
            resource: #resource,
            subject_id: #subject_id,
            wallet_issuer: #wallet_issuer,
            user_hint: #user_hint,
            issuer_state: #issuer_state,
        }
    })
}

fn authorization_details(details: &Value) -> Result<TokenStream> {
    let span = Span::call_site();
    let path = quote! {vercre_openid::issuer};

    let Some(details) = details.as_array() else {
        return Err(Error::new(span, "`authorization_details` must be an array"));
    };

    let mut tokens = TokenStream::new();

    for detail in details {
        let Some(detail) = detail.as_object() else {
            return Err(Error::new(span, "`authorization_details` must be an object"));
        };

        // check type is set and is `openid_credential`
        if let Some(type_) = detail.get("type") {
            if let Some(t) = type_.as_string()
                && t != "openid_credential"
            {
                return Err(Error::new(span, "`type` must be `openid_credential`"));
            }
        } else {
            return Err(Error::new(span, "`type` is not set"));
        }

        let Some(credential_configuration_id) = &detail.get("credential_configuration_id") else {
            return Err(Error::new(span, "`credential_configuration_id` is not set"));
        };

        // credential_definition
        let credential_definition = if let Some(defn_value) = detail.get("credential_definition") {
            let credential_definition = credential_definition(defn_value)?;
            quote! {Some(#credential_definition)}
        } else {
            quote! {None}
        };

        tokens.extend(quote! {
            #path::AuthorizationDetail {
                type_: #path::AuthorizationDetailType::OpenIdCredential,
                specification: #path::AuthorizationSpec::ConfigurationId (
                    #path::ConfigurationId::Definition {
                        credential_configuration_id: #credential_configuration_id,
                        credential_definition: #credential_definition,
                    }
                ),
                locations: None
            }
        });
    }

    Ok(quote! {vec![#tokens]})
}

fn credential_definition(defn_value: &Value) -> Result<TokenStream> {
    let span = Span::call_site();
    let path = quote! {vercre_openid::issuer};

    let Some(credential_definition) = defn_value.as_object() else {
        return Err(Error::new(span, "`credential_definition` must be an object"));
    };
    let Some(subject_value) = credential_definition.get("credentialSubject") else {
        return Err(Error::new(span, "`credentialSubject` is not set"));
    };
    let Some(credential_subject) = subject_value.as_object() else {
        return Err(Error::new(span, "`credential_subject` must be an object"));
    };

    // build claims map
    let claims = credential_subject.iter().map(|(k, _)| {
        quote! {(#k.to_string(), #path::ClaimEntry::Claim(#path::ClaimDefinition::default()))}
    });
    
    Ok(quote! {
        #path::CredentialDefinition {
            credential_subject: Some(std::collections::HashMap::from([#(#claims),*])),
            context: None,
            type_: None,
        }
    })
}
