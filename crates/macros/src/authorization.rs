use std::collections::HashMap;

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
    let redirect_uri = input1.option("redirect_uri");
    let state = input1.option("state");
    let scope = input1.option("scope");
    let resource = input1.option("resource");
    let wallet_issuer = input1.option("wallet_issuer");
    let user_hint = input1.option("user_hint");
    let issuer_state = input1.option("issuer_state");

    let authorization_details = if let Some(details) = input1.get("authorization_details") {
        let authorization_details = authorization_details(&details)?;
        quote! {Some(#authorization_details)}
    } else {
        quote! {None}
    };

    // return error for any unexpected fields
    input1.err_unconsumed()?;

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
            return Err(Error::new(span, "`authorization_detail` must be an object"));
        };

        // check type is set and is `openid_credential`
        if let Some(type_) = detail.get("type") {
            if let Some(t) = type_.as_str()
                && t != "openid_credential"
            {
                return Err(Error::new(span, "`type` must be `openid_credential`"));
            }
        } else {
            return Err(Error::new(span, "`type` is not set"));
        }

        // credential_configuration_id or format?
        let specification = credential_specification(detail)?;

        tokens.extend(quote! {
            #path::AuthorizationDetail {
                type_: #path::AuthorizationDetailType::OpenIdCredential,
                specification: #specification,
                locations: None
            }
        });
    }

    Ok(quote! {vec![#tokens]})
}

fn credential_specification(detail: &HashMap<String, Value>) -> Result<TokenStream> {
    let span = Span::call_site();
    let path = quote! {vercre_openid::issuer};

    // credential_configuration_id or format?
    if let Some(credential_configuration_id) = detail.get("credential_configuration_id") {
        // credential_definition is optional
        let credential_definition = if let Some(defn_value) = detail.get("credential_definition") {
            let credential_definition = configuration_definition(defn_value)?;
            quote! {Some(#credential_definition)}
        } else {
            quote! {None}
        };

        Ok(quote! {
            #path::AuthorizationSpec::ConfigurationId (
                #path::ConfigurationId::Definition {
                    credential_configuration_id: #credential_configuration_id,
                    credential_definition: #credential_definition,
                },
            )
        })
    } else if let Some(format) = detail.get("format") {
        // credential_definition is required
        let Some(defn_value) = detail.get("credential_definition") else {
            return Err(Error::new(span, "`credential_definition` is not set"));
        };
        let credential_definition = format_definition(defn_value)?;

        match format.as_str() {
            Some("jwt_vc_json") => Ok(quote! {
                #path::AuthorizationSpec::Format (
                    #path::Format::JwtVcJson {
                        credential_definition: #credential_definition,
                    },
                )
            }),
            _ => Err(Error::new(span, "unknown `format`")),
        }
    } else {
        return Err(Error::new(
            span,
            "either `credential_configuration_id` or `format` must be set",
        ));
    }
}

fn configuration_definition(defn_value: &Value) -> Result<TokenStream> {
    let span = Span::call_site();
    let path = quote! {vercre_openid::issuer};

    let Some(credential_definition) = defn_value.as_object() else {
        return Err(Error::new(span, "`credential_definition` must be an object"));
    };

    // TODO: only allow @context if format is ldp-vc or jwt_vc_json-ld
    // let context = if let Some(context) = credential_definition.get("@context") {
    //     quote! {Some(#context)}
    // } else {
    //     quote! {None}
    // };

    let type_ = credential_definition
        .get("type")
        .map_or_else(|| quote! {None}, |type_array| quote! {Some(#type_array)});
    let subject = subject(credential_definition)?;

    Ok(quote! {
        #path::CredentialDefinition {
            credential_subject: #subject,
            context: None,
            type_: #type_,
        }
    })
}

fn format_definition(defn_value: &Value) -> Result<TokenStream> {
    let span = Span::call_site();
    let path = quote! {vercre_openid::issuer};

    let Some(credential_definition) = defn_value.as_object() else {
        return Err(Error::new(span, "`credential_definition` must be an object"));
    };

    // TODO: only allow @context if format is ldp-vc or jwt_vc_json-ld
    // let Some(context) = credential_definition.get("@context") else {
    //     return Err(Error::new(span, "`@context` is not set"));
    // };

    let Some(type_array) = credential_definition.get("type") else {
        return Err(Error::new(span, "`type` is not set"));
    };

    let subject = subject(credential_definition)?;

    Ok(quote! {
        #path::CredentialDefinition {
            credential_subject: #subject,
            context: None,
            type_: Some(#type_array),
        }
    })
}

fn subject(definition: &HashMap<String, Value>) -> Result<TokenStream> {
    let span = Span::call_site();
    let path = quote! {vercre_openid::issuer};

    if let Some(subject_value) = definition.get("credentialSubject") {
        let Some(credential_subject) = subject_value.as_object() else {
            return Err(Error::new(span, "`credentialSubject` must be an object"));
        };

        // build claims map
        let claims = credential_subject.iter().map(|(k, _)| {
            quote! {(#k.to_string(), #path::ClaimEntry::Claim(#path::ClaimDefinition::default()))}
        });

        Ok(quote! {
            Some(std::collections::HashMap::from([#(#claims),*]))
        })
    } else {
        Ok(quote! {None})
    }
}
