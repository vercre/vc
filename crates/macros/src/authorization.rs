use std::collections::HashMap;

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::parse::{Error, Result};

use crate::parse::{Json, Value};

pub fn request(input: &Json) -> Result<TokenStream> {
    // we remove fields as we go so we can check for unexpected input
    let mut input = input.clone();

    // required fields — return error if not present
    let credential_issuer = input.expect("credential_issuer")?;
    let response_type = input.expect("response_type")?;
    let client_id = input.expect("client_id")?;
    let code_challenge = input.expect("code_challenge")?;
    let code_challenge_method = input.expect("code_challenge_method")?;
    let subject_id = input.expect("subject_id")?;

    // optional fields — return Some or None
    let redirect_uri = input.option("redirect_uri");
    let state = input.option("state");
    let scope = input.option("scope");
    let resource = input.option("resource");
    let wallet_issuer = input.option("wallet_issuer");
    let user_hint = input.option("user_hint");
    let issuer_state = input.option("issuer_state");

    let authorization_details = if let Some(details) = input.get("authorization_details") {
        let authorization_details = authorization_details(&details)?;
        quote! {Some(#authorization_details)}
    } else {
        quote! {None}
    };

    // return error for any unexpected fields
    input.check_consumed()?;

    let path = quote! {vercre_issuer};

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
    let path = quote! {vercre_issuer};

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
        let credential = credential_authorization(detail)?;

        tokens.extend(quote! {
            #path::AuthorizationDetail {
                type_: #path::AuthorizationDetailType::OpenIdCredential,
                credential: #credential,
                locations: None
            }
        });
    }

    Ok(quote! {vec![#tokens]})
}

fn credential_authorization(detail: &HashMap<String, Value>) -> Result<TokenStream> {
    let span = Span::call_site();
    let path = quote! {vercre_issuer};

    // credential_configuration_id or format?
    if let Some(credential_configuration_id) = detail.get("credential_configuration_id") {
        // credential_definition is optional
        let claims = if let Some(defn_value) = detail.get("credential_definition") {
            let credential_definition = configuration_definition(defn_value)?;
            quote! {Some(#path::ProfileClaims::W3c(#credential_definition))}
        } else {
            quote! {None}
        };

        Ok(quote! {
            #path::CredentialAuthorization::ConfigurationId {
                credential_configuration_id: #credential_configuration_id,
                claims: #claims,
            }
        })
    } else if let Some(format) = detail.get("format") {
        // credential_definition is required
        let Some(defn_value) = detail.get("credential_definition") else {
            return Err(Error::new(span, "`credential_definition` is not set"));
        };
        let credential_definition = format_definition(defn_value)?;

        match format.as_str() {
            Some("jwt_vc_json") => Ok(quote! {
                #path::CredentialAuthorization::Format (
                    #path::FormatIdentifier::JwtVcJson(#path::ProfileW3c {
                        credential_definition: #credential_definition
                    }),
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
    let path = quote! {vercre_issuer};

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
            context: None,
            type_: #type_,
            credential_subject: #subject,
        }
    })
}

fn format_definition(defn_value: &Value) -> Result<TokenStream> {
    let span = Span::call_site();
    let path = quote! {vercre_issuer};

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
            context: None,
            type_: Some(#type_array),
            credential_subject: #subject,
        }
    })
}

fn subject(definition: &HashMap<String, Value>) -> Result<TokenStream> {
    let span = Span::call_site();

    if let Some(subject_value) = definition.get("credentialSubject") {
        let Some(credential_subject) = subject_value.as_object() else {
            return Err(Error::new(span, "`credentialSubject` must be an object"));
        };

        // build claims map
        let claims = claims(credential_subject);

        Ok(quote! {#claims})
    } else {
        Ok(quote! {None})
    }
}

fn claims(claimset: &HashMap<String, Value>) -> TokenStream {
    let path = quote! {vercre_issuer};

    let claims = claimset.iter().map(|(k, v)| {
        if let Some(nested) = v.as_object()
            && !nested.is_empty()
        {
            let claims = claims(nested);
            quote! {(#k.to_string(), #path::Claim::Set(#claims.unwrap()))}
        } else {
            quote! {(#k.to_string(), #path::Claim::Entry(#path::ClaimDefinition::default()))}
        }
    });

    quote! {
        Some(std::collections::HashMap::from([#(#claims),*]))
    }
}
