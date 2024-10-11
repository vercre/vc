use std::collections::HashMap;

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::parse::{Error, Result};

use crate::parse::{Json, Value};

pub fn request(input: &Json) -> Result<TokenStream> {
    // let path = quote! {vercre_openid::issuer};

    // we remove fields as we go so we can check for unexpected input
    let mut input = input.clone();

    // required fields — return error if not present
    let credential_issuer = input.expect("credential_issuer")?;

    // optional fields — return Some or None
    let client_id = input.option("client_id");

    let Some(grant_type) = input.get("grant_type") else {
        return Err(Error::new(Span::call_site(), "`grant_type` is not set"));
    };

    let grant_type =
        if grant_type.as_str() == Some("urn:ietf:params:oauth:grant-type:pre-authorized_code") {
            pre_authorized_code(&mut input)?
        } else if grant_type.as_str() == Some("authorization_code") {
            authorization_code(&mut input)?
        } else {
            return Err(Error::new(Span::call_site(), "unknown `grant_type`"));
        };

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
        #path::TokenRequest {
            credential_issuer: #credential_issuer,
            client_id: #client_id,
            grant_type: #grant_type,
            authorization_details: #authorization_details,
            client_assertion: None,
        }
    })
}

fn pre_authorized_code(input: &mut Json) -> Result<TokenStream> {
    let path = quote! {vercre_issuer};

    let pre_authorized_code = input.expect("pre-authorized_code")?;
    let tx_code = input.option("tx_code");

    Ok(quote! {
        #path::TokenGrantType::PreAuthorizedCode {
            pre_authorized_code: #pre_authorized_code,
            tx_code: #tx_code,
        }
    })
}

fn authorization_code(input: &mut Json) -> Result<TokenStream> {
    let path = quote! {vercre_issuer};

    let code = input.expect("code")?;
    let redirect_uri = input.option("redirect_uri");
    let code_verifier = input.expect("code_verifier")?;

    Ok(quote! {
        #path::TokenGrantType::AuthorizationCode {
            code: #code,
            redirect_uri: #redirect_uri,
            code_verifier: Some(#code_verifier),
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
        let configuration = credential_configuration(detail)?;

        tokens.extend(quote! {
            #path::AuthorizationDetail {
                type_: #path::AuthorizationDetailType::OpenIdCredential,
                credential: #configuration,
                locations: None
            }
        });
    }

    Ok(quote! {vec![#tokens]})
}

fn credential_configuration(detail: &HashMap<String, Value>) -> Result<TokenStream> {
    let span = Span::call_site();
    let path = quote! {vercre_issuer};

    // credential_configuration_id or format?
    if let Some(credential_configuration_id) = detail.get("credential_configuration_id") {
        // credential_definition is optional
        let claims = if let Some(defn_value) = detail.get("credential_definition") {
            let credential_definition = configuration_definition(defn_value)?;
            quote! {Some(#path::ProfileW3c{
                credential_definition:#credential_definition
            })}
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
                    #path::Format::JwtVcJson(#path::ProfileW3c{
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
    let context = credential_definition
        .get("@context")
        .map_or_else(|| quote! {None}, |context| quote! {Some(#context)});
    let type_ = credential_definition
        .get("type")
        .map_or_else(|| quote! {None}, |type_array| quote! {Some(#type_array)});

    let subject = subject(credential_definition)?;

    Ok(quote! {
        #path::CredentialDefinition {
            credential_subject: #subject,
            context: #context,
            type_: #type_,
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
            credential_subject: #subject,
            context: None,
            type_: Some(#type_array),
        }
    })
}

fn subject(definition: &HashMap<String, Value>) -> Result<TokenStream> {
    let span = Span::call_site();
    let path = quote! {vercre_issuer};

    if let Some(subject_value) = definition.get("credentialSubject") {
        let Some(credential_subject) = subject_value.as_object() else {
            return Err(Error::new(span, "`credentialSubject` must be an object"));
        };

        // build claims map
        let claims = credential_subject.iter().map(|(k, _)| {
            quote! {(#k.to_string(), #path::ClaimDefinition::Claim(#path::ClaimDefinition::default()))}
        });

        Ok(quote! {
            Some(std::collections::HashMap::from([#(#claims),*]))
        })
    } else {
        Ok(quote! {None})
    }
}
