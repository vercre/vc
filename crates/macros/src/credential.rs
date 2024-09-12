use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::parse::{Error, Result};

use crate::parse::{Json, Value};

// Create strongly typed `CredentialRequest` from JSON-like input,
// doing basic validation and setting sensible defaults.
pub fn request(input: &Json) -> Result<TokenStream> {
    let path = quote! {vercre_openid::issuer};
    let span = Span::call_site();

    let mut input1 = input.clone();

    let credential_issuer = input1.expect("credential_issuer")?;
    let access_token = input1.expect("access_token")?;

    let specification = if let Some(identifier) = input1.get("credential_identifier") {
        quote! {
            #path::CredentialSpec::Identifier {
                credential_identifier: #identifier,
            }
        }
    } else if let Some(format) = input1.get("format") {
        let Some(defn_value) = input1.get("credential_definition") else {
            return Err(Error::new(span, "`credential_definition` is not set"));
        };
        let credential_definition = format_definition(&defn_value)?;

        match format.as_str() {
            Some("jwt_vc_json") => {
                quote! {
                    #path::CredentialSpec::Format(#path::Format::JwtVcJson {
                        credential_definition: #credential_definition,
                    })
                }
            }
            _ => return Err(Error::new(span, "unsupported format")),
        }
    } else {
        return Err(Error::new(span, "neither `credential_identifier` nor `format` are set"));
    };

    let proof = if let Some(p) = input1.get("proof") {
        let Value::Object(proof) = p else {
            return Err(Error::new(span, "`proof` must be an object"));
        };

        if let Some(pt) = proof.get("proof_type") {
            if let Value::String(proof_type) = pt
                && proof_type != "jwt"
            {
                return Err(Error::new(span, "`proof_type` must be `jwt`"));
            }
        } else {
            return Err(Error::new(span, "`type` is not set"));
        }

        let Some(jwt) = proof.get("jwt") else {
            return Err(Error::new(span, "`jwt` is not set"));
        };

        quote! {
            Some(#path::Proof::Single{
                proof_type: #path::SingleProof::Jwt{
                    jwt: #jwt,
                },
            })
        }
    } else {
        quote! {None}
    };

    // use default values if not set
    let credential_response_encryption = input1.option("credential_response_encryption");

    // return error for any unexpected fields
    if !input1.remaining().is_empty() {
        let keys =
            input1.remaining().iter().map(|k| format!("`{k}`")).collect::<Vec<_>>().join(", ");
        return Err(Error::new(Span::call_site(), format!("unexpected field(s): {keys}")));
    }

    let path = quote! {vercre_openid::issuer};

    Ok(quote! {
        #path::CredentialRequest {
            credential_issuer: #credential_issuer,
            access_token: #access_token,
            specification: #specification,
            proof: #proof,
            credential_response_encryption: #credential_response_encryption,
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

    // let subject = subject(credential_definition)?;

    Ok(quote! {
        #path::CredentialDefinition {
            credential_subject: None,
            context: None,
            type_: Some(#type_array),
        }
    })
}
