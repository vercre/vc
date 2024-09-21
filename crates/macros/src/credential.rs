use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::parse::{Error, Result};

use crate::parse::{Json, Value};

// Create strongly typed `CredentialRequest` from JSON-like input,
// doing basic validation and setting sensible defaults.
pub fn request(input: &Json) -> Result<TokenStream> {
    let mut input = input.clone();

    let credential_issuer = input.expect("credential_issuer")?;
    let access_token = input.expect("access_token")?;
    let credential = credential_issuance(&mut input)?;
    let proof = proof(&mut input)?;
    let credential_response_encryption = input.option("credential_response_encryption");

    // return error for any unexpected fields
    input.check_consumed()?;

    let path = quote! {vercre_issuer};

    Ok(quote! {
        #path::CredentialRequest {
            credential_issuer: #credential_issuer,
            access_token: #access_token,
            credential: #credential,
            proof: #proof,
            credential_response_encryption: #credential_response_encryption,
        }
    })
}

fn credential_issuance(input: &mut Json) -> Result<TokenStream> {
    let path = quote! {vercre_issuer};
    let span = Span::call_site();

    if let Some(identifier) = input.get("credential_identifier") {
        Ok(quote! {
            #path::CredentialIssuance::Identifier {
                credential_identifier: #identifier.into(),
            }
        })
    } else if let Some(format) = input.get("format") {
        let Some(defn_value) = input.get("credential_definition") else {
            return Err(Error::new(span, "`credential_definition` is not set"));
        };
        let credential_definition = format_definition(&defn_value)?;

        match format.as_str() {
            Some("jwt_vc_json") => Ok(quote! {
                #path::CredentialIssuance::Format(#path::CredentialFormat {
                    format: #path::Format::JwtVcJson,
                    profile: #path::FormatProfile::Definition(#credential_definition),
                })
            }),
            _ => return Err(Error::new(span, "unsupported format")),
        }
    } else {
        return Err(Error::new(span, "neither `credential_identifier` nor `format` are set"));
    }
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

    // let subject = subject(credential_definition)?;

    Ok(quote! {
        #path::CredentialDefinition {
            credential_subject: None,
            context: None,
            type_: Some(#type_array),
        }
    })
}

fn proof(input: &mut Json) -> Result<TokenStream> {
    let path = quote! {vercre_issuer};
    let span = Span::call_site();

    if let Some(p) = input.get("proof") {
        let Some(proof) = p.as_object() else {
            return Err(Error::new(span, "`proof` must be an object"));
        };

        if let Some(proof_type) = proof.get("proof_type") {
            if proof_type.as_str() != Some("jwt") {
                return Err(Error::new(span, "`proof_type` must be `jwt`"));
            }
        } else {
            return Err(Error::new(span, "`type` is not set"));
        }

        let Some(jwt) = proof.get("jwt") else {
            return Err(Error::new(span, "`jwt` is not set"));
        };

        return Ok(quote! {
            Some(#path::Proof::Single{
                proof_type: #path::SingleProof::Jwt{
                    jwt: #jwt.into(),
                },
            })
        });
    }

    Ok(quote! {None})
}
