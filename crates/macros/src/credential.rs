use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::parse::{Error, Result};

use crate::parse::{Json, Value};

// Create strongly typed `CredentialRequest` from JSON-like input,
// doing basic validation and setting sensible defaults.
pub fn request(input: &Json) -> Result<TokenStream> {
    // when returning an Option<_> token
    let none = || quote! {None};
    let some = |v: Value| quote! {#v.into()};
    let path = quote! {vercre_openid::issuer};

    // remove fields as we go so we can check for unexpected input
    let mut fields = input.fields.clone();
    let span = Span::call_site();

    // `credential_issuer` is required
    let Some(credential_issuer) = fields.remove("credential_issuer") else {
        return Err(Error::new(span, "`credential_issuer` is not set"));
    };
    // `access_token` is required
    let Some(access_token) = fields.remove("access_token") else {
        return Err(Error::new(span, "`access_token` is not set"));
    };

    let specification = if let Some(ci) = fields.remove("credential_identifier") {
        let Value::String(identifier) = ci else {
            return Err(Error::new(span, "`credential_identifier` must be a string"));
        };

        quote! {
            #path::CredentialSpec::Identifier {
                credential_identifier: #identifier.to_string(),
            }
        }
    } else {
        return Err(Error::new(span, "`credential_identifier` is not set"));
    };

    let proof = if let Some(p) = fields.remove("proof") {
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
    let credential_response_encryption =
        fields.remove("credential_response_encryption").map_or_else(none, some);

    // return error for any unexpected fields
    if !fields.is_empty() {
        let keys = fields.keys().map(|k| format!("`{k}`")).collect::<Vec<_>>().join(", ");
        return Err(Error::new(span, format!("unexpected field(s): {keys}")));
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
