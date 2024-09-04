//! # Core Utilities for Vercre
//!
//! This crate provides common utilities for the Vercre project and is not intended to be used
//! directly.

use std::collections::HashMap;

use proc_macro::TokenStream;
use proc_macro2::TokenTree;
use quote::quote;
use syn::parse::{Error, Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{braced, parse_macro_input, token, Field, Ident, Result, Token, Type};
use vercre_openid::issuer::SendType;

struct Temp;

impl Temp {
    fn parse_alternate(input: ParseStream) -> Result<Self> {
        println!("input: {input}");
        skip(input)?;
        Ok(Temp)
    }
}

fn skip(input: ParseStream) -> Result<()> {
    input.step(|cursor| {
        let mut rest = *cursor;
        while let Some((tt, next)) = rest.token_tree() {
            match &tt {
                TokenTree::Punct(punct) if punct.as_char() == '@' => {
                    return Ok(((), next));
                }
                _ => rest = next,
            }
        }
        // Err(cursor.error("no `@` was found after this point"))
        Ok(((), rest))
    })
}

/// Generate a `CreateOfferRequest` from JSON.
///
/// # Example
///
/// ```rust,ignore
/// let request = create_offer!({
///     "credential_issuer": "http://vercre.io",
///     "credential_configuration_ids": ["EmployeeID_JWT"],
///     "subject_id": "normal_user",
///     "pre-authorize": true,
///     "tx_code_required": true,
///     "send_type": SendType::ByVal
/// });
/// ```
#[proc_macro]
pub fn create_offer(input: TokenStream) -> TokenStream {
    // let cfg = parse_macro_input!(input with Temp::parse_alternate);

    let res = match syn::parse::Parser::parse(Temp::parse_alternate, input) {
        Ok(data) => {
            println!("data");
            data
        }
        Err(err) => {
            println!("err: {:?}", err);
            // Temp
            return TokenStream::from(err.to_compile_error());
        }
    };

    // if input.is_empty() {
    //     return Error::new(&input, "expected JSON object").to_compile_error().into();
    // }

    let config_ids = vec!["EmployeeID_JWT".to_string()].join(", ").to_string();
    let issuer = "http://vercre.io".to_string(); //cfg.credential_issuer;

    let expanded = quote! {
        CreateOfferRequest {
            credential_issuer: #issuer.to_string(),
            subject_id: Some("normal_user".to_string()),
            credential_configuration_ids: vec![#config_ids.to_string()],
            pre_authorize: true,
            tx_code_required: true,
            send_type: SendType::ByVal,
        }
    };

    TokenStream::from(expanded)
}

pub(crate) struct CreateOfferConfig {
    pub credential_issuer: String,
    pub subject_id: Option<String>,
    pub credential_configuration_ids: Vec<String>,
    pub pre_authorize: bool,
    pub tx_code_required: bool,
    pub send_type: SendType,
}

impl Parse for CreateOfferConfig {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        // println!("input: {:?}", input);

        let content;
        syn::braced!(content in input);

        println!("content: {:?}", content);

        Ok(Self {
            credential_issuer: "http://vercre.io".to_string(),
            subject_id: Some("normal_user".to_string()),
            credential_configuration_ids: vec!["EmployeeID_JWT".to_string()],
            pre_authorize: true,
            tx_code_required: true,
            send_type: SendType::ByVal,
        })
    }
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test() {
        let x = create_offer!({
            "input_1": "input1"
        });
    }
}