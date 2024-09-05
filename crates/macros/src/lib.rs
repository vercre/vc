//! # Core Utilities for Vercre
//!
//! This crate provides common utilities for the Vercre project and is not intended to be used
//! directly.

use proc_macro::TokenStream;
use proc_macro2::TokenTree;
use quote::quote;
use syn::parse::{Parse, ParseStream}; // Error,
use syn::punctuated::Punctuated;
use syn::{braced, parse_macro_input, token, Result, Token};
use vercre_openid::issuer::SendType;

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
    let _cfg = parse_macro_input!(input as CreateOffer);

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

pub(crate) struct CreateOffer {
    pub credential_issuer: String,
    pub subject_id: Option<String>,
    pub credential_configuration_ids: Vec<String>,
    pub pre_authorize: bool,
    pub tx_code_required: bool,
    pub send_type: SendType,
}

impl Parse for CreateOffer {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        if input.peek(token::Brace) {
            let content;
            braced!(content in input);
            println!("content: {content}");

            let fields = Punctuated::<OfferField, Token![,]>::parse_terminated(&content)?;
            for field in fields.into_pairs() {
                let field = field.into_value();
                println!("field: {field:?}");
            }
            // skip(input)?;
        }

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

#[derive(Debug)]
struct OfferField {
    lhs: String,
    rhs: String,
}

impl Parse for OfferField {
    fn parse(input: ParseStream) -> Result<Self> {
        println!("input: {input}");

        let lhs = input.parse::<syn::LitStr>()?;
        input.parse::<Token![:]>()?;
        let rhs = input.parse::<syn::LitStr>()?;

        Ok(Self {
            lhs: lhs.value(),
            rhs: rhs.value(),
        })
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
