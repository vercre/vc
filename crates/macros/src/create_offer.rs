// use std::collections::HashMap;

use proc_macro2::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream}; // Error,
use syn::punctuated::{Pair, Punctuated};
use syn::{braced, bracketed, token, Result};
use vercre_openid::issuer::SendType;

pub fn expand(input: &CreateOffer) -> TokenStream {
    let credential_issuer = &input.credential_issuer;
    let subject_id = &input.subject_id;
    let credential_configuration_ids = &input.credential_configuration_ids.join(", ");

    // let send_type: syn::Variant = parse_quote!(input.send_type.clone());

    quote! {
        CreateOfferRequest {
            credential_issuer: #credential_issuer.to_string(),
            subject_id: Some(#subject_id.to_string()),
            credential_configuration_ids: vec![#credential_configuration_ids.to_string()],
            pre_authorize: true,
            tx_code_required: true,
            send_type:  SendType::ByVal,
        }
    }
}

#[derive(Default)]
pub struct CreateOffer {
    pub credential_issuer: String,
    pub subject_id: String,
    pub credential_configuration_ids: Vec<String>,
    pub pre_authorize: bool,
    pub tx_code_required: bool,
    pub send_type: SendType,
}

impl Parse for CreateOffer {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut offer = Self::default();

        if input.peek(token::Brace) {
            let content;
            braced!(content in input);

            // offer.credential_configuration_ids = vec!["EmployeeID_JWT".to_string()];
            offer.send_type = SendType::ByVal;

            let fields = Punctuated::<JsonField, token::Comma>::parse_terminated(&content)?;
            for field in fields.into_pairs() {
                let field = field.into_value();

                // println!("Field {}: {:?}", field.lhs, field.rhs);

                match field.lhs.as_str() {
                    "credential_issuer" => offer.credential_issuer = field.rhs.as_string(),
                    "subject_id" => offer.subject_id = field.rhs.as_string(),
                    "credential_configuration_ids" => {
                        offer.credential_configuration_ids =
                            field.rhs.as_array().iter().map(JsonValue::as_string).collect();
                    }
                    "pre-authorize" => offer.pre_authorize = field.rhs.as_bool(),
                    "tx_code_required" => offer.tx_code_required = field.rhs.as_bool(),
                    "send_type" => {
                        println!("Field {}", field.rhs.as_string());
                        offer.send_type = SendType::ByVal;
                    } //field.rhs.as_string(),
                    _ => {
                        println!("unknown field");
                        //Err(cursor.error("no `@` was found after this point"))
                    }
                }
            }
        }

        Ok(offer)
    }
}

struct JsonField {
    lhs: String,
    rhs: JsonValue,
}

#[derive(Debug, Clone)]
enum JsonValue {
    // Null,
    Bool(bool),
    // Number(u64),
    String(String),
    Array(Vec<JsonValue>),
    // Object(HashMap<String, FieldKind>),
}

impl Parse for JsonField {
    fn parse(input: ParseStream) -> Result<Self> {
        let lhs = input.parse::<syn::LitStr>()?;
        input.parse::<token::Colon>()?;

        Ok(Self {
            lhs: lhs.value(),
            rhs: input.parse::<JsonValue>()?,
        })
    }
}

impl Parse for JsonValue {
    fn parse(input: ParseStream) -> Result<Self> {
        let l = input.lookahead1();

        let rhs = if l.peek(syn::LitStr) {
            Self::String(input.parse::<syn::LitStr>()?.value())
        } else if l.peek(syn::LitBool) {
            Self::Bool(input.parse::<syn::LitBool>()?.value())
        } else if l.peek(token::Bracket) {
            let contents;
            bracketed!(contents in input);
            let items = Punctuated::<Self, token::Comma>::parse_terminated(&contents)?;
            let values = items.into_pairs().map(Pair::into_value).collect();
            Self::Array(values)
        // } else if l.peek(syn::token::Const) {
        //     let x = input.parse::<syn::ConstParam>()?;
        //     println!("{:?}", x);
        //     skip(input)?;
        //     JsonValue::String("hellox".to_string())
        } else {
            // JsonValue::Null
            dump(input)?;
            Self::String("hello".to_string())
        };

        Ok(rhs)
    }
}

impl JsonValue {
    const fn as_bool(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            _ => false,
        }
    }

    fn as_string(&self) -> String {
        match self {
            Self::String(s) => s.clone(),
            _ => String::new(),
        }
    }

    fn as_array(&self) -> Vec<Self> {
        match self {
            Self::Array(a) => a.clone(),
            _ => vec![],
        }
    }
}

fn dump(input: ParseStream) -> Result<()> {
    input.step(|cursor| {
        let mut rest = *cursor;
        while let Some((tt, next)) = rest.token_tree() {
            println!("{tt:?}");
            rest = next;
        }
        // Err(cursor.error("no `@` was found after this point"))
        Ok(((), rest))
    })
}
