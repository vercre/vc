use std::collections::HashMap;

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::parse::{Parse, ParseStream}; // Error,
use syn::punctuated::{Pair, Punctuated};
use syn::{braced, bracketed, token, Result};

#[derive(Default)]
pub struct Data {
    pub fields: HashMap<String, Value>,
}

impl Parse for Data {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut data = Self::default();

        if input.peek(token::Brace) {
            let content;
            braced!(content in input);

            let fields = Punctuated::<Field, token::Comma>::parse_terminated(&content)?;
            for field in fields.into_pairs() {
                let field = field.into_value();
                data.fields.insert(field.lhs, field.rhs);
            }
        }

        Ok(data)
    }
}

struct Field {
    lhs: String,
    rhs: Value,
}

#[derive(Debug, Clone, Default)]
pub enum Value {
    #[default]
    Null,
    Bool(bool),
    // Number(u64),
    String(String),
    Array(Vec<Self>),
    // Object(HashMap<String, JsonValue>),
    Ident(syn::Ident),
    Enum(syn::Ident, syn::Variant),
}

impl Parse for Field {
    fn parse(input: ParseStream) -> Result<Self> {
        let lhs = input.parse::<syn::LitStr>()?;
        input.parse::<token::Colon>()?;

        Ok(Self {
            lhs: lhs.value(),
            rhs: input.parse::<Value>()?,
        })
    }
}

impl Parse for Value {
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
        } else if l.peek(syn::Ident) {
            let ident = input.parse::<syn::Ident>()?;

            // is this an enum variant?
            let l = input.lookahead1();
            if l.peek(token::PathSep) {
                input.parse::<token::PathSep>()?;
                let variant = input.parse::<syn::Variant>()?;
                Self::Enum(ident, variant)
            } else {
                Self::Ident(ident)
            }
        } else {
            // dump(input)?;
            return Err(input.error("unexpected token"));
        };

        Ok(rhs)
    }
}

impl ToTokens for Value {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            Self::Null => tokens.extend(quote! { None }),
            Self::Bool(b) => tokens.extend(quote! { #b }),
            Self::String(s) => tokens.extend(quote! { #s }),
            Self::Array(a) => {
                let values = a.iter().map(|v| {
                    let mut tokens = TokenStream::new();
                    v.to_tokens(&mut tokens);
                    tokens
                });
                tokens.extend(quote! { vec![#(#values),*] });
            }
            Self::Ident(i) => tokens.extend(quote! { #i }),
            Self::Enum(i, v) => tokens.extend(quote! { #i::#v }),
        }
    }
}

// fn dump(input: ParseStream) -> Result<()> {
//     input.step(|cursor| {
//         let mut rest = *cursor;
//         while let Some((tt, next)) = rest.token_tree() {
//             println!("{tt:?}");
//             rest = next;
//         }
//         Ok(((), rest))
//     })
// }
