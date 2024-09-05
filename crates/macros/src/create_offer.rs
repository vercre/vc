use proc_macro::TokenStream;
// use proc_macro2::TokenTree;
use quote::quote;
use syn::parse::{Parse, ParseStream}; // Error,
use syn::punctuated::Punctuated;
use syn::{braced, token, Result, Token};
use vercre_openid::issuer::SendType;

pub fn expand(input: &CreateOffer) -> proc_macro::TokenStream {
    let config_ids = ["EmployeeID_JWT".to_string()].join(", ");

    let credential_issuer = &input.credential_issuer;
    let subject_id = &input.subject_id;

    let expanded = quote! {
        CreateOfferRequest {
            credential_issuer: #credential_issuer.to_string(),
            subject_id: Some(#subject_id.to_string()),
            credential_configuration_ids: vec![#config_ids.to_string()],
            pre_authorize: true,
            tx_code_required: true,
            send_type: SendType::ByVal,
        }
    };

    TokenStream::from(expanded)
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

            offer.credential_configuration_ids = vec!["EmployeeID_JWT".to_string()];
            offer.send_type = SendType::ByVal;

            let fields = Punctuated::<OfferField, token::Comma>::parse_terminated(&content)?;
            for field in fields.into_pairs() {
                let field = field.into_value();

                match field.lhs.as_str() {
                    "credential_issuer" => offer.credential_issuer = field.rhs.as_string(),
                    "subject_id" => offer.subject_id = field.rhs.as_string(),
                    // "credential_configuration_ids" => offer.credential_configuration_ids = field.rhs,
                    "pre-authorize" => offer.pre_authorize = field.rhs.as_bool(),
                    "tx_code_required" => offer.tx_code_required = field.rhs.as_bool(),
                    // "send_type" => offer.credential_issuer = field.rhs,
                    _ => {
                        println!("unknown field: {}", field.lhs);
                        //Err(cursor.error("no `@` was found after this point"))
                    }
                }
            }
        }

        Ok(offer)
    }
}

struct OfferField {
    lhs: String,
    rhs: FieldKind,
}

enum FieldKind {
    String(String),
    Bool(bool),
}

impl FieldKind {
    fn as_string(&self) -> String {
        match self {
            Self::String(s) => s.clone(),
            _ => String::new(),
        }
    }

    const fn as_bool(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            _ => false,
        }
    }
}

impl Parse for OfferField {
    fn parse(input: ParseStream) -> Result<Self> {
        let lhs = input.parse::<syn::LitStr>()?;
        input.parse::<Token![:]>()?;

        let l = input.lookahead1();
        let rhs = if l.peek(syn::LitStr) {
            FieldKind::String(input.parse::<syn::LitStr>()?.value())
        } else if l.peek(syn::LitBool) {
            FieldKind::Bool(input.parse::<syn::LitBool>()?.value())
        } else {
            FieldKind::String(input.parse::<syn::LitStr>()?.value())
        };

        Ok(Self {
            lhs: lhs.value(),
            rhs,
        })
    }
}

// fn skip(input: ParseStream) -> Result<()> {
//     input.step(|cursor| {
//         let mut rest = *cursor;
//         while let Some((tt, next)) = rest.token_tree() {
//             match &tt {
//                 TokenTree::Punct(punct) if punct.as_char() == '@' => {
//                     return Ok(((), next));
//                 }
//                 _ => rest = next,
//             }
//         }
//         // Err(cursor.error("no `@` was found after this point"))
//         Ok(((), rest))
//     })
// }
