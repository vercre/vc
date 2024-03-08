use std::rc::Rc;

use gloo_console::log;
use vercre_wallet::credential::{self, Credential, CredentialDisplay};
use vercre_wallet::Event;
use yew::prelude::*;

use crate::core::{update, Message};

#[derive(Clone, PartialEq, Properties)]
pub(crate) struct CredentialsProps {
    pub credentials: Vec<Credential>,
    pub on_load_credentials: Callback<()>,
}

#[function_component(Credentials)]
pub(crate) fn credentials(props: &CredentialsProps) -> Html {
    // props.clone().on_load_credentials.emit(());

    html! {
        <ul>
            { for props.credentials.iter().map(|credential| html! {
                <li>{display_props(credential.clone()).name}</li>
            }) }
        </ul>
    }
}

struct VcCardProps {
    name: String,
}

fn display_props(credential: Credential) -> VcCardProps {
    let mut config = CredentialDisplay::default();
    if let Some(display) = credential.metadata.display {
        for d in display {
            if let Some(locale) = d.locale.clone() {
                if locale == "en-NZ" {
                    config = d.clone();
                    break;
                }
            }
        }
    }
    VcCardProps {
        name: config.name.clone(),
    }
}
