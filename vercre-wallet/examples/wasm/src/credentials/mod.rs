use gloo_console::log;
use vercre_wallet::credential::{Credential, CredentialDisplay};
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub(crate) struct CredentialsProps {
    pub credentials: Vec<Credential>
}

#[function_component(Credentials)]
pub(crate) fn credentials(props: &CredentialsProps) -> Html {

    use_effect_with(props.credentials.clone(), |credentials| {
        log!("credentials effect");
    });

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