use gloo_console::log;
use vercre_wallet::app::View;
use yew::prelude::*;

use crate::core::{Core, Message, self};
use crate::credentials::{Credentials, CredentialsProps};
use crate::shell::{HeaderProps, Shell, ShellProps};

#[function_component(App)]
pub(crate) fn app() -> Html {
    let core = use_state(|| core::new());

    use_effect_with(core.view(), |view| {
        log!("app effect");
        log!(format!("view: {:?}", view));
    });

    html! {
        <Shell>
            <h1>{"Credibil Wallet"}</h1>
            <p>{"Rust Core, Rust Shell (Yew)"}</p>
            if core.view().view == View::Credential {
                <Credentials credentials={core.view().credential.credentials.clone()} />
            }
        </Shell>
    }
}
