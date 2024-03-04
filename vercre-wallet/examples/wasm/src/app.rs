use gloo_console::log;
use vercre_core::callback;
use vercre_wallet::app::View;
use vercre_wallet::{credential, Event};
use yew::prelude::*;

use crate::core::{Core, Message, self};
use crate::credentials::{Credentials, CredentialsProps};
use crate::shell::{HeaderProps, Shell, ShellProps};

#[function_component(App)]
pub(crate) fn app() -> Html {
    let core = use_state(|| core::new());
    let view = core.view();

    use_effect_with(core.view(), |view| {
        log!("app effect");
        log!(format!("view: {:?}", view));
    });

    let on_load_credentials: Callback<()> = Callback::from(move |_| {
        core::update(&core.clone(), Event::Credential(credential::Event::List), &Callback::noop());
    });

    html! {
        <Shell>
            <h1>{"Credibil Wallet"}</h1>
            <p>{"Rust Core, Rust Shell (Yew)"}</p>
            if view.view  == View::Credential {
                <Credentials 
                    credentials={view.credential.credentials.clone()}
                    {on_load_credentials}
                />
            }
        </Shell>
    }
}
