use gloo_console::log;
use yew::prelude::*;

use crate::core::{Core, Message, self};
use crate::shell::Shell;

#[function_component(App)]
pub(crate) fn app() -> Html {
    // let core = use_state(|| core::new());
    let wibble = use_state(|| [0, 0]);

    use_effect_with(wibble.clone(), |wibble| {
        log!("effect");
        if wibble[0] == 0 {
            log!("setting wibble");
            wibble.set([1, 2]);
        }
    });

    html! {
        <Shell>
            <h1>{"Credibil Wallet"}</h1>
            <p>{"Rust Core, Rust Shell (Yew)"}</p>
            <p>{wibble[0]}</p>
            <p>{wibble[1]}</p>
        </Shell>
    }
}
