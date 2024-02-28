use yew::prelude::*;

use crate::shell::Shell;

#[function_component(App)]
pub(crate) fn app() -> Html {
    html! {
        <Shell>
            <h1>{"Credibil Wallet"}</h1>
            <p>{"Rust Core, Rust Shell (Yew)"}</p>
        </Shell>
    }
}
