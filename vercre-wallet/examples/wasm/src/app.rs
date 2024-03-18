use gloo_console::log;
use vercre_core::callback;
use vercre_wallet::{credential, Event};
use yew::prelude::*;

use crate::core::{self, Core, Message};
use crate::credentials::{Credentials, CredentialsProps};
use crate::shell::{HeaderProps, Shell, ShellProps};

#[derive(Default)]
pub struct App {
    core: Core,
}

impl Component for App {
    type Message = Message;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self { core: core::new() }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        let link = ctx.link().clone();
        let callback = Callback::from(move |msg| {
            link.send_message(msg);
        });
        if let Message::Event(event) = msg {
            core::update(&self.core, event, &callback);
            false
        } else {
            true
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        let view = self.core.view();

        html! {
            <Shell>
                <h1>{"Credibil Wallet"}</h1>
                <p>{"Rust Core, Rust Shell (Yew)"}</p>
                if view.view  == "Credential" {
                    <Credentials
                        credentials={serde_json::from_str::<Vec<credential::Credential>>(&view.credential.credentials).expect("should deserialize")}
                        on_load_credentials={link.callback(|_| Message::Event(Event::Credential(credential::Event::List)))}
                    />
                }
            </Shell>
        }
    }
}
