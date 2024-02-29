#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

mod app;
mod components;
mod core;
mod http;
mod shell;
mod signer;

use yew::prelude::*;

use crate::app::App;
// use crate::core::{Core, Message};

fn main() {
    yew::Renderer::<App>::new().render();
}


// #[derive(Default)]
// struct RootComponent {
//     core: Core,
// }

// impl Component for RootComponent {
//     type Message = Message;
//     type Properties = ();

//     fn create(ctx: &Context<Self>) -> Self {
//         // ctx.link().send_message(Message::Event(Event::StartWatch));

//         Self { core: core::new() }
//     }

//     fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
//         let link = ctx.link().clone();
//         let callback = Callback::from(move |msg| {
//             link.send_message(msg);
//         });
//         if let Message::Event(event) = msg {
//             core::update(&self.core, event, &callback);
//             false
//         } else {
//             true
//         }
//     }

//     fn view(&self, ctx: &Context<Self>) -> Html {
//         let link = ctx.link();
//         let view = self.core.view();

//         html! {
//             <>
//                 <section class="section has-text-centered">
//                     <h1>{"Credibil Wallet"}</h1>
//                     <p>{"Rust Core, Rust Shell (Yew)"}</p>
//                 </section>
//                 <section class="container has-text-centered">
//                     // <p class="is-size-5">{&view.offer.credential_issuer}</p>
//                     <div class="buttons section is-centered">
//                         // <button class="button is-primary is-warning"
//                         //     onclick={link.callback(|_| Message::Event(Event::Decrement))}>
//                         //     {"Decrement"}
//                         // </button>
//                         // <button class="button is-primary is-danger"
//                         //     onclick={link.callback(|_| Message::Event(Event::Increment))}>
//                         //     {"Increment"}
//                         // </button>
//                     </div>
//                 </section>
//             </>
//         }
//     }
// }

