use std::rc::Rc;

use futures_util::TryStreamExt;
use gloo_console::log;
use vercre_wallet::{App, Capabilities, Effect, Event};
use yew::platform::spawn_local;
use yew::Callback;

use crate::http;

pub type Core = Rc<vercre_wallet::Core<Effect, App>>;

pub enum Message {
    Event(Event),
    Effect(Effect),
}

pub fn new() -> Core {
    Rc::new(vercre_wallet::Core::new::<Capabilities>())
}

pub fn update(core: &Core, event: Event, callback: &Callback<Message>) {
    log!(format!("event: {:?}", event));

    for effect in core.process_event(event) {
        process_effect(core, effect, callback);
    }
}

pub fn process_effect(core: &Core, effect: Effect, callback: &Callback<Message>) {
    log!(format!("effect: {:?}", effect));
    match effect {
        render @ Effect::Render(_) => callback.emit(Message::Effect(render)),

        Effect::Http(mut request) => {
            spawn_local({
                let core = core.clone();
                let callback = callback.clone();

                async move {
                    let response = http::request(&request.operation).await.unwrap();

                    for effect in core.resolve(&mut request, response) {
                        process_effect(&core, effect, &callback);
                    }
                }
            });
        }
        Effect::Store(mut _request) => {
            spawn_local({
                let core = core.clone();
                let callback = callback.clone();

                async move {
                    //   let mut stream = sse::request(&request.operation).await.unwrap();

                    //   while let Ok(Some(response)) = stream.try_next().await {
                    //       for effect in core.resolve(&mut request, response) {
                    //           process_effect(&core, effect, &callback);
                    //       }
                    //   }
                }
            });
        }
        Effect::Signer(_) => {
            todo!("implement effect")
        }
        Effect::Delay(duration) => {
            todo!("implement effect")
        }
    }
}
