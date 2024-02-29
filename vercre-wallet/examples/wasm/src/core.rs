use std::rc::Rc;

use futures_util::TryStreamExt;
use gloo_console::log;
use vercre_wallet::{http::protocol::HttpResult, signer::SignerResponse, App, Capabilities, Effect, Event};
use yew::platform::spawn_local;
use yew::{callback, Callback};

use crate::http;
use crate::signer;

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
                    let response = http::request(&request.operation)
                        .await
                        .expect("error processing http effect");

                    for effect in core.resolve(&mut request, HttpResult::Ok(response)) {
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
        Effect::Signer(mut request) => {
            spawn_local({
                let core = core.clone();
                let callback = callback.clone();

                async move {
                    let response = match signer::request(&request.operation).await {
                        Ok(resp) => resp,
                        Err(err) => SignerResponse::Err(err.unwrap_or_default()),
                    };
                    for effect in core.resolve(&mut request, response) {
                        process_effect(&core, effect, &callback);
                    }
                }
            });
        }
        Effect::Delay(mut request) => {
            spawn_local({
                let core = core.clone();
                let callback = callback.clone();

                async move {
                    let response = ();
                    std::thread::sleep(std::time::Duration::from_millis(
                        request.operation.delay_ms,
                    ));
                    for effect in core.resolve(&mut request, response) {
                        process_effect(&core, effect, &callback);
                    }
                }
            });
        }
    }
}
