use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_std::task::spawn;
use crossbeam_channel::Sender;
use futures::TryStreamExt;
use tracing::error;
use vercre_wallet::issuance::{App, Capabilities, Effect, Event};
use vercre_wallet::store;

use crate::http;

pub type Core = Arc<vercre_wallet::Core<Effect, App>>;

pub fn new() -> Core {
    Arc::new(vercre_wallet::Core::new::<Capabilities>())
}

pub fn update(core: &Core, event: Event, tx: &Arc<Sender<Effect>>) -> Result<()> {
    debug!("event: {:?}", event);

    for effect in core.process_event(event) {
        process_effect(core, effect, tx)?;
    }
    Ok(())
}

pub fn process_effect(core: &Core, effect: Effect, tx: &Arc<Sender<Effect>>) -> Result<()> {
    debug!("effect: {:?}", effect);

    match effect {
        render @ Effect::Render(_) => {
            tx.send(render).map_err(|e| anyhow!("{:?}", e))?;
        }

        Effect::Http(mut request) => {
            spawn({
                let core = core.clone();
                let tx = tx.clone();

                async move {
                    let response = http::request(&request.operation).await?;

                    for effect in core.resolve(&mut request, response) {
                        process_effect(&core, effect, &tx)?;
                    }
                    Result::<()>::Ok(())
                }
            });
        }
        Effect::Store(mut _request) => {
            spawn({
                let core = core.clone();
                let tx = tx.clone();

                async move {
                    // let mut stream = vc::request(&request.operation).await?;

                    // while let Ok(Some(response)) = stream.try_next().await {
                    //     for effect in core.resolve(&mut request, response) {
                    //         process_effect(&core, effect, &tx)?;
                    //     }
                    // }
                    Result::<()>::Ok(())
                }
            });
        }
        Effect::Signer(_) => todo!("implement signer effect"),
        Effect::Delay(_) => todo!("implement signer effect"),
    }
    Ok(())
}
