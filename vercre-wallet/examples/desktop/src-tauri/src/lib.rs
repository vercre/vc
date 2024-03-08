mod error;
#[path = "http.rs"]
mod http_loc;
mod iroh_node;
mod signer;
mod store;

use std::sync::Arc;

use lazy_static::lazy_static;
use tauri::{AppHandle, Manager};
use tauri_plugin_log::{Target, TargetKind};
use vercre_wallet::signer::SignerResponse;
use vercre_wallet::store::StoreResponse;
use vercre_wallet::{credential, issuance, presentation, App, Capabilities, Core, Effect, Event};

lazy_static! {
    static ref CORE: Arc<Core<Effect, App>> = Arc::new(Core::new::<Capabilities>());
}

/// Tauri entry point
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(
            tauri_plugin_log::Builder::default()
                .targets([Target::new(TargetKind::Stdout), Target::new(TargetKind::Webview)])
                .level(log::LevelFilter::Error)
                .build(),
        )
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let handle = app.handle().clone();

            init_store(handle.clone())?;
            init_stronghold(handle.clone())?;

            // initialise deep link listener
            app.listen("deep-link://new-url", move |event| deep_link(event, handle.clone()));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            accept, authorize, cancel, delete, get_list, set_pin, start, offer, present
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

const VC_STORE: &str = "docaaacbp4ivplq3xf7krm3y5zybzjv2ha56qvhpfiykjjc6iukdifgoyihafk62aofuwwwu5zb5ocvzj5v3rtqt6siglyuhoxhqtu4fxravvoteajcnb2hi4dthixs65ltmuys2mjomrsxe4bonfzg62bonzsxi53pojvs4lydaac2cyt22erablaraaa5ciqbfiaqj7ya6cbpuaaaaaaaaaaaahjce";
use futures::StreamExt;
use tokio::sync::Mutex;

use crate::iroh_node::{DocType, Node};

fn init_store(handle: tauri::AppHandle) -> anyhow::Result<()> {
    // ~/Library/Application Support/io.credibil.wallet/iroh
    let path = handle.path().app_local_data_dir()?.join("iroh");

    tauri::async_runtime::spawn(async move {
        let mut node = Node::new(path).await.expect("should start node");
        node.load_doc(DocType::Credential, VC_STORE).await.expect("should join doc");

        let state = IrohState {
            node,
            _events: Mutex::new(None),
        };
        handle.manage(state);
    });

    Ok(())
}

pub struct IrohState {
    node: Node,
    _events: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl IrohState {
    async fn init(&self, handle: tauri::AppHandle) -> anyhow::Result<()> {
        let node = self.node.clone();

        let events_handle = tokio::spawn(async move {
            let mut events = node.events().await;
            while let Some(event) = events.next().await {
                match event {
                    _ => {
                        println!("{:?}", event);
                        process_event(Event::Credential(credential::Event::List), handle.clone())
                            .expect("should process event")
                    }
                }
            }
        });

        let mut events = self._events.lock().await;
        if let Some(handle) = events.take() {
            handle.abort();
        }
        *events = Some(events_handle);

        Ok(())
    }
}

fn init_stronghold(handle: tauri::AppHandle) -> anyhow::Result<()> {
    // FIXME: get passphrase from user and salt from file(?)
    let passphrase = b"pass-phrase";
    let salt = b"randomsalt";
    let hash = argon2::hash_raw(passphrase, salt, &argon2::Config::default())?;

    // open/initialize Stronghold snapshot
    let path = handle.path().app_local_data_dir()?.join("stronghold.bin");
    let stronghold = signer::Stronghold::new(&path, hash)?;
    handle.manage(stronghold);

    Ok(())
}

// Handle deep links
fn deep_link(event: tauri::Event, handle: AppHandle) {
    // credential offer
    const OFFER_PREFIX: &str = "openid-vc://credential_offer?credential_offer=";
    const REQUEST_PREFIX: &str = "openid-vc://request_uri=";

    // trim '[]' wrapping payload
    let payload = event.payload();
    let Some(link) = payload.get(2..payload.len() - 2) else {
        return;
    };

    if link.starts_with(OFFER_PREFIX) {
        let offer = link.strip_prefix(OFFER_PREFIX).unwrap_or_default();
        let _ = process_event(Event::Issuance(issuance::Event::Offer(offer.to_string())), handle);
    } else if link.starts_with(REQUEST_PREFIX) {
        let request = link.strip_prefix(REQUEST_PREFIX).unwrap_or_default();
        let _ = process_event(
            Event::Presentation(presentation::Event::Requested(request.to_string())),
            handle,
        );
    }
}

// ----------------------------------------------------------------------------
// App lifecycle
// ----------------------------------------------------------------------------
#[tauri::command]
async fn start(handle: AppHandle, state: tauri::State<'_, IrohState>) -> Result<(), error::Error> {
    state.init(handle.clone()).await?;
    process_event(Event::Start, handle)
}

#[tauri::command]
async fn cancel(handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Cancel, handle)
}

// ----------------------------------------------------------------------------
// Credential management
// ----------------------------------------------------------------------------
#[tauri::command]
async fn get_list(_filter: String, handle: AppHandle) -> Result<(), error::Error> {
    // TODO: build filter from query string
    process_event(Event::Credential(credential::Event::List), handle)
}

#[tauri::command]
async fn delete(id: String, handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Credential(credential::Event::Delete(id)), handle)
}

// ----------------------------------------------------------------------------
// Issuance flow
// ----------------------------------------------------------------------------
#[tauri::command]
async fn offer(url: String, handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Issuance(issuance::Event::Offer(url)), handle)
}

#[tauri::command]
async fn accept(handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Issuance(issuance::Event::Accept), handle)
}

#[tauri::command]
async fn set_pin(pin: String, handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Issuance(issuance::Event::Pin(pin)), handle)
}

// ----------------------------------------------------------------------------
// Presentation flow
// ----------------------------------------------------------------------------
#[tauri::command]
async fn present(url: String, handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Presentation(presentation::Event::Requested(url)), handle)
}

#[tauri::command]
async fn authorize(handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Presentation(presentation::Event::Authorized), handle)
}

// Trigger an App event and process the resulting effects.
fn process_event(event: Event, handle: AppHandle) -> Result<(), error::Error> {
    for effect in CORE.process_event(event) {
        process_effect(effect, handle.clone())?
    }
    Ok(())
}

// Process `Capability` effects.
fn process_effect(effect: Effect, handle: AppHandle) -> Result<(), error::Error> {
    match effect {
        Effect::Render(_) => handle.emit("render", CORE.view()).map_err(error::Error::Tauri),
        Effect::Http(mut request) => {
            tauri::async_runtime::spawn({
                async move {
                    let result = http_loc::request(&request.operation)
                        .await
                        .expect("error processing Http effect");

                    for effect in CORE.resolve(&mut request, result) {
                        let _ = process_effect(effect, handle.clone());
                    }
                }
            });

            Ok(())
        }
        Effect::Store(mut request) => {
            tauri::async_runtime::spawn({
                async move {
                    let response = match store::request(&request.operation, &handle).await {
                        Ok(resp) => resp,
                        Err(err) => StoreResponse::Err(err.to_string()),
                    };

                    for effect in CORE.resolve(&mut request, response) {
                        let _ = process_effect(effect, handle.clone());
                    }
                }
            });

            Ok(())
        }
        Effect::Signer(mut request) => {
            tauri::async_runtime::spawn({
                async move {
                    let response = match signer::request(&request.operation, &handle).await {
                        Ok(resp) => resp,
                        Err(err) => SignerResponse::Err(err.to_string()),
                    };

                    for effect in CORE.resolve(&mut request, response) {
                        let _ = process_effect(effect, handle.clone());
                    }
                }
            });

            Ok(())
        }
        Effect::Delay(mut request) => {
            tauri::async_runtime::spawn({
                async move {
                    let response = ();
                    std::thread::sleep(std::time::Duration::from_millis(
                        request.operation.delay_ms,
                    ));

                    for effect in CORE.resolve(&mut request, response) {
                        let _ = process_effect(effect, handle.clone());
                    }
                }
            });

            Ok(())
        }
    }
}
