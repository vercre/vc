mod error;
#[path = "http.rs"]
mod http_loc;
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
///
/// # Panics
// #[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(
            tauri_plugin_log::Builder::default()
                .targets([Target::new(TargetKind::Stdout), Target::new(TargetKind::Webview)])
                .level(log::LevelFilter::Info)
                .build(),
        )
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let handle = app.handle().clone();

            // initialise stronghold
            // FIXME: get passphrase from user and salt from file(?)
            let passphrase = b"pass-phrase";
            let salt = b"randomsalt";
            let hash = argon2::hash_raw(passphrase, salt, &argon2::Config::default())?;

            // open/initialize Stronghold snapshot
            let path = handle.path().app_local_data_dir()?.join("stronghold.bin");
            let stronghold = signer::Stronghold::new(path, hash)?;
            handle.manage(stronghold);

            // initialise deep link listener
            app.listen("deep-link://new-url", move |event| deep_link(&event, &handle));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            accept, authorize, cancel, delete, get_list, set_pin, start, offer, present
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// Handle deep links
fn deep_link(event: &tauri::Event, handle: &AppHandle) {
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
async fn start(handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Start, &handle)
}

#[tauri::command]
async fn cancel(handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Cancel, &handle)
}

// ----------------------------------------------------------------------------
// Credential management
// ----------------------------------------------------------------------------
#[tauri::command]
async fn get_list(_filter: String, handle: AppHandle) -> Result<(), error::Error> {
    // TODO: build filter from query string
    process_event(Event::Credential(credential::Event::List), &handle)
}

#[tauri::command]
async fn delete(id: String, handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Credential(credential::Event::Delete(id)), &handle)
}

// ----------------------------------------------------------------------------
// Issuance flow
// ----------------------------------------------------------------------------
#[tauri::command]
async fn offer(url: String, handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Issuance(issuance::Event::Offer(url)), &handle)
}

#[tauri::command]
async fn accept(handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Issuance(issuance::Event::Accept), &handle)
}

#[tauri::command]
async fn set_pin(pin: String, handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Issuance(issuance::Event::Pin(pin)), &handle)
}

// ----------------------------------------------------------------------------
// Presentation flow
// ----------------------------------------------------------------------------
#[tauri::command]
async fn present(url: String, handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Presentation(presentation::Event::Requested(url)), &handle)
}

#[tauri::command]
async fn authorize(handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Presentation(presentation::Event::Authorized), &handle)
}

// Trigger an App event and process the resulting effects.
fn process_event(event: Event, handle: &AppHandle) -> Result<(), error::Error> {
    for effect in CORE.process_event(event) {
        process_effect(effect, handle.clone())?;
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
                    let response = match store::request(&request.operation, &handle) {
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
                    let response = match signer::request(&request.operation, &handle) {
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
