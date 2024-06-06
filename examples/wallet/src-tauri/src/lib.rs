//! # Wallet Tauri Entry Point
//!
//! This module is the entry point for the Tauri application.

mod error;
mod signer;

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_log::{Target, TargetKind};
use vercre_wallet::issuance::Status;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Model {
    status: Status,
}

struct StateModel(Mutex<Model>);

/// Tauri entry point
#[cfg_attr(mobile, tauri::mobile_entry_point)]
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
            let _handle = app.handle().clone();

            // initialise stronghold
            // FIXME: get passphrase from user and salt from file(?)
            let passphrase = b"pass-phrase";
            let salt = b"randomsalt";
            let _hash = argon2::hash_raw(passphrase, salt, &argon2::Config::default())?;

            // open/initialize Stronghold snapshot
            // let path = handle.path().app_local_data_dir()?.join("stronghold.bin");
            // let stronghold = signer::Stronghold::new(path, hash)?;
            // handle.manage(stronghold);

            // initialise deep link listener
            // app.listen("deep-link://new-url", move |event| deep_link(&event, &handle));

            Ok(())
        })
        .manage(StateModel(Mutex::new(Model {
            status: Status::default(),
        })))
        .invoke_handler(tauri::generate_handler![
            update_status,
            // accept, authorize, cancel, delete, get_list, set_pin, start, offer, present
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
async fn update_status(
    status: Status, state: State<'_, StateModel>, app: AppHandle,
) -> Result<(), error::AppError> {
    let mut model = state.0.lock().unwrap();
    (*model).status = status;
    app.emit("status_updated", model.clone()).map_err(|e| error::AppError::from(e))?;
    Ok(())
}
