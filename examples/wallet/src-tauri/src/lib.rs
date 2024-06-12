//! # Wallet Tauri Entry Point
//!
//! This module is the entry point for the Tauri application.

#![allow(clippy::used_underscore_binding)]

mod app;
mod error;
mod model;
mod store;

use futures::lock::Mutex;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_log::{Target, TargetKind};

use app::AppState;
use model::ViewModel;
use store::Store;

struct StateModel(Mutex<AppState>);

/// Tauri entry point
///
/// # Panics
///
/// Will panic if the Tauri application builder fails to run.
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
        .manage(StateModel(Mutex::new(AppState::default())))
        .invoke_handler(tauri::generate_handler![
            start, // called by the shell on load.
            reset, // called when the shell application has finished it's initialisation.
            // accept, authorize, cancel, delete, get_list, set_pin, start, offer, present
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// The `start` command is called by the shell on load.
#[tauri::command]
async fn start(state: State<'_, StateModel>, app: AppHandle) -> Result<(), error::AppError> {
    let model = state.0.lock().await.clone();
    let view: ViewModel = model.into();
    app.emit("state_updated", view).map_err(error::AppError::from)?;
    Ok(())
}

/// The `reset` command is called whenever the shell finishes a workflow, including abandoning it.
/// Is also called by the shell after start-up is complete to initialise state.
#[tauri::command]
async fn reset(state: State<'_, StateModel>, app: AppHandle) -> Result<(), error::AppError> {
    let mut model = state.0.lock().await;
    let store = Store::new(app.clone());
    model.reset(store).await?;
    let view: ViewModel = model.clone().into();
    app.emit("state_updated", view).map_err(error::AppError::from)?;
    Ok(())
}
