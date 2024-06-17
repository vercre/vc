//! # Wallet Tauri Entry Point
//!
//! This module is the entry point for the Tauri application.

#![allow(clippy::used_underscore_binding)]

mod app;
mod error;
mod provider;
mod view;

use std::collections::HashMap;
use std::sync::Arc;

use app::AppState;
use futures::lock::Mutex;
use provider::Provider;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_log::{Target, TargetKind};
use view::credential::CredentialDetail;
use view::ViewModel;

struct StateModel {
    app_state: Mutex<AppState>,
    state_store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

/// Unique identifier for this wallet application as a client of the issuance service. In a real
/// application, this may be provided by registering the client with the issuer.
pub const CLIENT_ID: &str = "wallet";

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
        .manage(StateModel {
            app_state: Mutex::new(AppState::default()),
            state_store: Arc::new(Mutex::new(HashMap::<String, Vec<u8>>::new())),
        })
        .invoke_handler(tauri::generate_handler![
            start,  // called by the shell on load.
            reset,  // called when the shell application has finished it's initialisation.
            select, // select a credential to view the detail.
            delete, // delete a credential.
            offer,  // submit a credential issuance offer directly from shell input.
            accept, // accept a credential issuance offer.
            pin,    // set a user PIN on the token request.
            get_credentials, // get the credentials for the accepted issuance offer.
                    // accept, authorize, cancel, delete, get_list, set_pin, start, offer, present
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

//-----------------------------------------------------------------------------------------------
// Global State and Credential Management Commands
//-----------------------------------------------------------------------------------------------

/// The `start` command is called by the shell on load.
#[tauri::command]
async fn start(state: State<'_, StateModel>, app: AppHandle) -> Result<(), error::AppError> {
    log::info!("start invoked");
    let mut app_state = state.app_state.lock().await;
    app_state.init();
    let view: ViewModel = app_state.clone().into();
    log::info!("emitting state_updated");
    app.emit("state_updated", view).map_err(error::AppError::from)?;
    Ok(())
}

/// The `reset` command is called whenever the shell finishes a workflow, including abandoning it.
/// Is also called by the shell after start-up is complete to initialise state.
#[tauri::command]
async fn reset(state: State<'_, StateModel>, app: AppHandle) -> Result<(), error::AppError> {
    log::info!("reset invoked");
    let mut app_state = state.app_state.lock().await;
    let store = Provider::new(app.clone(), state.state_store.clone());
    app_state.reset(store).await?;
    let view: ViewModel = app_state.clone().into();
    log::info!("emitting state_updated");
    app.emit("state_updated", view).map_err(error::AppError::from)?;
    Ok(())
}

/// The `select` command returns credential claims details.
#[tauri::command]
async fn select(
    state: State<'_, StateModel>, id: String,
) -> Result<Option<CredentialDetail>, error::AppError> {
    log::info!("select invoked");
    let app_state = state.app_state.lock().await;
    let Some(credential) = app_state.credential.iter().find(|c| c.id == id) else {
        return Ok(None);
    };
    Ok(Some(credential.into()))
}

/// The `delete` command deletes a credential from storage and updates the view model.
#[tauri::command]
async fn delete(
    state: State<'_, StateModel>, app: AppHandle, id: String,
) -> Result<(), error::AppError> {
    log::info!("delete invoked");
    let mut app_state = state.app_state.lock().await;
    let store = Provider::new(app.clone(), state.state_store.clone());
    app_state.delete(&id, store).await?;
    let view: ViewModel = app_state.clone().into();
    log::info!("emitting state_updated");
    app.emit("state_updated", view).map_err(error::AppError::from)?;
    Ok(())
}

//-----------------------------------------------------------------------------------------------
// Issuance Commands
//-----------------------------------------------------------------------------------------------

/// The `offer` command submits a credential issuance offer directly from shell input. Performs the
/// same operation as the deep link listener but is useful for demo and testing purposes.
#[tauri::command]
async fn offer(
    state: State<'_, StateModel>, app: AppHandle, encoded_offer: String,
) -> Result<(), error::AppError> {
    log::info!("offer invoked: {encoded_offer}");
    let mut app_state = state.app_state.lock().await;
    let provider = Provider::new(app.clone(), state.state_store.clone());
    app_state.offer(&encoded_offer, provider).await?;
    let view: ViewModel = app_state.clone().into();
    log::info!("emitting state_updated");
    app.emit("state_updated", view).map_err(error::AppError::from)?;
    Ok(())
}

/// The `accept` command accepts a credential issuance offer. This will emit a status update to
/// indicate the holder has accepted the offer and we can proceed directly to getting the
/// credentials or a further PIN is required.
#[tauri::command]
async fn accept(state: State<'_, StateModel>, app: AppHandle) -> Result<(), error::AppError> {
    log::info!("accept invoked");
    let mut app_state = state.app_state.lock().await;
    let provider = Provider::new(app.clone(), state.state_store.clone());
    app_state.accept(provider).await?;
    let view: ViewModel = app_state.clone().into();
    log::info!("emitting state_updated");
    app.emit("state_updated", view).map_err(error::AppError::from)?;
    Ok(())
}

/// The `pin` command sets a user PIN on for use in the token request as part of the issuance flow.
/// The flow will proceed from token request to credential issuance and emit a status update.
#[tauri::command]
async fn pin(state: State<'_, StateModel>, app: AppHandle, pin: String) -> Result<(), error::AppError> {
    log::info!("pin invoked");
    let mut app_state = state.app_state.lock().await;
    let provider = Provider::new(app.clone(), state.state_store.clone());
    app_state.pin(provider, &pin).await?;
    let view: ViewModel = app_state.clone().into();
    log::info!("emitting state_updated");
    app.emit("state_updated", view).map_err(error::AppError::from)?;
    Ok(())
}

/// The `get_credentials` command gets the credentials for the accepted issuance offer using the
/// `get_credentials` endpoint in the `vercre-holder` crate.
#[tauri::command]
async fn get_credentials(
    state: State<'_, StateModel>, app: AppHandle,
) -> Result<(), error::AppError> {
    log::info!("get_credentials invoked");
    let mut app_state = state.app_state.lock().await;
    let provider = Provider::new(app.clone(), state.state_store.clone());
    app_state.get_credentials(provider).await?;
    let view: ViewModel = app_state.clone().into();
    log::info!("emitting state_updated");
    app.emit("state_updated", view).map_err(error::AppError::from)?;
    Ok(())
}
