// #![warn(missing_docs)]
#![warn(unused_extern_crates)]
#![feature(let_chains)]

//! # `OpenID` Wallet
//!
//! A vercre-wallet app that support `OpenID` for Verifiable Credential Issuance and
//! Presentation.
//!
//! The app is based on Red Badger's experimental [CRUX](https://redbadger.github.io/crux/overview.html)
//! framework, for cross-platform applications.
//!
//! The application is split into two parts; the core business logic (this
//! library) built in Rust, and a platform-specific shell (Swift, Kotlin,
//! TypeScript) to manage user interactions.

// TODO: implement server metatdata endpoint
// TODO: implement client registration/ client metadata endpoints

// TODO: support [SIOPv2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)(https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)
//        - add Token endpoint
//        - add Metadata endpoint
//        - add Registration endpoint

pub mod app;
pub mod capabilities;
pub mod credential;
pub mod issuance;
pub mod presentation;
pub mod typegen;

pub use app::{App, Capabilities, Effect, Event};
pub use capabilities::{signer, store};
pub use crux_core::bridge::{Bridge, Request};
pub use crux_core::Core;
pub use crux_http as http;
use lazy_static::lazy_static;
use wasm_bindgen::prelude::wasm_bindgen;

uniffi::include_scaffolding!("shared");

lazy_static! {
    static ref CORE: Bridge<Effect, App> = Bridge::new(Core::new::<Capabilities>());
}

/// FFI interface to receive an event from the shell.
#[wasm_bindgen]
#[must_use]
pub fn process_event(data: &[u8]) -> Vec<u8> {
    CORE.process_event(data)
}

/// FFI interface to receive a response to a capability request from the shell.
///
/// The `output` is serialized capability output. It will be deserialized by the
/// core. The `uuid` MUST match the `uuid` of the effect that triggered it, else
/// the core will panic.
#[wasm_bindgen]
#[must_use]
pub fn handle_response(uuid: &[u8], data: &[u8]) -> Vec<u8> {
    CORE.handle_response(uuid, data)
}

/// FFI interface to get the current state of the app's view model (serialized).
#[wasm_bindgen]
#[must_use]
pub fn view() -> Vec<u8> {
    CORE.view()
}
