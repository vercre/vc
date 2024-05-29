//! # Wallet Credential Data Model
//!
//! This module provides a data model suitable for storing a credential in a wallet so that it can
//! be displayed offline and used in presentation with minimal rebuilding.

use std::ops::Deref;

use serde::{Deserialize, Serialize};
use vercre_core::metadata::CredentialConfiguration;
use vercre_core::w3c::VerifiableCredential;

/// The Credential model contains information about a credential owned by the
/// Wallet.
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credential {
    /// Credential `id` is the credential's unique identifier
    /// (from Verifiable Credential `id`).
    pub id: String,

    /// The credential issuer.
    pub issuer: String,

    /// The unpacked Verifiable Credential. Used to display VC details and for `JSONPath`
    /// Presentation Definition queries.
    pub vc: VerifiableCredential,

    /// `CredentialConfiguration` metadata
    pub metadata: CredentialConfiguration,

    /// The Verifiable Credential as issued, for use in Presentation Submissions.
    /// This could be a base64-encoded JWT or 'stringified' JSON.
    pub issued: String,

    /// A base64-encoded logo image for the credential ingested from the logo url in the
    /// display section of the metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<Logo>,
}

/// Use Deref to access the `VerifiableCredential` fields directly.
impl Deref for Credential {
    type Target = VerifiableCredential;

    fn deref(&self) -> &Self::Target {
        &self.vc
    }
}

/// Logo information for a credential.
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename = "EncodedLogo")]
pub struct Logo {
    /// The logo image as a base64-encoded string.
    pub image: String,

    /// Content type. e.g. "image/png"
    #[serde(rename = "mediaType")]
    pub media_type: String,
}

impl Credential {
    /// Create a new Credential.
    #[must_use]
    pub fn sample() -> Self {
        Self {
            id: String::from("61b9a42e-3dbb-4657-9a24-924a9586f233"),
            issuer: String::from("http://localhost:8080"),
            vc: VerifiableCredential::sample(),
            metadata: CredentialConfiguration::sample(),
            issued: String::from("eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aW9uOkVpRHlPUWJiWkFhM2FpUnplQ2tWN0xPeDNTRVJqakg5M0VYb0lNM1VvTjRvV2c6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKd2RXSnNhV05MWlhsTmIyUmxiREZKWkNJc0luQjFZbXhwWTB0bGVVcDNheUk2ZXlKamNuWWlPaUp6WldOd01qVTJhekVpTENKcmRIa2lPaUpGUXlJc0luZ2lPaUowV0ZOTFFsOXlkV0pZVXpkelEycFljWFZ3VmtwRmVsUmpWek5OYzJwdFJYWnhNVmx3V0c0NU5scG5JaXdpZVNJNkltUlBhV05ZY1dKcVJuaHZSMG90U3pBdFIwb3hhMGhaU25GcFkxOUVYMDlOZFZWM2ExRTNUMncyYm1zaWZTd2ljSFZ5Y0c5elpYTWlPbHNpWVhWMGFHVnVkR2xqWVhScGIyNGlMQ0pyWlhsQlozSmxaVzFsYm5RaVhTd2lkSGx3WlNJNklrVmpaSE5oVTJWamNESTFObXN4Vm1WeWFXWnBZMkYwYVc5dVMyVjVNakF4T1NKOVhTd2ljMlZ5ZG1salpYTWlPbHQ3SW1sa0lqb2ljMlZ5ZG1salpURkpaQ0lzSW5ObGNuWnBZMlZGYm1Sd2IybHVkQ0k2SW1oMGRIQTZMeTkzZDNjdWMyVnlkbWxqWlRFdVkyOXRJaXdpZEhsd1pTSTZJbk5sY25acFkyVXhWSGx3WlNKOVhYMTlYU3dpZFhCa1lYUmxRMjl0YldsMGJXVnVkQ0k2SWtWcFJFdEphM2R4VHpZNVNWQkhNM0JQYkVoclpHSTRObTVaZERCaFRuaFRTRnAxTW5JdFltaEZlbTVxWkVFaWZTd2ljM1ZtWm1sNFJHRjBZU0k2ZXlKa1pXeDBZVWhoYzJnaU9pSkZhVU5tUkZkU2JsbHNZMFE1UlVkQk0yUmZOVm94UVVoMUxXbFpjVTFpU2psdVptbHhaSG8xVXpoV1JHSm5JaXdpY21WamIzWmxjbmxEYjIxdGFYUnRaVzUwSWpvaVJXbENaazlhWkUxMFZUWlBRbmM0VUdzNE56bFJkRm90TWtvdE9VWmlZbXBUV25sdllVRmZZbkZFTkhwb1FTSjlmUSNwdWJsaWNLZXlNb2RlbDFJZCIsInR5cCI6Imp3dCJ9.eyJzdWIiOiJkaWQ6aW9uOkVpRHlPUWJiWkFhM2FpUnplQ2tWN0xPeDNTRVJqakg5M0VYb0lNM1VvTjRvV2c6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKd2RXSnNhV05MWlhsTmIyUmxiREZKWkNJc0luQjFZbXhwWTB0bGVVcDNheUk2ZXlKamNuWWlPaUp6WldOd01qVTJhekVpTENKcmRIa2lPaUpGUXlJc0luZ2lPaUowV0ZOTFFsOXlkV0pZVXpkelEycFljWFZ3VmtwRmVsUmpWek5OYzJwdFJYWnhNVmx3V0c0NU5scG5JaXdpZVNJNkltUlBhV05ZY1dKcVJuaHZSMG90U3pBdFIwb3hhMGhaU25GcFkxOUVYMDlOZFZWM2ExRTNUMncyYm1zaWZTd2ljSFZ5Y0c5elpYTWlPbHNpWVhWMGFHVnVkR2xqWVhScGIyNGlMQ0pyWlhsQlozSmxaVzFsYm5RaVhTd2lkSGx3WlNJNklrVmpaSE5oVTJWamNESTFObXN4Vm1WeWFXWnBZMkYwYVc5dVMyVjVNakF4T1NKOVhTd2ljMlZ5ZG1salpYTWlPbHQ3SW1sa0lqb2ljMlZ5ZG1salpURkpaQ0lzSW5ObGNuWnBZMlZGYm1Sd2IybHVkQ0k2SW1oMGRIQTZMeTkzZDNjdWMyVnlkbWxqWlRFdVkyOXRJaXdpZEhsd1pTSTZJbk5sY25acFkyVXhWSGx3WlNKOVhYMTlYU3dpZFhCa1lYUmxRMjl0YldsMGJXVnVkQ0k2SWtWcFJFdEphM2R4VHpZNVNWQkhNM0JQYkVoclpHSTRObTVaZERCaFRuaFRTRnAxTW5JdFltaEZlbTVxWkVFaWZTd2ljM1ZtWm1sNFJHRjBZU0k2ZXlKa1pXeDBZVWhoYzJnaU9pSkZhVU5tUkZkU2JsbHNZMFE1UlVkQk0yUmZOVm94UVVoMUxXbFpjVTFpU2psdVptbHhaSG8xVXpoV1JHSm5JaXdpY21WamIzWmxjbmxEYjIxdGFYUnRaVzUwSWpvaVJXbENaazlhWkUxMFZUWlBRbmM0VUdzNE56bFJkRm90TWtvdE9VWmlZbXBUV25sdllVRmZZbkZFTkhwb1FTSjlmUSIsImp0aSI6IkVtcGxveWVlSURfSldUIiwiaXNzIjoiaHR0cDovL2NyZWRpYmlsLmlvIiwibmJmIjoxNzAwNTIyNTE1LCJpYXQiOjE3MDA1MjI1MTUsImV4cCI6bnVsbCwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwOi8vY3JlZGliaWwuaW8vY3JlZGVudGlhbHMvdjEiXSwiaWQiOiJFbXBsb3llZUlEX0pXVCIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJFbXBsb3llZUlEQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJodHRwOi8vY3JlZGliaWwuaW8iLCJpc3N1YW5jZURhdGUiOiIyMDIzLTExLTIwVDIzOjIxOjU1LjQ4ODY1OVoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDppb246RWlEeU9RYmJaQWEzYWlSemVDa1Y3TE94M1NFUmpqSDkzRVhvSU0zVW9ONG9XZzpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUp3ZFdKc2FXTkxaWGxOYjJSbGJERkpaQ0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSnpaV053TWpVMmF6RWlMQ0pyZEhraU9pSkZReUlzSW5naU9pSjBXRk5MUWw5eWRXSllVemR6UTJwWWNYVndWa3BGZWxSalZ6Tk5jMnB0UlhaeE1WbHdXRzQ1Tmxwbklpd2llU0k2SW1SUGFXTlljV0pxUm5odlIwb3RTekF0UjBveGEwaFpTbkZwWTE5RVgwOU5kVlYzYTFFM1QydzJibXNpZlN3aWNIVnljRzl6WlhNaU9sc2lZWFYwYUdWdWRHbGpZWFJwYjI0aUxDSnJaWGxCWjNKbFpXMWxiblFpWFN3aWRIbHdaU0k2SWtWalpITmhVMlZqY0RJMU5tc3hWbVZ5YVdacFkyRjBhVzl1UzJWNU1qQXhPU0o5WFN3aWMyVnlkbWxqWlhNaU9sdDdJbWxrSWpvaWMyVnlkbWxqWlRGSlpDSXNJbk5sY25acFkyVkZibVJ3YjJsdWRDSTZJbWgwZEhBNkx5OTNkM2N1YzJWeWRtbGpaVEV1WTI5dElpd2lkSGx3WlNJNkluTmxjblpwWTJVeFZIbHdaU0o5WFgxOVhTd2lkWEJrWVhSbFEyOXRiV2wwYldWdWRDSTZJa1ZwUkV0SmEzZHhUelk1U1ZCSE0zQlBiRWhyWkdJNE5tNVpkREJoVG5oVFNGcDFNbkl0WW1oRmVtNXFaRUVpZlN3aWMzVm1abWw0UkdGMFlTSTZleUprWld4MFlVaGhjMmdpT2lKRmFVTm1SRmRTYmxsc1kwUTVSVWRCTTJSZk5Wb3hRVWgxTFdsWmNVMWlTamx1Wm1seFpIbzFVemhXUkdKbklpd2ljbVZqYjNabGNubERiMjF0YVhSdFpXNTBJam9pUldsQ1prOWFaRTEwVlRaUFFuYzRVR3M0TnpsUmRGb3RNa290T1VaaVltcFRXbmx2WVVGZlluRkVOSHBvUVNKOWZRIn0sInByb29mIjp7InR5cGUiOiIiLCJjcnlwdG9zdWl0ZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSIsInByb29mUHVycG9zZSI6IiIsInZlcmlmaWNhdGlvbk1ldGhvZCI6ImRpZDppb246RWlEeU9RYmJaQWEzYWlSemVDa1Y3TE94M1NFUmpqSDkzRVhvSU0zVW9ONG9XZzpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUp3ZFdKc2FXTkxaWGxOYjJSbGJERkpaQ0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSnpaV053TWpVMmF6RWlMQ0pyZEhraU9pSkZReUlzSW5naU9pSjBXRk5MUWw5eWRXSllVemR6UTJwWWNYVndWa3BGZWxSalZ6Tk5jMnB0UlhaeE1WbHdXRzQ1Tmxwbklpd2llU0k2SW1SUGFXTlljV0pxUm5odlIwb3RTekF0UjBveGEwaFpTbkZwWTE5RVgwOU5kVlYzYTFFM1QydzJibXNpZlN3aWNIVnljRzl6WlhNaU9sc2lZWFYwYUdWdWRHbGpZWFJwYjI0aUxDSnJaWGxCWjNKbFpXMWxiblFpWFN3aWRIbHdaU0k2SWtWalpITmhVMlZqY0RJMU5tc3hWbVZ5YVdacFkyRjBhVzl1UzJWNU1qQXhPU0o5WFN3aWMyVnlkbWxqWlhNaU9sdDdJbWxrSWpvaWMyVnlkbWxqWlRGSlpDSXNJbk5sY25acFkyVkZibVJ3YjJsdWRDSTZJbWgwZEhBNkx5OTNkM2N1YzJWeWRtbGpaVEV1WTI5dElpd2lkSGx3WlNJNkluTmxjblpwWTJVeFZIbHdaU0o5WFgxOVhTd2lkWEJrWVhSbFEyOXRiV2wwYldWdWRDSTZJa1ZwUkV0SmEzZHhUelk1U1ZCSE0zQlBiRWhyWkdJNE5tNVpkREJoVG5oVFNGcDFNbkl0WW1oRmVtNXFaRUVpZlN3aWMzVm1abWw0UkdGMFlTSTZleUprWld4MFlVaGhjMmdpT2lKRmFVTm1SRmRTYmxsc1kwUTVSVWRCTTJSZk5Wb3hRVWgxTFdsWmNVMWlTamx1Wm1seFpIbzFVemhXUkdKbklpd2ljbVZqYjNabGNubERiMjF0YVhSdFpXNTBJam9pUldsQ1prOWFaRTEwVlRaUFFuYzRVR3M0TnpsUmRGb3RNa290T1VaaVltcFRXbmx2WVVGZlluRkVOSHBvUVNKOWZRI3B1YmxpY0tleU1vZGVsMUlkIiwicHJvb2ZWYWx1ZSI6IiJ9fX0.yUsvBJDMk5rS7BjGlOT4TwUeI4IczC5RihwNSm4ErRgd8CfSdf0aEIzMGcHxxYNVaMHPV0yzM8VgC0jLsv14aQ"),
            logo: Some(Logo {
                image: String::from("iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAAGXcA1uAAAACXBIWXMAAAsSAAALEgHS3X78AAACGklEQVRIiYVV0XXbMAw8+eXf7AYagd2A2YAjeIR0A3eCagRlA20QZYJ4g6gbKBNcP3QwIZpq8B6eCIIAARwIdSQBYAEQOgkZAEzAg3ACYNLacVN1AGjHTNvZ+sltPmvdAQBIguSVG0V9R3/jqm8wVwOABOAsxQxggcwvchlIZpLRQnyWi9lcngD8BfAmN1mRrRZVYqFEMpiideDq1hbDPT9PIDnqO9X6kwIEgK97lYAewGQ10P7GSnVW+lbNIDlIvofdCinKAfTNdbyee6cLbt3XNxibt8wC8MWf2bWXa5WarBg4uYME8Cr5FcAvtzY9WmhaLoENtC2km+u/5Jona33TurcuA4Af7lB0XTftsnHXDbo+kVxY2mLHHclR3rJ8TLrJ2iLXN/hbDKAXV//o9KFGN+mwf6XeIFqVXnThnwPgDJPhCOkvfe1Fd+VEoxIsL3zlntaDfZ//jp+qUC/YHtuCDdxzpT9jw7Teh+ySsx+BMjt7AJ8NIxtLEaVhjGZsEC/ij4b9T5/O8k3a2SF64f4Z9g3b1drCxsjMbXjVtRy0H5x+kjyID7H0b8fTb5RhaBRU1zOAd5VsxXekyFudUs/zm8t0kJxaUXv2QlTqqxwlOfO1tmFrJTI8bIoPCvI+1X2ELfIRenwC99MkHtn7DKZKeZNTTwbotdof+VjqmXz8K9R1b1Ht3Ci3/PwXIG71tbGwsuCRDvYf+B9W+Cda6rdupAAAAABJRU5ErkJggg=="),
                media_type: String::from("image/png"),
            }),
        }
    }
}
// #![allow(missing_docs)]

// //! # Credential App
// //!
// //! The Credential app module implements `crux::App` for credential management.

// pub(crate) mod model;

// use crux_core::macros::Effect;
// #[cfg(feature = "typegen")]
// use crux_core::macros::Export;
// use crux_core::render::Render;
// use crux_http::Http;
// use serde::{Deserialize, Serialize};
// #[allow(clippy::module_name_repetitions)]
// pub use vercre_core::metadata::{CredentialConfiguration, CredentialDisplay};
// use vercre_core::w3c::vp::Constraints;
// #[allow(clippy::module_name_repetitions)]
// pub use vercre_core::w3c::VerifiableCredential;

// use crate::capabilities::delay::Delay;
// use crate::capabilities::signer::Signer;
// use crate::capabilities::store::{self, Store};
// #[allow(clippy::module_name_repetitions)]
// pub use crate::credential::model::{Credential, Logo};

// /// App implements `crux::App` for the Credential management.
// #[derive(Default)]
// pub struct App;

// /// Events supported by the Wallet app.
// ///
// /// Sub-app events are delegated to the appropriate sub-app through top-level
// /// wrapper events.
// ///
// /// Events may be external (initiated by the shell), internal (initiated by
// /// local processing), or both. Local events are not published
// /// (`#[serde(skip)]`) to the shell.
// #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
// #[serde(rename = "CredentialEvent")]
// #[allow(clippy::large_enum_variant)]
// pub enum Event {
//     // -----------------------
//     // Shell-initiated actions
//     // -----------------------
//     /// Request from shell to list stored credentials. An optional set of
//     /// constraints may be provided to filter the credentials.
//     List,

//     // -----------------------
//     // Capability callbacks
//     // -----------------------
//     /// An internal event to find credentials matching a Presentation Request.
//     #[serde(skip)]
//     ListLocal(Option<Constraints>),

//     /// An internal event to set credentials fetched in `Find` into the model.
//     #[serde(skip)]
//     Listed(store::Result<Vec<model::Credential>>),

//     // // FIXME: box to reduce the total size of the enum: Add(Box<Credential>),
//     // /// Add adds a Credential to the store.
//     // #[serde(skip)]
//     // Add(Credential),

//     // /// Added is set after a credential has been saved to the store.
//     // #[serde(skip)]
//     // Added(store::Result<()>),
//     /// Shell-initiated event to delete a credential. The `String` is the
//     /// credential `id`.
//     Delete(String),

//     /// An internal event initated on completion of a `Delete` event.
//     #[serde(skip)]
//     Deleted(store::Result<()>),

//     /// Fail is set when an error occurs.
//     #[serde(skip)]
//     Fail(String),
// }

// /// Model holds an internal representation of app state.
// #[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
// pub struct Model {
//     filter: Option<Constraints>,
//     credentials: Vec<model::Credential>,
//     error: Option<String>,
// }

// /// The view model represents the App's 'external' state to the shell.
// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
// #[serde(rename = "CredentialView")]
// pub struct ViewModel {
//     /// Serialized list of credentials. Serializing as a String makes it easier to
//     /// serialize to the shell.
//     pub credentials: String,

//     /// Error message for the shell, if any.
//     #[serde(skip)]
//     pub error: Option<String>,
// }

// /// App `Capabilities` allow the app to interface with the shell and external
// /// systems.
// ///
// /// They create `effects` (technically side effects) that are handled by the
// /// shell, with the manner of handling unique to a particualr shell.
// #[cfg_attr(feature = "typegen", derive(Export))]
// #[derive(Effect)]
// #[effect(app = "App")]
// pub struct Capabilities {
//     /// The Render capability allows the app to request a re-render of the UI.
//     pub render: Render<Event>,

//     /// The Http capability allows the app to make HTTP requests.
//     pub http: Http<Event>,

//     /// The Store capability allows the app to store and retrieve credentials.
//     pub store: Store<Event>,

//     /// The Signer capability allows the app to sign and verify messages.
//     pub signer: Signer<Event>,

//     /// The Delay capability allows the app to delay processing.
//     pub delay: Delay<Event>,
// }

// impl crux_core::App for App {
//     type Capabilities = Capabilities;
//     type Event = Event;
//     type Model = Model;
//     type ViewModel = ViewModel;

//     // Called in response to an event, usually by the shell but can also be in
//     // response to a capability executing, or an internal processing step.
//     fn update(&self, event: Self::Event, model: &mut Self::Model, caps: &Self::Capabilities) {
//         match event {
//             Event::List => {
//                 caps.store.list(None, Event::Listed);
//                 model.filter = None;
//             }
//             Event::ListLocal(filter) => {
//                 caps.store.list(filter.clone(), Event::Listed);
//                 model.filter = filter;
//             }
//             Event::Listed(Ok(response)) => {
//                 model.credentials = response;
//             }
//             Event::Delete(id) => {
//                 caps.store.delete(&id, Event::Deleted);
//             }
//             Event::Deleted(Ok(())) => {
//                 // re-query stored credentials
//                 self.update(Event::List, model, caps);
//             }

//             // ----------------------------------------------------------------
//             // Error handling
//             // ----------------------------------------------------------------
//             Event::Listed(Err(e)) => {
//                 let msg = format!("Issue retrieving credentials: {e:?}");
//                 self.update(Event::Fail(msg), model, caps);
//             }
//             Event::Deleted(Err(e)) => {
//                 let msg = format!("Issue deleting credential: {e:?}");
//                 self.update(Event::Fail(msg), model, caps);
//             }
//             Event::Fail(msg) => {
//                 log::error!("{}", msg);
//                 model.error = Some(msg);
//             }
//         }

//         caps.render.render();
//     }

//     // `view` is called by the shell to render the current state of the app.
//     // Typically, this is invoked by the `render()` method of the Render
//     // capability.
//     fn view(&self, model: &Self::Model) -> Self::ViewModel {
//         let mut buf = Vec::new();
//         let mut ser =
//             serde_json::Serializer::with_formatter(&mut buf, olpc_cjson::CanonicalFormatter::new());
//         model.credentials.serialize(&mut ser).expect("should serialize");
//         ViewModel {
//             credentials: String::from_utf8(buf).expect("should convert to string"),
//             error: model.error.clone(),
//         }
//     }
// }

// #[cfg(test)]
// mod tests {
//     use assert_let_bind::assert_let;
//     use crux_core::testing::AppTester;

//     // use insta::{assert_yaml_snapshot, internals::Redaction};
//     use super::*;
//     use crate::capabilities::store::{StoreEntry, StoreResponse};

//     /// Test that a `Event::List(filter)` event causes the app to fetch the
//     /// credentials specified in the query.
//     #[tokio::test]
//     async fn find() {
//         let app = AppTester::<App, _>::default();
//         let mut model = Model::default();

//         let mut update = app.update(Event::List, &mut model);

//         // make real metadata request
//         assert_let!(Effect::Store(request), &mut update.effects[0]);
//         assert_eq!(request.operation, store::StoreRequest::List);

//         let credentials = Vec::<Credential>::new();
//         let values: Vec<StoreEntry> = credentials
//             .iter()
//             .map(|c| StoreEntry(serde_json::to_vec(c).expect("should serialize")))
//             .collect();
//         let response = StoreResponse::List(values.clone());

//         let update = app.resolve(request, response).expect("should resolve");
//         assert_eq!(update.events[0], Event::Listed(Ok(credentials.clone())));
//     }
// }
