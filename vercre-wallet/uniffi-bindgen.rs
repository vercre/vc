//! `UniFFI` Type Generation Workaround
//!
//! This workaround is required until Cargo supports artifact dependencies
//! (<https://github.com/rust-lang/cargo/issues/9096/>).
//!
//! See <https://mozilla.github.io/uniffi-rs/tutorial/foreign_language_bindings.html#creating-the-bindgen-binary/>
//! for more information.

fn main() {
    uniffi::uniffi_bindgen_main();
}
