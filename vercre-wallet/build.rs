//! # `UniFFI` Bindings Generator
//!
//! This build file is used to generate the scaffolding for the `UniFFI` bindings.
//!
//! See the [UniFFI documentation](https://mozilla.github.io/uniffi-rs/) for more
//! information.

fn main() {
    uniffi::generate_scaffolding("src/shared.udl").expect("should generate scaffolding");
}
