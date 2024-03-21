# Wallet

The Vercre wallet is a cross-platform app with a Rust core and native UI integrated
using Mozilla's Foreign Function Interface (FFI) library,
[UniFFI](https://mozilla.github.io/uniffi-rs).

This library contains the wallet's core business logic and FFI bindings. Developers can
use it to build their own UIs in Swift, Kotlin, or TypeScript. Alternatively, simply
clone the [Vercre Wallet](<https://github.com/vercre/vercre/vercre-wallet/examples/app>) for a quicker start.

## Cross-platform with Crux

Vercre uses [Crux](<https://redbadger.github.io/crux/overview.html>) with its built-in
FFI support to simplify the creation of wallets.

Crux splits the application into a **Core** built in Rust (this library), containing the
business logic, and a **Shell**, or UI, built in the platform native language (Swift,
Kotlin, TypeScript), that provides the interface with the external world.

The **Core : Shell** interface is a Foreign Function Interface (FFI) where simple
data structures are passed both ways between the Rust **Core** and [Swift|Kotlin|Typescript]
**Shell**.

[Learn how to use Crux in your project](https://redbadger.github.io/crux).

## Getting Started

<!-- TODO: add `examples/tauri` -->

See the [Vercre Wallet](<https://github.com/vercre/vercre/vercre-wallet/examples/app>).

## Development

### Generating FFI Bindings

[Mozilla UniFFI](https://mozilla.github.io/uniffi-rs) generates foreign-language bindings
for Rust libraries. It fits in the practice of consolidating business logic in a single
Rust library while targeting multiple platforms, making it simpler to develop and maintain
a cross-platform codebase.

```bash
cd vercre-wallet
cargo build
cargo uniffi-bindgen --out-dir ./gen ./src/shared.udl --language kotlin --language swift
# cargo run --bin uniffi-bindgen generate --out-dir ./gen ./src/shared.udl --language kotlin --language swift
```
