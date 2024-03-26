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

For an example of the library used as a Tauri application, see the [Vercre App](<https://github.com/vercre/vercre/vercre-wallet/examples/app>).

For an exmaple of the library published as a WebAssembly package and used as a web application, see the [Vercre Web App](<https://github.com/vercre/vercre/vercre-wallet/examples/web>)

## NPM Packages

The wallet is built as a WebAssembly package and published to NPM. To use it in your typescript project, use your favourite package manager to install it:

```bash
npm i --save @vercre/vercre-wallet
```

If using TypeScript you will also need to install some shared types that have been generated from the Rust crux application. These provide classes with serialization and deserialization compatibile with the FFI.

```bash
npm i --save @vercre/shared-types
```

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
