# Building

This section describes everything required to build and run Credibil VC.

## Prerequisites

Before we can actually build Credibil VC, we'll need to make sure these things are
installed first.

### The Rust Toolchain

[Install the Rust toolchain here.](https://www.rust-lang.org/tools/install) This
includes `rustup`, `cargo`, `rustc`, etc...

## Building `credibil-vc` Library

To make an unoptimized, debug build of the `credibil-vc` crate, go to the root
of the repository and run this command:

```shell
cargo build
```

The built executable will be located at `target/debug/libcredibil_vc.rlib`.

To make an optimized build, run this command in the root of the repository:

```shell
cargo build --release
```

The built executable will be located at `target/release/libcredibil_vc.rlib`.

## Building Example Crates

You can build any of the example crates by appending `-p whatever` to
the `cargo build` invocation. For example, to build the example `issuer` crate,
execute this command:

```shell
cargo build -p issuer
```

Alternatively, you can `cd` into the crate's directory, and run `cargo build`
there, without needing to supply the `-p` flag:

```shell
cd examples/issuer
cargo build
```
