# Building

This section describes everything required to build and run Vercre.

## Prerequisites

Before we can actually build Vercre, we'll need to make sure these things are
installed first.

### The Rust Toolchain

[Install the Rust toolchain here.](https://www.rust-lang.org/tools/install) This
includes `rustup`, `cargo`, `rustc`, etc...

## Building `vercre` Libraries

To make an unoptimized, debug build of the `vercre` CLI tool, go to the root
of the repository and run this command:

```shell
cargo build
```

The built executable will be located at `target/debug/vercre`.

To make an optimized build, run this command in the root of the repository:

```shell
cargo build --release
```

The built executable will be located at `target/release/vercre`.

You can also build and run a local `vercre` CLI by replacing `cargo build`
with `cargo run`.

## Building Other Vercre Crates

You can build any of the Vercre crates by appending `-p vercre-whatever` to
the `cargo build` invocation. For example, to build the `vercre-holder` crate,
execute this command:

```shell
cargo build -p vercre-holder
```

Alternatively, you can `cd` into the crate's directory, and run `cargo build`
there, without needing to supply the `-p` flag:

```shell
cd vercre-holder
cargo build
```
