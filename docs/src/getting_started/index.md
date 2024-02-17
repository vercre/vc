# Getting Started

## Install the tools

This is an example of a `rust-toolchain.toml` file, which you can add at the root of your repo. It should ensure that the correct rust channel and compile targets are installed automatically for you when you use any rust tooling within the repo.

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "rustc-dev"]
targets = [
  "aarch64-apple-darwin",
  "wasm32-unknown-unknown",
]
profile = "minimal"
```

## Create a new project

```bash
cargo new my_project
cd my_project
```

[TODO]
