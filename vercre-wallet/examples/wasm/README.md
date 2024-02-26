# Web Wallet

Yew

## Getting Started

Install [trunk](https://crates.io/crates/trunk), the WASM bundler.

```bash
cargo install trunk
```

and make sure you have the WASM build target installed:

```bash
rustup target add wasm32-unknown-unknown
```

Run the application using...

```bash
trunk serve --open
```

(`--open` will open your default browser. Omit if you prefer to open manually.)

You should see the wallet application running at `http://127.0.0.1:8080`.

