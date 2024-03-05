# Vercre Example Web Wallet

This is an example of a React (+Vite +TypeScript) shell for the Vercre wallet. It is a static,
single-page application with client-side rendering and uses a [Rust Crux](https://github.com/redbadger/crux) core that is transpiled to TypeScript.

## Getting Started

Make an entry in your hosts file that points `localhost` to `dev.vercre.io`. This allows the Vite `mkcert` plugin to generate a certificate for `dev.vercre.io` and serve the app over HTTPS.

```bash
echo "127.0.0.1 dev.vercre.io" | sudo tee -a /private/etc/hosts
```

Generate the types by building the `types` crate:

```bash
cd types
cargo build
```

Install the TypeScript dependencies:

```bash
pnpm install
```

Run the app:

```bash
pnpm dev
```

Navigate to [https://dev.vercre.io:3000](https://dev.vercre.io:3000) in your browser.

TODO: Instructions for running services for issuance, verification and capabilities.
