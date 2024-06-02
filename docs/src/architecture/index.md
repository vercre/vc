# Architecture

At its most simple, Vercre is a set of three top-level libraries that support 
developers in building Verifiable Credential-based applications. That is, applications
that can issue, present, and verify credentials — all underpinned by OpenID for 
Verifiable Credential specifications.

Implementers choose their own HTTP server(s) and implement the provider traits for
each library used.

![overview](../images/architecture.png)

Top-level libraries:

- [vercre-vci](../using/issuance/index.md) — Credential issuance
- [Vercre Verifier](../using/presentation/index.md) — Credential presentation
- [Vercre Wallet](../using/wallet/index.md) — Credential wallet