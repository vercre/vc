# Architecture

At its most simple, Vercre is a set of three top-level libraries  that allow developers
to build applications that can issue, present, and verify credentials. All underpinned
by OpenID for Verifiable Credential specifications.

Implementers choose their own HTTP server(s) and implement the provider traits for
each library.

<div style="text-align:center;">
    <img src="../images/architecture.png" width="65%" alt="overview" />
</div>

Top-level libraries:

- [vercre-vci](../using/issuance/index.md) — Credential issuance
- [Vercre Verifier](../using/presentation/index.md) — Credential presentation
- [Vercre Wallet](../using/wallet/index.md) — Credential wallet