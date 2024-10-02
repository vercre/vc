# Credential Holder Agent

The Vercre holder agent (typically a wallet) provides an opiniated API for
managing the receipt of credentials via the OpenID for Verifiable Credentials
(OIDC4VC) protocol and the presentation of credentials via the OpenID for
Verifiable Presentation (VP) protocol.

It covers most of the possible flows and interaction types defined in the
specification and the intention is to be up-to-date with the respective
`vercre-issuer` and `vercre-verifier` endpoints. There may be some use cases
that are not covered but in general this crate should be a good starting point
for anyone needing to implement a custom solution by calling standards-compliant
issuer and verifier services.

## Getting Started

No wallet technology or interactions are mandated by this crate, leaving a
user-interface or service implementation up to the user. However, see the
[Example Wallet](https://github.com/vercre/vercre/examples/wallet) for a simple,
naive implementation using this crate.
