# OpenID for Verifiable Credential Issuance

An API for the issuance of Verifiable Credentials based on the [OpenID for Verifiable Credential Issuance] specification.

> [!CAUTION]
>
> **Alpha code not yet intended for production use!**
>
> The code in this repository is experimental and under active development. The examples work, albeit for a narrow range of use cases, so have a play. We welcome feedback and contributions.

## Getting Started

An example impementation of a Verifiable Credential Issuance service can be found at: [Credential Issuance API](./examples/issuance).

[Learn how to use `vercre-issuer` in your project](https://vercre.io/issuance).

[Read the API documentation](https://docs.rs/vercre-issuer).

## Specification Conformance

The following table shows the current status of the implementation of the OpenID for 
Verifiable Credential Issuance specification:

|                | Alpha<sup>1</sup>         | In-progress        | Planned                          |
| -------------- | ------------------------- | ------------------ | -------------------------------- |
| **Initiated**  | Issuer, Wallet            |                    |                                  |
| **Flow**       | Pre-Authorized            | Authorization Code |                                  |
| **Origin**     | Cross-device, same-device |                    |                                  |
| **Issuance**   | Immediate, Deferred       |                    |                                  |
| **Format**     | jwt_vc_json               |                    | ldp_vc, jwt_vc_json-ld, mso-mdoc |
| **Signature**  | ES256K, EdDSA             |                    |                                  |
| **Binding**    | did:web, did:key          |                    | did:dht, did:keri                |
| **Encryption** |                           | ECDH-ES/A128GCM    | ECDH-ES/A256GCM                  |

1. Working code, but not yet rigorously verified.

## Additional

[![Crates.io Status](https://img.shields.io/crates/v/vercre-vci.svg)](https://crates.io/crates/vercre-vci)
[![Docs.rs Status](https://docs.rs/vercre-vci/badge.svg)](https://docs.rs/vercre-vci/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE-MIT)
[![License](https://img.shields.io/badge/license-Apache-blue.svg)](./LICENSE-APACHE)

<!-- The [changelog][CHANGES] is used to record a summary of changes between releases. A more granular
record of changes can be found in the commit history. -->

The artefacts in this repository are dual licensed under either:

- MIT license ([LICENSE-MIT] or <http://opensource.org/licenses/MIT>)
- Apache License, Version 2.0 ([LICENSE-APACHE] or <http://www.apache.org/licenses/LICENSE-2.0>)

The license applies to all parts of the source code, its documentation and supplementary files
unless otherwise indicated.

[OpenID for Verifiable Credential Issuance]: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>
[LICENSE-MIT]: LICENSE-MIT
[LICENSE-APACHE]: LICENSE-APACHE
<!-- [CHANGES]: CHANGELOG.md -->
