# Vercre

Issuance, Holder, and Verification libraries for use in `OpenID` Verifiable Credentials
solutions.

> [!CAUTION]
>
> **Alpha code not yet intended for production use!**
>
> The code in this repository is experimental and under active development. The examples
> work, albeit for a narrow range of use cases **with hard-coded values**.
> 
> We still have much to do and welcome feedback and contributions.

## OpenID for Verifiable Credentials

This repository provides (rudimentary) implementations of [OpenID for Verifiable 
Credential Issuance] and [OpenID for Verifiable Presentations] specifications with an
initial focus on meeting requirements in the [JWT VC Issuance] and [JWT VC Presentation]
Profiles.

You will find a more complete set of documentation on the 
[Vercre website](https://vercre.io).

## Getting Started

Example impementations for Credential issuance, presentation, and a rudimentary wallet
can be found in the [examples](./examples) directory

The wallet example is built using [Tauri](https://tauri.studio/) to provide an 
end-to-end example using the `vercre` libraries to issue and present Verifiable 
Credentials.

Additionally, end-to-end client examples can be found in each top-level crate's `/tests`
directory.

## Specification Conformance

### OpenID for Verifiable Credential Issuance

The following table shows the current status of the implementation of the OpenID for 
Verifiable Credential Issuance specification:

|                | Alpha[^1]                 | In-progress     | Planned                          |
| -------------- | ------------------------- | --------------- | -------------------------------- |
| **Initiated**  | Issuer, Wallet            |                 |                                  |
| **Flow**       | Pre-Authorized            | Authorization   |                                  |
| **Origin**     | Cross-device, same-device |                 |                                  |
| **Issuance**   | Immediate, Deferred       |                 |                                  |
| **Format**     | jwt_vc_json               |                 | ldp_vc, jwt_vc_json-ld, mso-mdoc |
| **Signature**  | ES256K, EdDSA             |                 |                                  |
| **Binding**    | did:web, did:key          |                 | did:dht, did:keri                |
| **Encryption** |                           | ECDH-ES/A128GCM | ECDH-ES/A256GCM                  |

[^1]: Working code, but not yet rigorously verified.

### OpenID for Verifiable Presentations

TODO

## Additional

[![ci](https://github.com/vercre/vercre/actions/workflows/ci.yaml/badge.svg)](https://github.com/vercre/vercre/actions/workflows/ci.yaml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE-MIT)
[![License](https://img.shields.io/badge/license-Apache-blue.svg)](./LICENSE-APACHE)

<!-- The [changelog][CHANGES] is used to record a summary of changes between releases. A more granular
record of changes can be found in the commit history. -->

More information about [contributing][CONTRIBUTING]. Please respect we maintain this project on a
part-time basis. While we welcome suggestions and technical input, it may take time to respond.

The artefacts in this repository are dual licensed under either:

- MIT license ([LICENSE-MIT] or <http://opensource.org/licenses/MIT>)
- Apache License, Version 2.0 ([LICENSE-APACHE] or <http://www.apache.org/licenses/LICENSE-2.0>)

The license applies to all parts of the source code, its documentation and supplementary files
unless otherwise indicated.

[OpenID for Verifiable Credential Issuance]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
[OpenID for Verifiable Presentations]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
[JWT VC Issuance]: https://identity.foundation/jwt-vc-issuance-profile
[JWT VC Presentation]: https://identity.foundation/jwt-vc-presentation-profile
<!-- [CHANGES]: CHANGELOG.md -->
[CONTRIBUTING]: CONTRIBUTING.md
[LICENSE-MIT]: LICENSE-MIT
[LICENSE-APACHE]: LICENSE-APACHE

<!-- > [!NOTE]  
> Highlights information that users should take into account, even when skimming.
> [!TIP]
> Optional information to help a user be more successful.
> [!IMPORTANT]  
> Crucial information necessary for users to succeed.
> [!WARNING]  
> Critical content demanding immediate user attention due to potential risks.
> [!CAUTION]
> Negative potential consequences of an action.
-->
