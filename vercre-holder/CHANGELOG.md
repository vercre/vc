# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking changes

- Internal flow state for issuance (`Issuance`) and presentation (`Presentation`) is no longer returned in endpoint responses; Only the minimum information required by the holder's agent is returned. See endpoint documentation for new response types.


## [v0.1.0-alpha.6](https://github.com/vercre/vercre/releases/tag/vercre-holder-v0.1.0-alpha.6) - 2024-08-08

### Breaking changes

- **Endpoints now require `Request` objects to be borrowed, i.e. passed by ref rather than
by val**.
- The `credential_identifiers` attribute is not supported in credential requests until use
is clarified in the Pre-Authorized Code Flow.

### Added

- `Notification` endpoint, as defined in [Draft 13] of the OpenID4VCI specification.

### Changed

- Changes as outlined in [Draft 13] of the OpenID4VCI specification.

### Fixed

- Replaced deps preventing `wasm` build.

### Other

- Further alignment with the OpenID4VCI specification.
- Refactoring to improve code maintainability and supportability.

[Draft 13]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-document-history
