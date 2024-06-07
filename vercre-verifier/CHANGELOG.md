# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.1.0-alpha.5](https://github.com/vercre/vercre/compare/vercre-vp-v0.1.0-alpha.4...vercre-vp-v0.1.0-alpha.5) - 2024-03-01

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
