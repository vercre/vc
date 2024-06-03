# Release Process

This section serves as a high-level summary of Vercre's process. A more detailed
description of the process can be found in the [contributing section].

[contributing section]: ../contributing/maintainer-guidelines/release-process.md

Key takeways:

* A new version of Vercre will be made available once a month.
* Security bugs and correctness fixes will be backported to the latest two releases
  of Vercre and issued as patch releases.

Once a month Vercre will issue a new version. This will be issued with a semver-major
version update, such as 0.1.0 to 0.2.0. 

A release is scheduled when an automated PR is sent to bump the version on the 5th of 
every month with the release effected when the PR is merged. The PR typically gets
merged within a few days.

**TODO: use Github Action to schedule Release PR**

## Breaking Changes

Each major release of Vercre reserves the right to break both behavior and API
backwards-compatibility. This is not expected to happen frequently, however, and any
breaking change will follow these criteria:

* Minor breaking changes, either behavior or with APIs, will be documented in
  the `RELEASES.md` release notes. Minor changes will require some degree of
  consensus but are not required to go through the entire RFC process.

* Major breaking changes, such as major refactorings to the API, will be
  required to go through the [RFC process]. These changes are intended to be
  broadly communicated to those interested and provides an opportunity to give
  feedback about embeddings. Release notes will clearly indicate if any major
  breaking changes through accepted RFCs are included in a release.

[RFC process]: https://github.com/vercre/rfcs

## Patching

Patch releases of Vercre will only be issued for security and critical correctness
issues for on-by-default behavior in the previous releases. If Vercre is currently
at version 0.2.0 then 0.2.1 and 0.1.1 will be issued as patch releases if a bug is
found. Patch releases are guaranteed to maintain API and behavior
backwards-compatibility and are intended to be trivial for users to upgrade to.

## What's released?

Currently, Vercre's release process encompasses the three top-level `vercre-xxx` Rust
crates.

Other projects maintained by the Vercre will also likely be released, with the same
version numbers, with the main Vercre project soon after a release is made.
