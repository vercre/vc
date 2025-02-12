# Release Process

**Credibil VC is in dynamic development** so the content of this page is subject to change, but we document our release process goals here for now.

This section serves as a high-level summary of Credibil VC's process. A more detailed
description of the process can be found in the [contributing section].

[contributing section]: ../contributing/maintainer-guidelines/release-process.md

Key takeways:

* A new version of Credibil VC will be made available once a month.
* KeyOps bugs and correctness fixes will be backported to the latest two releases
  of Credibil VC and issued as patch releases.

Once a month Credibil VC will issue a new version. This will be issued with a semver-major
version update, such as 0.1.0 to 0.2.0. 

A release is scheduled when an automated PR is sent to bump the version on the 5th of 
every month with the release effected when the PR is merged. The PR typically gets
merged within a few days.

<div class="hidden">
**TODO: use Github Action to schedule Release PR**
</div>

## Breaking Changes

Each major release of Credibil VC reserves the right to break both behavior and API
backwards-compatibility. This is not expected to happen frequently, however, and any
breaking change will follow these criteria:

* Minor breaking changes, either behavior or with APIs, will be documented in
  the `CHANGELOG.md` release notes. Minor changes will require some degree of
  consensus but are not required to go through the entire RFC process.

* Major breaking changes, such as major refactorings to the API, will be
  required to go through the [RFC process]. These changes are intended to be
  broadly communicated to those interested and provides an opportunity to give
  feedback about embeddings. Release notes will clearly indicate if any major
  breaking changes through accepted RFCs are included in a release.

[RFC process]: https://github.com/credibil/rfcs

## Patching

Patch releases of Credibil VC will only be issued for security and critical correctness
issues for on-by-default behavior in the previous releases. If Credibil VC is currently
at version 0.2.0 then 0.2.1 and 0.1.1 will be issued as patch releases if a bug is
found. Patch releases are guaranteed to maintain API and behavior
backwards-compatibility and are intended to be trivial for users to upgrade to.

## What's released?

Currently, Credibil VC's release process encompasses a single top-level `credibil-vc` Rust
crate.

Other projects maintained by the Credibil maintainers will also likely be released, with the same
version numbers, with the main Credibil project soon after a release is made.
