# Release Process

Vercre's release process is described in more  [detail here](../contributing/maintainer-guidelines/release-process.md)
with this page serving as a high-level summary of the process.

* A new major version of Vercre will be made available once a month.
* Security bugs and correctness fixes will be backported to the latest two releases 
  of Vercre and issued as patch releases.

Once a month Vercre will issue a new version. This will be issued with a
semver-major version update, such as 4.0.0 to 5.0.0. The precise schedule of
Vercre's release is currently an automated PR is sent to bump the version on
the 5th of every month and a release is made when the PR is merged. The PR
typically gets merged within a few days.

Each major release of Vercre reserves the right to break both behavior and API
backwards-compatibility. This is not expected to happen frequently, however, and
any breaking change will follow these criteria:

* Minor breaking changes, either behavior or with APIs, will be documented in
  the `RELEASES.md` release notes. Minor changes will require some degree of
  consensus but are not required to go through the entire RFC process.

* Major breaking changes, such as major refactorings to the API, will be
  required to go through the [RFC process]. These changes are intended to be
  broadly communicated to those interested and provides an opportunity to give
  feedback about embeddings. Release notes will clearly indicate if any major
  breaking changes through accepted RFCs are included in a release.

Patch releases of Vercre will only be issued for security and critical
correctness issues for on-by-default behavior in the previous releases. If
Vercre is currently at version 5.0.0 then 5.0.1 and 4.0.1 will be issued as
patch releases if a bug is found. Patch releases are guaranteed to maintain API
and behavior backwards-compatibility and are intended to be trivial for users to
upgrade to.

Patch releases for Cranelift will be made for any miscompilations found by
Cranelift, even those that Vercre itself may not exercise. Due to the current
release process a patch release for Cranelift will issue a patch release for
Vercre as well.

## What's released?

At this time the release process of Vercre encompasses:

* The `vercre-xxx` Rust crates

<div class="hidden">
Other projects maintained by the Vercre will also likely be released,
with the same version numbers, with the main Vercre project soon after a
release is made, such as:

* [`vercre-dotnet`](https://github.com/bytecodealliance/vercre-dotnet)
* [`vercre-py`](https://github.com/bytecodealliance/vercre-py)
* [`vercre-go`](https://github.com/bytecodealliance/vercre-go)
* [`vercre-cpp`](https://github.com/bytecodealliance/vercre-cpp)
* [`vercre-rb`](https://github.com/bytecodealliance/vercre-rb)

Note, though, that bugs and security issues in these projects do not at this
time warrant patch releases for Vercre.
</div>

[RFC process]: https://github.com/vercre/rfcs
