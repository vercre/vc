# Tiers of Support in Vercre

Vercre recognises three distinct tiers for platform and feature support. Each tier
outlines the level of support that Vercre will provide for a given platform or feature.

The description of these tiers are inspired by the [Rust compiler's support tiers for
targets](https://doc.rust-lang.org/rustc/target-tier-policy.html) with additional
tailoring for Vercre.

This document should provide the means by which to evaluate the inclusion of new 
features and support for existing features within Vercre. Keep in mind this is only a 
guide. It should not be used to "lawyer" a change into Vercre on a precise technical
detail or similar.

## Supported Platforms and Features

Vercre's tier definitions are likely to change over time. Tier 1 is classified
as the highest level of support, confidence, and correctness for a component. Each 
tier encompasses all the guarantees of previous tiers.

Features classified under a particular tier may already meet the criteria for
later tiers as well. In situations like this it's not intended to use these
guidelines to justify removal of a feature at any one point in time. Guidance is
provided here for phasing out unmaintained features but it should be clear under
what circumstances work "can be avoided" for each tier.

### Tier 1 - Production Ready

<div style="display:flex;">

| Category            | Description                  |
|---------------------|------------------------------|
| Target              | `aarch64-apple-darwin`       |
| Target [^1]         | `x86_64-unknown-linux-gnu`   |
| Target              | `wasm32-wasi`                |
| Example feature     | [`example feature`]          |
</div>

[`example feature`]: https://github.com/vercre/vercre/blob/master/proposals/example-feature/Overview.md
[^1]: Binary artifacts for MUSL are dynamically linked, not statically
linked, meaning that they are not suitable for "run on any linux distribution"
style use cases. Vercre does not have static binary artifacts at this time and
that will require building from source.

This tier is intended to be the highest level of support in Vercre for any
particular feature, indicating that it is suitable for production environments.
This conveys a high level of confidence in the Vercre project about the
specified features.

Tier 1 features include:

* Continuous fuzzing is required for WebAssembly proposals. This means that any
  WebAssembly proposal must have support in the `wasm-smith` crate and existing
  fuzz targets must be running and exercising the new code paths. Where possible
  differential fuzzing should also be implemented to compare results with other
  implementations.

* Continuous fuzzing is required for the architecture of supported targets. For
  example currently there are three x86\_64 targets that are considered Tier 1
  but only `x86_64-unknown-linux-gnu` is fuzzed.

* CVEs and security releases will be performed as necessary for any bugs found
  in features and targets.

* Major changes affecting this component may require help from maintainers with
  specialized expertise, but otherwise it should be reasonable to expect most
  Vercre developers to be able to maintain Tier 1 features.

* Major changes affecting Tier 1 features require an RFC and prior agreement on
  the change before an implementation is committed.

A major inclusion point for this tier is intended to be the continuous fuzzing
of Vercre. This implies a significant commitment of resources for fixing
issues, hardware to execute Vercre, etc. Additionally this tier comes with the
broadest expectation of "burden on everyone else" in terms of what changes
everyone is generally expected to handle.

Features classified as Tier 1 are rarely, if ever, turned off or removed from
Vercre.

### Tier 2 - Almost Production Ready

<div style="display:flex;">

| Category             | Description                | Missing Tier 1 Requirements |
|----------------------|----------------------------|-----------------------------|
| Target               | `aarch64-unknown-linux-gnu`| Continuous fuzzing          |
| Target               | `x86_64-apple-darwin`      | Continuous fuzzing          |
| Target               | `x86_64-pc-windows-msvc`   | Continuous fuzzing          |
| Target               | `x86_64-pc-windows-gnu`    | Clear owner of the target   |
| Target               | Support for `#![no_std]`   | Support beyond CI checks    |
</div>

This tier is meant to encompass features and components of Vercre which are
well-maintained, tested well, but don't necessarily meet the stringent criteria
for Tier 1. Features in this category may already be "production ready" and safe
to use.

Tier 2 features include:

* Tests are run in CI for the Vercre project for this feature and everything
  passes. For example a Tier 2 platform runs in CI directly or via emulation.
  Features are otherwise fully tested on CI.

* Complete implementations for anything that's part of Tier 1. For example
  all Tier 2 targets must implement all of the Tier 1 WebAssembly proposals,
  and all Tier 2 features must be implemented on all Tier 1 targets.

* All existing developers are expected to handle minor changes which affect Tier
  2 components. For example if Vercre's interfaces change then the developer
  changing the interface is expected to handle the changes for Tier 2
  architectures so long as the affected part is relatively minor. Note that if a
  more substantial change is required to a Tier 2 component then that falls
  under the next bullet.

* Maintainers of a Tier 2 feature are responsive (reply to requests within a
  week) and are available to accommodate architectural changes that affect their
  component. For example more expansive work beyond the previous bullet where
  contributors can't easily handle changes are expected to be guided or
  otherwise implemented by Tier 2 maintainers.

* Major changes otherwise requiring an RFC that affect Tier 2 components are
  required to consult Tier 2 maintainers in the course of the RFC. Major changes
  to Tier 2 components themselves do not require an RFC, however.

Features at this tier generally are not turned off or disabled for very long.
Maintainers are already required to be responsive to changes and will be
notified of any unrelated change which affects their component. It's recommended
that if a component breaks for one reason or another due to an unrelated change
that the maintainer either contributes to the PR-in-progress or otherwise has a
schedule for the implementation of the feature.

### Tier 3 - Not Production Ready

<div style="display:flex;">

| Category             | Description                   | Missing Tier 2 Requirements                  |
|----------------------|-------------------------------|----------------------------------------------|
| Target               | `aarch64-pc-windows-msvc`     | CI testing, unwinding, full-time maintainer  |
| Target               | `riscv64gc-unknown-linux-gnu` | full-time maintainer                         |
</div>

The general idea behind Tier 3 is that this is the baseline for inclusion of
code into the Vercre project. This is not intended to be a catch-all "if a
patch is sent it will be merged" tier. Instead the goal of this tier is to
outline what is expected of contributors adding new features to Vercre which
might be experimental at the time of addition. This is intentionally not a
relaxed tier of restrictions but already implies a significant commitment of
effort to a feature being included within Vercre.

Tier 3 features include:

* Inclusion of a feature does not impose unnecessary maintenance overhead on
  other components/features. Some examples of additions to Vercre which would
  not be accepted are:

  * An experimental feature doubles the time of CI for all PRs.
  * A change which makes it significantly more difficult to architecturally
    change Vercre's internal implementation.
  * A change which makes building Vercre more difficult for unrelated
    developers.

  In general Tier 3 features are off-by-default at compile time but still
  tested-by-default on CI.

* New features of Vercre cannot have major known bugs at the time of
  inclusion. Landing a feature in Vercre requires the feature to be correct
  and bug-free as best can be evaluated at the time of inclusion. Inevitably
  bugs will be found and that's ok, but anything identified during review must
  be addressed.

* Code included into the Vercre project must be of an acceptable level of
  quality relative to the rest of the code in Vercre.

* There must be a path to a feature being finished at the time of inclusion.
  Adding a new backend to Vercre for example is a significant undertaking
  which may not be able to be done in a single PR. Partial implementations of a
  feature are acceptable so long as there's a clear path forward and schedule
  for completing the feature.

* New components in Vercre must have a clearly identified owner who is willing
  to be "on the hook" for review, updates to the internals of Vercre, etc. For
  example a new backend in Vercre would need to have a maintainer who is
  willing to respond to changes in Vercre's interfaces and the needs of
  Vercre.

This baseline level of support notably does not require any degree of testing,
fuzzing, or verification. As a result components classified as Tier 3 are
generally not production-ready as they have not been battle-tested much.

Features classified as Tier 3 may be disabled in CI or removed from the
repository as well. If a Tier 3 feature is preventing development of other
features then the owner will be notified. If no response is heard from within a
week then the feature will be disabled in CI. If no further response happens
for a month then the feature may be removed from the repository.

## Unsupported features and platforms

While this is not an exhaustive list, Vercre does not currently have support
for the following features. Note that this is intended to document Vercre's
current state and does not mean Vercre does not want to ever support these
features; rather design discussion and PRs are welcome for many of the below
features to figure out how best to implement them and at least move them to Tier
3 above.

* Target: ARM 32-bit
* Target: [FreeBSD](https://github.com/bytecodealliance/vercre/issues/5499)
* Target: [NetBSD/OpenBSD](https://github.com/bytecodealliance/vercre/issues/6962)
* Target: [i686 (32-bit Intel targets)](https://github.com/bytecodealliance/vercre/issues/1980)
* Target: Android
* Target: MIPS
* Target: SPARC
* Target: PowerPC
* Target: RISC-V 32-bit
