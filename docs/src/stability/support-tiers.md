# Support Tiers

Vercre recognises three distinct tiers of platform and feature support. Each tier
identifies the level of support that should be provided for a given platform or feature.

The description of these tiers are inspired by the Rust compiler's [support tiers for
targets](https://doc.rust-lang.org/rustc/target-tier-policy.html) with some additional
customization for feature support.

This section provides a framework for the evaluation of new features as well as support 
requires for existing features.

_Keep in mind, this is merely a guide and should not be used to "lawyer" a change into 
Vercre on some technical detail._

## Supported Platforms and Features

Tier 1 is classified as the highest level of support, confidence, and correctness for a
component. Each tier encompasses all the guarantees of previous tiers.

Features classified under one tier may already meet the criteria for a higher tier. In
such situations, it's not intended to use these guidelines to justify removal of a 
feature.

Guidance is provided for phasing out unmaintained features but it should be clear under
what circumstances work "can be avoided" for each tier.

### Tier 1 - Production Ready

<div style="display:flex;">

| Category            | Description                  |
|---------------------|------------------------------|
| Target              | `aarch64-apple-darwin`       |
| Target [^1]         | `x86_64-unknown-linux-musl`  |
| Target              | `wasm32-wasi`                |
| Example feature     | [`example feature`]          |
</div>

[`example feature`]: https://github.com/vercre/vercre/blob/master/proposals/example-feature/Overview.md

[^1]: Binary artifacts for MUSL can be statically linked, meaning that they are
suitable for "run on any linux distribution" style use cases.

Tier 1 is intended to be the highest level of support in Vercre for included features,
indicating that they are suitable for production environments. This conveys a high 
level of confidence within the Vercre project about the included features.

Tier 1 features include:

* Continuous fuzzing is required for all features. This means that any existing fuzz
  targets must be running and exercising the new code paths. Where possible differential
  fuzzing should also be implemented to compare results with other implementations.

* Continuous fuzzing is required for the _architecture_ of supported targets.

* CVEs and security releases will be performed as necessary for any bugs found in
  features and targets.

* Major changes affecting this tier may require help from maintainers with specialized
  expertise, but otherwise it should be reasonable to expect most Vercre developers to
  be able to maintain Tier 1 features.

* Major changes affecting Tier 1 features require an RFC and prior agreement on the
  change before an implementation is committed.

A major inclusion point for this tier is intended to be the continuous fuzzing 
requirement. This implies a significant commitment of resources for fixing issues, 
resources to execute, etc. Additionally this tier comes with the broadest expectation 
of "burden on everyone else" in terms of what changes everyone is generally expected to
handle.

Features classified as Tier 1 are rarely, if ever, turned off or removed.

### Tier 2 - Almost Production Ready

<div style="display:flex;">

| Category             | Description                 | Missing Tier 1 Requirements |
|----------------------|-----------------------------|-----------------------------|
| Target               | `aarch64-unknown-linux-musl`| Continuous fuzzing          |
| Target               | `x86_64-apple-darwin`       | Continuous fuzzing          |
| Target               | `x86_64-pc-windows-msvc`    | Continuous fuzzing          |
| Target               | `x86_64-pc-windows-gnu`     | Clear owner of the target   |
| Target               | Support for `#![no_std]`    | Support beyond CI checks    |
</div>

Tier 2 encompasses features and components which are well-maintained, tested well, but
don't necessarily meet the stringent criteria for Tier 1. Features in this category may
already be "production ready" and safe to use.

Tier 2 features include:

* Tests are run in CI for the Vercre project for this feature and everything
  passes. For example a Tier 2 platform runs in CI directly or via emulation.
  Features are otherwise fully tested on CI.

* Complete implementations for anything that's part of Tier 1. For example
  all Tier 2 targets must implement all of the Tier 1 WebAssembly proposals,
  and all Tier 2 features must be implemented on all Tier 1 targets.

* Any Vercre developer could be expected to handle minor changes which affect Tier 2
  features. For example, if an interface changes, the developer changing the 
  interface should be able to handle the changes for Tier 2 architectures as long as the
  affected part is relatively minor.

* For more significant changes, maintainers of a Tier 2 feature should be responsive
  (reply to requests within a week) and are available to accommodate architectural 
  changes that affect their component. For example more expansive work beyond the 
  previous point where contributors can't easily handle changes are expected to be
  guided or otherwise implemented by Tier 2 maintainers.

* Major changes otherwise requiring an RFC that affect Tier 2 components are
  required to consult Tier 2 maintainers in the course of the RFC. Major changes
  to Tier 2 components themselves do not require an RFC, however.

Tier 2 features are generally not turned off or disabled for long. Maintainers are
required to be responsive to changes and will be notified of any unrelated change 
which affects their component. It's recommended that if a component breaks for any 
reason due to an unrelated change that the maintainer either contributes to the 
PR-in-progress or otherwise has a schedule for the implementation of the feature.

### Tier 3 - Not Production Ready

<div style="display:flex;">

| Category             | Description                   | Missing Tier 2 Requirements                  |
|----------------------|-------------------------------|----------------------------------------------|
| Target               | `aarch64-pc-windows-msvc`     | CI testing, unwinding, full-time maintainer  |
| Target               | `riscv64gc-unknown-linux-gnu` | full-time maintainer                         |
</div>

In general, Tier 3 is the baseline for inclusion of code into the Vercre project.
However, this does not mean it is the catch-all "if a patch is sent it will be merged"
tier. Instead, the goal of this tier is to outline what is expected of contributors 
adding new features to Vercre which might be experimental at the time of addition. 

Tier 3 not a tier where restrictions are releaxed, rather it already implies a
significant commitment of effort to a feature being included within Vercre.

Tier 3 features include:

* Inclusion of a feature does not impose unnecessary maintenance overhead on
  other components/features. Some examples of additions which would not be accepted are:

  * An experimental feature that doubles the CI time for all PRs.
  * A change which makes it significantly more difficult to make architectural changes
    to Vercre's internal implementation.
  * A change which makes building Vercre more difficult.

  In general Tier 3 features are off-by-default at compile time but still
  tested-by-default on CI.

* New features of Vercre cannot have major known bugs at the time of inclusion. Landing
  a feature requires the feature to be correct and bug-free as best can be evaluated at
  the time of inclusion. Inevitably, bugs will be found and that's ok, but anything 
  identified during review must be addressed.

* Code included into the project must be of an acceptable level of quality relative to
  the rest of the codebase.

* There must be a path to a feature being finished at the time of inclusion. Adding a 
  new backend, for example, is a significant undertaking which may not be able to be
  done in a single PR. Partial implementations are acceptable as long as there's a clear
  path for delivering the completed feature.

* New components must have a clearly identified owner who is willing to be "on the hook"
  for review, updates to any internals, etc. For example, a new backend would need to 
  have a maintainer who is willing to respond to changes in interfaces and the needs of 
  Vercre.

Notably, this baseline level of support does not require any degree of testing, fuzzing,
or verification. As a result, components classified as Tier 3 are generally not 
production-ready as they have not yet been 'battle-tested'.

Tier 3 features may be disabled in CI or even removed from the repository. If a Tier 3
feature is preventing development of other features then:

1. The owner will be notified. 
2. If no response is received within one week, the feature will be disabled in CI.
3. If no response is received within one month, the feature may be removed from the 
   repository.

## Unsupported features and platforms

While this is not an exhaustive list, Vercre does not currently support the following
features. While this documents Vercre's current state, it does not mean Vercre does not
want to ever support these features; rather design discussion and PRs are welcome for 
many of the below features to figure out how best to implement them and at least move 
them to Tier 3 above.

* Target: ARM 32-bit
* Target: FreeBSD
* Target: NetBSD/OpenBSD
* Target: i686 (32-bit Intel targets)
* Target: Android
* Target: MIPS
* Target: SPARC
* Target: PowerPC
* Target: RISC-V 32-bit
