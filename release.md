# Release Process

## Pre-requisites

Use `cargo-release` to release a new version of the crate.

```sh
cargo install cargo-release
```

## Dry run

Set the release level using one of `release`, `major`, `minor`, `patch`, `alpha`, `beta`, `rc`

For example, to release a minor version:

```sh
cargo-release minor
```

## Changelog

```sh
cargo changelog
```

## Publish

Release to crates.io:

```sh
cargo-release minor --execute
```

# Release-plz

<https://release-plz.ieni.dev/docs/usage/installation>

```sh
cargo install cargo-release-plz --locked
```


# Smart Release

```sh
brew install cmake
cargo install cargo-smart-release
```

```sh
cargo install cargo-smart-release
cargo smart-release vercre-core
cargo smart-release --dry-run-cargo-publish
cargo changelog vercre-core vercre-vci vercre-vp vercre-wallet
cargo changelog vercre-core --write
```
