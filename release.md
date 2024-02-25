# Release Process

## Pre-requisites

Use `cargo-release` to release a new version of the crate.

```sh
cargo install cargo-release
```

```sh
cargo install cargo-smart-release
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
