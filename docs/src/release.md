# Releasing Updates

## Overview

Test

![Release Process](images/release.png)



## Preparing to release

Use [cargo-release](https://github.com/crate-ci/cargo-release) to release a new version of each crate.

### Changelog

All notable changes should be documented in the project's CHANGELOG.md file.
Per [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) recommendations, changes are a manually
documented, high-level summary of changes in a release.

### Dry run

Set the release level using one of `release`, `major`, `minor`, `patch`, `alpha`, `beta`, `rc`

For example, to release a minor version:

```sh
cargo-release minor
```

### Publish

Release to crates.io:

```sh
cargo-release minor --execute
```

### [TO REVIEW] Github Release

In order to track changes to each crate independently, we need a branch containing only the contents of the crate we want to release:

Manually:

1. Create a new branch (use crate name).
2. Delete all files and folders except the crate to release.
3. Push the new branch
4. Use Github to create a release **on the new branch**

CLI:

```sh
# create a new branch from `main` and check out
git checkout -b serde-from-v0.2.0

# delete all files and folders except the crate to release

# stage and commit changes
git add . 
git  commit -a -m "serde-from-v0.2.0"

# tag the branch
git tag v0.2.0 -m "v0.2.0 release"

# push new branch
git push --set-upstream origin serde-from-v0.2.0
git push --tags
```
