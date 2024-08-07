# Testing

This section describes how to run Vercre's tests and add new tests.

Before continuing, make sure you can [build Vercre](./building.md) successfully. Can't run the tests if you
can't build it!

## Installing `wasm32` Targets

To compile the tests, you'll need the `wasm32-wasip1` and
`wasm32-unknown-unknown` targets installed, which, assuming you're using
[rustup.rs](https://rustup.rs) to manage your Rust versions, can be done as
follows:

```shell
rustup target add wasm32-wasip1
```

## Running All Tests

To run all of Vercre's tests, execute this command:

```shell
cargo test --workspace
```

You can also exclude a particular crate from testing with `--exclude`. For
example, if you want to avoid testing the `vercre-verifier` crate:

```shell
cargo test --workspace --exclude vercre-verifier
```

## Testing a Specific Crate

You can test a particular Vercre crate with `cargo test -p
vercre-whatever`. For example, to test the `vercre-issuer` crate, execute
this command:

```shell
cargo test -p vercre-issuer
```

Alternatively, you can `cd` into the crate's directory, and run `cargo test`
there, without needing to supply the `-p` flag:

```shell
cd vercre-issuer/
cargo test
```

## Adding New Tests

### Adding Rust's `#[test]`-Style Tests

For very "unit-y" tests, we add `test` modules in the same `.rs` file as the
code that is being tested. These `test` modules are configured to only get
compiled during testing with `#[cfg(test)]`.

```rust
// some code...

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn some_test_for_that_code() {
        // ...
    }
}
```

If you're writing a unit test and a `test` module doesn't already exist, you can
create one.

For more "integration-y" tests, we create a `tests` directory within the crate,
and put the tests inside there. For example, there are various end-to-end flow tests at `vercre-holder/tests`. Always feel free to
add a `tests` directory to a crate, if you want to add a new test and there
aren't any existing tests.

