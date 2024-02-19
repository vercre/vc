
build:
	@cargo build

# gen: build
# 	@cargo run --features=uniffi/cli --bin uniffi-bindgen generate -l swift -l kotlin .vercre-wallet/src/shared.udl

clean:
	@cargo clean

# TESTS = ""
test:
	@RUSTFLAGS="-Dwarnings" cargo nextest run

test-miri:
	MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-panic-on-unsupported" cargo miri test -- --nocapture --color=always
	# @cargo miri nextest run -J20

docs: build
	@cargo doc --no-deps

test-doc:
	@cargo test --doc -- --nocapture --color=always

fmt:
	cargo fmt --all

fmt-check:
	@rustup component add rustfmt 2> /dev/null
	@cargo fmt --all -- --check

lint:
	@rustup component add clippy 2> /dev/null
	@cargo clippy -- -Dclippy::all -Dclippy::pedantic
	# @cargo clippy --all-targets --all-features -- -D warnings

unused:
	@rustup component add cargo-udeps 2> /dev/null
	@cargo +nightly udeps --all-targets

dev:
	@cargo run

pub:
	@cargo publish --dry-run vercre-core

.PHONY: build gen clean test docs test-doc fmt fmt-check lint unused pub
