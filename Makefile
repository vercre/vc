
.PHONY: build
build:
	@cargo build
	# cargo build --manifest-path ./vercre-wallet/examples/Cargo.toml

.PHONY: clean
clean:
	@cargo clean
	@cargo clean --target-dir=vercre-wallet/examples/target

# TESTS = ""
.PHONY: test
test:
	@RUSTFLAGS="-Dwarnings" cargo nextest run

# test-doc:
# 	@cargo test --doc -- --nocapture --color=always

.PHONY: doc
doc:
	@cargo doc --no-deps

.PHONY: fmt
fmt:
	cargo fmt --all

.PHONY: lint
lint:
	@rustup component add clippy 2> /dev/null
	@cargo clippy -- -Dclippy::all -Dclippy::pedantic

.PHONY: unused
unused:
	-cargo install cargo-machete > /dev/null
	@cargo machete

.PHONY: pub-check
pub-check:
	@cargo publish --dry-run --package vercre-core
	@cargo publish --dry-run --package vercre-vci
	@cargo publish --dry-run --package vercre-vp
	@cargo publish --dry-run --package vercre-wallet
	
	# 	cargo publish --package $e

# test-miri:
# 	MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-panic-on-unsupported" cargo miri test -- --nocapture --color=always
# 	# @cargo miri nextest run -J20