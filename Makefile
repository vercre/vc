
.PHONY: build
build:
	@cargo build

.PHONY: clean
clean:
	@cargo clean

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
	@cargo clippy -- -Dclippy::all -Dclippy::pedantic -Dclippy::nursery

	# clippy::all = correctness, suspicious, style, complexity, perf
	# not using (yet) -Dclippy::restriction

.PHONY: audit
audit: 
	@cargo audit

.PHONY: unused
unused:
	# -cargo install cargo-machete > /dev/null
	@cargo machete --skip-target-dir

.PHONY: check
check: fmt lint audit unused

.PHONY: breaking
breaking:
	# cargo install cargo-semver-checks --locked
	@cargo semver-checks

.PHONY: pub-check
pub-check:
	@cargo publish --dry-run --package vercre-core
	@cargo publish --dry-run --package vercre-vci
	@cargo publish --dry-run --package vercre-vp
	@cargo publish --dry-run --package vercre-wallet

# test-miri:
# 	MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-panic-on-unsupported" cargo miri test -- --nocapture --color=always
# 	# @cargo miri nextest run -J20