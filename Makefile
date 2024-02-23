
# .PHONY: build
# build:
# 	@cargo build

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
	@cargo publish --dry-run vercre-core
	# for e in crux_macros crux_core crux_http crux_kv crux_platform crux_time
	# 	echo $e
	# 	cargo publish --package $e
	# end

# test-miri:
# 	MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-panic-on-unsupported" cargo miri test -- --nocapture --color=always
# 	# @cargo miri nextest run -J20