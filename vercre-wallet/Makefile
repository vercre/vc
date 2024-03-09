
# Generate bindings for Swift and Kotlin
# The target uses the `uniffi-bindgen` Cargo alias to mimic the as yet unsupported 
# uniffi-bindgen CLI
# 
# TODO: migrate to generating from release library file:
# https://mozilla.github.io/uniffi-rs/tutorial/foreign_language_bindings.html#running-uniffi-bindgen-using-a-library-file-recommended

.PHONY: gen
gen:
	@cargo uniffi-bindgen -l swift -l kotlin -o ./gen ./src/shared.udl

	# Build examples
	@cargo build --manifest-path ./examples/cli/Cargo.toml
	@cargo build --manifest-path ./examples/desktop/Cargo.toml
	@cargo build --manifest-path ./examples/mobile/Cargo.toml
	@cargo build --manifest-path ./examples/wasm/Cargo.toml
	@cargo build --manifest-path ./examples/web/Cargo.toml
