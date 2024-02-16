
# Generate bindings for Swift and Kotlin
# The target uses the `uniffi-bindgen` Cargo alias to mimic the as yet unsupported 
# uniffi-bindgen CLI
# 
# TODO: migrate to generating from release library file:
# https://mozilla.github.io/uniffi-rs/tutorial/foreign_language_bindings.html#running-uniffi-bindgen-using-a-library-file-recommended
gen:
	# @cargo run --features=uniffi/cli --bin uniffi-bindgen generate -l swift -l kotlin ./src/shared.udl
	@cargo uniffi-bindgen -l swift -l kotlin -o ./gen ./src/shared.udl

.PHONY: gen
