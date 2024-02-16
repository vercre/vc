# Shared Types

The `shared_types` crate is a "build only" crate used to generate types specific to each UI. Types are generated from types imported from the `vercre-wallet` library and used in communication between the shell (UI) and the wallet core (`vercre-wallet` library).

Generated types are stored in UI-specific sub-directories under the the `src/generated` directory.

## Generating Types

To generate types, run:

```bash
make build
```

New types must be registered in the `build.rs` file.

## Known Issues

Due to the way the type generator works, types cannot use `serde` macros that lead to asymmetry between serialization and deserialization. For example, using `#[serde(skip_serializing_if = "Option::is_none")]` on a field will lead to issues generating the type.
