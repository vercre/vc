# Provider

Common 'providers' required by `vercre-issuer`, `vercre-verifier`, and `vercre-holder`
crates.

Providers are used to provide top-level libraries with external services, such as 
persistence, encryption and signing, access to third-party services, and more.
Each provider is a trait that defines the required functionality to be provided by
the library implementer.

See [Using the API](https://vercre.io/using/index.md) for more information on providers.

> [!CAUTION]
>
> The crate is for internal use within `Vercre` project and is not intended to be used
> directly by the end users. Any public types are re-exported through the respective 
> top-level, published `vercre-xxx` crates.