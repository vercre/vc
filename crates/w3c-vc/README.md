# Verifiable Credentials

>This crate is a higher order crate to support the Vercre suite of crates. It is not intended to be used directly. See
>
>* [vercre-issuer](https://crates.io/crates/vercre-issuer)
>* [vercre-verifier](https://crates.io/crates/vercre-verifier)
>* [vercre-holder](https://crates.io/crates/vercre-holder)

Created to support the [Verifiable Credentials Data Model v2.0], this crate implements
some of the family of W3C Recommendations for Verifiable Credentials as outlined in the
[Verifiable Credentials Overview].

The crate is organized along the lines of the top-level specifications:

- model: [VC Data Model](https://www.w3.org/TR/vc-data-model-2.0)

- proof: [Data Integrity](https://www.w3.org/TR/vc-data-integrity) 
  and [JOSE and COSE](https://www.w3.org/TR/vc-jose-cose) proof formats

- status: [Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list)
  for Credential status.

- schema: [VC JSON Schema](https://www.w3.org/TR/vc-json-schema) for interpreting
  the structure of a Credential in a consistent manner.


[Verifiable Credentials Overview]: https://w3c.github.io/vc-overview
[Verifiable Credentials Data Model v2.0]: https://www.w3.org/TR/vc-data-model-2.0