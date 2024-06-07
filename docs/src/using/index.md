# Using the Vercre API

<div class="warning">
    APIs listed here are still <strong>under development</strong>.

    The APIs are suitable for demonstration purposes but not yet intended for 
    production use!
</div>

The Vercre API comprises three top-level libraries that form the backbone of OpenID 
for Verifiable Credentials.

- [Issuance](./issuance/index.md) — based on the [OpenID for Verifiable Credential Issuance]
  specification, the [vercre-issuer] library provides an API for issuing Verifiable 
  Credentials.

- [Presentation](./presentation/index.md) — based on the [OpenID for VerifiablePresentations]
  specification, the [vercre-verifier] library provides an API for  requesting and presenting 
  Verifiable Credentials.

- [Wallet](./wallet/index.md) — the the [vercre-holder] library is built against both
  specifications and can be used to simplify interactions with the issuance and 
  presentation APIs.

## Design Axioms

While not critical to learning to use the API, the following design axioms might be of
some interest in understanding the philosophy we adopted for the development of Vercre
libraries.

### Do not bake HTTP into the API

While the two core `OpenID4VC` specifications define an HTTP-based API, we have chosen 
not to bake HTTP into the libraries. This decision was made to allow for flexibility of
implementation by library users. 

This could be as simple as selecting the most suitable  HTTP libraries for the task
or as complex as integrating with an existing application. It could even mean using
the libraries in a non-HTTP context.

### Embrace asynchronous Rust

The libraries are built using asynchronous Rust in order allow for efficient handling
of I/O and mximum utility.

### Be opinionated

Vercre libraries are opinionated in that they provide a specific way of doing things.
Each endpoint accepts a strongly-typed Request object and returns a strongly-typed
Response object. This is intended to make the libraries easy to use and reason
about.

The Request and Response objects should readily serialize and deserialize to and 
from compliant JSON objects.

[OpenID for Verifiable Credential Issuance]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
[OpenID for VerifiablePresentations]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
[vercre-issuer]: https://github.com/vercre/vercre/tree/main/vercre-issuer
[vercre-verifier]: https://github.com/vercre/vercre/tree/main/vercre-verifier
[vercre-holder]: https://github.com/vercre/vercre/tree/main/vercre-holder